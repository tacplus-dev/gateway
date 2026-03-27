use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use tokio_stream::StreamExt;
use tonic::transport::Channel;

use gateway_tacplus::types::libs::jwk::jwk::Jwk as ProtoJwk;
use gateway_tacplus::types::libs::key::key::KeyType;
use gateway_tacplus::types::services::kernel::kernel::identity_state_service_client::IdentityStateServiceClient;
use gateway_tacplus::types::services::kernel::kernel::VerifyingKeysEntriesResponse;

// Generated libs for JWT verification
use gateway_jwk::jwk::ImmutableJwk;
use gateway_servicemanager::auth::proto_jwk_to_lib;
use gateway_token::token::Token;

use crate::health::TokenProvider;

/// Gateway token pre-validator.
/// Watches JWK verifying keys from kernel and validates JWT signature + expiry.
/// Also stores raw JWK protos for the JWKS endpoint.
#[derive(Clone)]
pub struct GatewayAuth {
    keys: Arc<RwLock<HashMap<String, Arc<ImmutableJwk>>>>,
    raw_jwks: Arc<RwLock<Vec<ProtoJwk>>>,
}

#[allow(clippy::result_large_err)]
impl GatewayAuth {
    /// Creates a GatewayAuth and starts watching JWK keys from the kernel connection.
    pub fn new(channel: Channel, token_provider: TokenProvider) -> Self {
        let auth = Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            raw_jwks: Arc::new(RwLock::new(Vec::new())),
        };

        let auth_clone = auth.clone();
        tokio::spawn(async move {
            auth_clone.watch_keys(channel, token_provider).await;
        });

        auth
    }

    /// Validate a gRPC request: check if auth is needed, then verify token.
    pub fn validate(
        &self,
        method: &str,
        metadata: &tonic::metadata::MetadataMap,
    ) -> Result<(), tonic::Status> {
        if crate::rest_dispatch::is_grpc_no_auth(method) {
            return Ok(());
        }

        let auth_value = metadata
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                tonic::Status::unauthenticated("missing authorization header")
            })?;

        let token_str = extract_bearer(auth_value).ok_or_else(|| {
            tonic::Status::unauthenticated("invalid authorization header format")
        })?;

        self.verify_token(token_str)
    }

    /// Validate a REST request token. The caller is responsible for checking
    /// no_auth via the route entry before calling this.
    pub fn validate_rest(
        &self,
        _path: &str,
        auth_header: Option<&str>,
    ) -> Result<(), tonic::Status> {
        let auth_value = auth_header.ok_or_else(|| {
            tonic::Status::unauthenticated("missing authorization header")
        })?;

        let token_str = extract_bearer(auth_value).ok_or_else(|| {
            tonic::Status::unauthenticated("invalid authorization header format")
        })?;

        self.verify_token(token_str)
    }

    fn verify_token(&self, token_str: &str) -> Result<(), tonic::Status> {
        let keys = self.keys.read().unwrap();
        if keys.is_empty() {
            return Err(tonic::Status::unauthenticated("no JWK keys configured"));
        }

        // Parse the JWT using the generated token library.
        let tw = Token::parse(token_str).map_err(|e| {
            tonic::Status::unauthenticated(format!("invalid token: {}", e))
        })?;

        // Look up the signing key by kid.
        let kid = tw.kid().ok_or_else(|| {
            tonic::Status::unauthenticated("token missing key ID (kid)")
        })?;

        let jwk = keys.get(kid).cloned().ok_or_else(|| {
            tonic::Status::unauthenticated(format!("unknown signing key: {}", kid))
        })?;

        // Verify signature and expiry using the generated token library.
        tw.verify(&jwk).map_err(|e| {
            tracing::warn!(error = %e, kid = kid, "JWT verification failed");
            tonic::Status::unauthenticated("invalid or expired token")
        })
    }

    /// Watch JWK verifying keys from the kernel's IdentityStateService.
    async fn watch_keys(&self, channel: Channel, token_provider: TokenProvider) {
        loop {
            match self.start_key_watch(channel.clone(), &token_provider).await {
                Ok(()) => {
                    tracing::warn!("JWK watch stream ended, reconnecting");
                }
                Err(e) => {
                    tracing::error!(error = %e, "JWK watch failed, retrying in 5s");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        }
    }

    async fn start_key_watch(
        &self,
        channel: Channel,
        token_provider: &TokenProvider,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut client = IdentityStateServiceClient::new(channel);

        let mut request = tonic::Request::new(());
        if let Ok(token) = (token_provider)().await {
            let val: tonic::metadata::MetadataValue<tonic::metadata::Ascii> = format!("Bearer {}", token)
                .parse()
                .map_err(|_| "invalid token metadata")?;
            request.metadata_mut().insert("authorization", val);
        }

        let response = client
            .watch_verifying_keys(request)
            .await?;

        let mut stream = response.into_inner();
        tracing::info!("JWK WatchVerifyingKeys stream started");

        while let Some(msg) = stream.next().await {
            match msg {
                Ok(entries_response) => {
                    self.process_jwk_entries(&entries_response);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "JWK watch stream error");
                    return Err(e.into());
                }
            }
        }

        Ok(())
    }

    fn process_jwk_entries(&self, entries_response: &VerifyingKeysEntriesResponse) {
        let mut new_keys = HashMap::new();
        let mut new_raw = Vec::new();

        for (kid, proto_jwk) in &entries_response.entries {
            let kty = KeyType::try_from(proto_jwk.kty).unwrap_or(KeyType::Undefined);
            tracing::info!(kid = %kid, kty = ?kty, x_len = proto_jwk.x.len(), "processing JWK entry");

            let local_jwk = proto_jwk_to_lib(proto_jwk);
            match ImmutableJwk::new(local_jwk) {
                Ok(immutable) => {
                    tracing::info!(kid = %kid, "JWK decoded successfully");
                    new_keys.insert(kid.clone(), Arc::new(immutable));
                    new_raw.push(proto_jwk.clone());
                }
                Err(e) => {
                    tracing::warn!(kid = %kid, error = %e, "skipping invalid JWK");
                }
            }
        }

        let count = new_keys.len();
        *self.keys.write().unwrap() = new_keys;
        *self.raw_jwks.write().unwrap() = new_raw;

        tracing::info!(count, "JWK keys updated");
    }

    /// Returns a clone of the raw JWK protos for the JWKS endpoint.
    pub fn get_raw_jwks(&self) -> Vec<ProtoJwk> {
        self.raw_jwks.read().unwrap().clone()
    }
}

/// Extract bearer token from Authorization header value.
fn extract_bearer(header_value: &str) -> Option<&str> {
    header_value
        .strip_prefix("Bearer ")
        .or_else(|| header_value.strip_prefix("bearer "))
}

