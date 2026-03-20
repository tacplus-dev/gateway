use std::sync::{Arc, RwLock};

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use tokio_stream::StreamExt;
use tonic::transport::Channel;

use gateway_tacplus::types::libs::jwk::jwk::Jwk;
use gateway_tacplus::types::libs::key::key::KeyType;
use gateway_tacplus::types::services::kernel::kernel::identity_state_service_client::IdentityStateServiceClient;
use gateway_tacplus::types::services::kernel::kernel::VerifyingKeysEntriesResponse;

use crate::health::TokenProvider;
use crate::registry::Registry;

/// Auth function signature matching passthrough handler expectations.
pub type AuthFn = Arc<dyn Fn(&str, &tonic::metadata::MetadataMap) -> Result<(), tonic::Status> + Send + Sync>;

/// Minimal JWT claims for pre-validation.
/// The gateway only checks signature + expiry.
/// Audience and entitlements are validated by backends.
#[derive(Debug, Serialize, Deserialize)]
pub struct GatewayClaims {
    pub sub: Option<String>,
    pub exp: Option<u64>,
    pub iat: Option<u64>,
    pub aud: Option<serde_json::Value>,
}

/// Gateway token pre-validator.
/// Watches JWK verifying keys from kernel and validates JWT signature + expiry.
/// Also stores raw JWK protos for the JWKS endpoint.
#[derive(Clone)]
pub struct GatewayAuth {
    keys: Arc<RwLock<Vec<DecodingKey>>>,
    raw_jwks: Arc<RwLock<Vec<Jwk>>>,
    registry: Arc<Registry>,
}

#[allow(clippy::result_large_err)]
impl GatewayAuth {
    /// Creates a GatewayAuth and starts watching JWK keys from the kernel connection.
    pub fn new(channel: Channel, registry: Arc<Registry>, token_provider: TokenProvider) -> Self {
        let auth = Self {
            keys: Arc::new(RwLock::new(Vec::new())),
            raw_jwks: Arc::new(RwLock::new(Vec::new())),
            registry,
        };

        let auth_clone = auth.clone();
        tokio::spawn(async move {
            auth_clone.watch_keys(channel, token_provider).await;
        });

        auth
    }

    /// Build an AuthFn closure matching the passthrough handler signature.
    pub fn auth_fn(self: &Arc<Self>) -> AuthFn {
        let auth = Arc::clone(self);
        Arc::new(move |method: &str, metadata: &tonic::metadata::MetadataMap| {
            auth.validate(method, metadata)
        })
    }

    /// Validate a gRPC request: check if auth is needed, then verify token.
    pub fn validate(
        &self,
        method: &str,
        metadata: &tonic::metadata::MetadataMap,
    ) -> Result<(), tonic::Status> {
        if self.registry.is_grpc_no_auth(method) {
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

    /// Validate a REST request: check if auth is needed, then verify token.
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

    fn verify_token(&self, token: &str) -> Result<(), tonic::Status> {
        let keys = self.keys.read().unwrap();
        if keys.is_empty() {
            return Err(tonic::Status::unauthenticated("no JWK keys configured"));
        }

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.validate_aud = false;
        validation.required_spec_claims.clear();

        for key in keys.iter() {
            match jsonwebtoken::decode::<GatewayClaims>(token, key, &validation) {
                Ok(_data) => return Ok(()),
                Err(_) => continue,
            }
        }

        Err(tonic::Status::unauthenticated("invalid or expired token"))
    }

    /// Watch JWK verifying keys from the kernel's TokenExchangerStateStateService.
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
        if let Some(token) = (token_provider)().await {
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
        let mut new_keys = Vec::new();
        let mut new_raw = Vec::new();

        for (kid, jwk) in &entries_response.entries {
            match jwk_to_decoding_key(jwk) {
                Ok(key) => {
                    new_keys.push(key);
                    new_raw.push(jwk.clone());
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
    pub fn get_raw_jwks(&self) -> Vec<Jwk> {
        self.raw_jwks.read().unwrap().clone()
    }
}

/// Extract bearer token from Authorization header value.
fn extract_bearer(header_value: &str) -> Option<&str> {
    header_value
        .strip_prefix("Bearer ")
        .or_else(|| header_value.strip_prefix("bearer "))
}

/// Convert a generated Jwk proto to a jsonwebtoken DecodingKey.
fn jwk_to_decoding_key(jwk: &Jwk) -> Result<DecodingKey, String> {
    let kty = KeyType::try_from(jwk.kty).unwrap_or(KeyType::Undefined);

    match kty {
        KeyType::Okp => {
            // Ed25519 key
            if jwk.x.is_empty() {
                return Err("missing x coordinate".to_string());
            }
            let x_bytes = base64_url_decode(&jwk.x)?;
            if x_bytes.len() != 32 {
                return Err(format!("invalid Ed25519 key size: {}", x_bytes.len()));
            }
            Ok(DecodingKey::from_ed_der(&x_bytes))
        }
        KeyType::Ec => {
            if jwk.x.is_empty() || jwk.y.is_empty() {
                return Err("missing EC coordinates".to_string());
            }
            let x_bytes = base64_url_decode(&jwk.x)?;
            let y_bytes = base64_url_decode(&jwk.y)?;
            let mut point = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
            point.push(0x04);
            point.extend_from_slice(&x_bytes);
            point.extend_from_slice(&y_bytes);
            Ok(DecodingKey::from_ec_der(&point))
        }
        KeyType::Rsa => {
            if jwk.n.is_empty() || jwk.e.is_empty() {
                return Err("missing RSA modulus or exponent".to_string());
            }
            DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
                .map_err(|e| format!("invalid RSA key: {}", e))
        }
        _ => Err(format!("unsupported key type: {:?}", kty)),
    }
}

fn base64_url_decode(input: &str) -> Result<Vec<u8>, String> {
    let input = input.replace('-', "+").replace('_', "/");
    let padding = match input.len() % 4 {
        2 => "==",
        3 => "=",
        _ => "",
    };
    let padded = format!("{}{}", input, padding);
    base64_decode_standard(&padded)
}

fn base64_decode_standard(input: &str) -> Result<Vec<u8>, String> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = Vec::new();
    let bytes: Vec<u8> = input.bytes().filter(|&b| b != b'\n' && b != b'\r').collect();

    for chunk in bytes.chunks(4) {
        let mut buf = [0u8; 4];
        let mut count = 0;
        for (i, &b) in chunk.iter().enumerate() {
            if b == b'=' {
                break;
            }
            buf[i] = TABLE
                .iter()
                .position(|&c| c == b)
                .ok_or_else(|| format!("invalid base64 char: {}", b as char))? as u8;
            count = i + 1;
        }

        if count >= 2 {
            result.push((buf[0] << 2) | (buf[1] >> 4));
        }
        if count >= 3 {
            result.push((buf[1] << 4) | (buf[2] >> 2));
        }
        if count >= 4 {
            result.push((buf[2] << 6) | buf[3]);
        }
    }

    Ok(result)
}
