use std::sync::Arc;

use http::StatusCode;

use gateway_tacplus::types::libs::jwk::jwk::Jwk as ProtoJwk;
use gateway_grpcserver::authorizer::{JwkCache, ProfileCache};

// Generated libs for JWT parsing (no crypto needed — authorizer handles verification)
use gateway_token::token::Token;

/// Gateway C2S authenticator/authorizer.
///
/// Uses the decomposed JwkCache and ProfileCache directly (not the Authorizer
/// wrapper) because the gateway's auth policy differs from standard S2S:
///   - `aud` must match the **target** service (not "gateway")
///   - entitlements are checked against the **target** service
#[derive(Clone)]
pub struct GatewayAuth {
    jwk_cache: Arc<JwkCache>,
    profile_cache: Arc<ProfileCache>,
}

impl GatewayAuth {
    pub fn new(jwk_cache: Arc<JwkCache>, profile_cache: Arc<ProfileCache>) -> Self {
        Self {
            jwk_cache,
            profile_cache,
        }
    }

    /// Validate a C2S request against the per-route auth policy.
    ///
    /// - `NoAuth`: pass through.
    /// - `AnyUser`: verify token, check aud==target_service, reject S2S tokens.
    /// - `Entitled`: AnyUser + check entitlements against `service_id`.
    pub async fn validate_c2s(
        &self,
        auth_policy: gateway_tacplus::s2sm::rest_dispatch::AuthPolicy,
        service_id: &str,
        grpc_path: &str,
        auth_header: Option<&str>,
    ) -> Result<(), (StatusCode, String)> {
        use gateway_tacplus::s2sm::rest_dispatch::AuthPolicy;

        match auth_policy {
            AuthPolicy::NoAuth => Ok(()),
            AuthPolicy::AnyUser => {
                self.authenticate(service_id, auth_header)?;
                Ok(())
            }
            AuthPolicy::Entitled => {
                self.authenticate(service_id, auth_header)?;
                let method = grpc_path.rsplit('/').next().unwrap_or(grpc_path);
                self.check_entitlements(auth_header.unwrap_or(""), service_id, method)?;
                Ok(())
            }
        }
    }

    /// Verify token signature + aud == target_service, then reject S2S tokens.
    fn authenticate(
        &self,
        target_service: &str,
        auth_header: Option<&str>,
    ) -> Result<(), (StatusCode, String)> {
        let token_str = extract_bearer(
            auth_header.ok_or_else(|| {
                (StatusCode::UNAUTHORIZED, "missing authorization header".into())
            })?,
        )
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "invalid authorization header".into()))?;

        // Parse token
        let tw = Token::parse(token_str)
            .map_err(|e| (StatusCode::UNAUTHORIZED, format!("invalid token: {e}")))?;

        // Verify signature using JWK cache
        let kid = tw
            .kid()
            .ok_or_else(|| (StatusCode::UNAUTHORIZED, "token missing key ID (kid)".into()))?;

        let jwk = self.jwk_cache.get(kid).ok_or_else(|| {
            if self.jwk_cache.has_keys() {
                (
                    StatusCode::UNAUTHORIZED,
                    format!("unknown signing key: {kid}"),
                )
            } else {
                // No keys loaded yet — fail open for gradual rollout
                (
                    StatusCode::UNAUTHORIZED,
                    "no JWK keys loaded yet".into(),
                )
            }
        })?;

        tw.verify(&jwk)
            .map_err(|e| (StatusCode::UNAUTHORIZED, format!("token verification failed: {e}")))?;

        // Reject refresh tokens — they should only be exchanged at the Mint endpoint.
        // Check token_use first, fall back to legacy typ for backwards compat.
        let is_refresh = tw
            .custom_field("token_use")
            .and_then(|v| v.as_str())
            .map(|v| v == "refresh")
            .unwrap_or_else(|| {
                tw.custom_field("typ")
                    .and_then(|v| v.as_str())
                    .map(|v| v == "refresh")
                    .unwrap_or(false)
            });
        if is_refresh {
            return Err((
                StatusCode::UNAUTHORIZED,
                "refresh tokens cannot be used for API access".into(),
            ));
        }

        // Check aud matches TARGET service (not gateway)
        let aud = tw.audience().unwrap_or("");
        if aud != target_service {
            return Err((
                StatusCode::UNAUTHORIZED,
                format!(
                    "token audience \"{}\" does not match target service \"{}\"",
                    aud, target_service
                ),
            ));
        }

        Ok(())
    }

    /// Check entitlements against the **target** service (not gateway).
    fn check_entitlements(
        &self,
        auth_header: &str,
        target_service: &str,
        method: &str,
    ) -> Result<(), (StatusCode, String)> {
        let token_str = extract_bearer(auth_header)
            .ok_or_else(|| (StatusCode::UNAUTHORIZED, "invalid authorization header".into()))?;
        let tw = Token::parse(token_str)
            .map_err(|e| (StatusCode::UNAUTHORIZED, format!("invalid token: {e}")))?;

        let azp = tw
            .custom_field("azp")
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();

        // Extract profile names from token.
        let profile_names: Vec<String> = match tw.custom_field("profiles") {
            Some(serde_json::Value::Array(arr)) => {
                arr.iter().filter_map(|v| v.as_str().map(String::from)).collect()
            }
            Some(serde_json::Value::String(s)) if !s.is_empty() => {
                serde_json::from_str(s).unwrap_or_else(|_| {
                    s.split(',').map(|p| p.trim().to_string()).collect()
                })
            }
            _ => vec![],
        };

        if profile_names.is_empty() {
            return Err((
                StatusCode::FORBIDDEN,
                "token missing profiles claim".into(),
            ));
        }

        // Resolve against cached entitlement profiles.
        if self.profile_cache.is_empty() {
            return Err((
                StatusCode::FORBIDDEN,
                "no entitlement profiles cached yet".into(),
            ));
        }

        for name in &profile_names {
            if let Some(profile) = self.profile_cache.get(name) {
                // azp restriction
                if !profile.azp.is_empty() && !profile.azp.iter().any(|a| a == &azp) {
                    continue;
                }
                // Check RPCs on the TARGET service (not gateway).
                if let Some(rpcs) = profile.services.get(target_service) {
                    for rpc in rpcs {
                        if rpc == "*" || rpc == method {
                            return Ok(());
                        }
                    }
                }
            }
        }

        Err((
            StatusCode::FORBIDDEN,
            format!(
                "method \"{}\" not granted by any profile for service \"{}\"",
                method, target_service
            ),
        ))
    }

    /// Returns raw JWK protos for the JWKS endpoint.
    pub fn get_raw_jwks(&self) -> Vec<ProtoJwk> {
        self.jwk_cache.jwk_protos()
    }
}

/// Extract bearer token from Authorization header value.
fn extract_bearer(header_value: &str) -> Option<&str> {
    header_value
        .strip_prefix("Bearer ")
        .or_else(|| header_value.strip_prefix("bearer "))
}
