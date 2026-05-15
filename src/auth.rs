use std::sync::Arc;

use http::StatusCode;

use gateway_tacplus::types::libs::jwk::jwk::Jwk as ProtoJwk;
use gateway_grpcserver::authorizer::JwkCache;

// Generated libs for JWT parsing (no crypto needed — authorizer handles verification)
use gateway_token::token::Token;

/// Gateway C2S authenticator/authorizer.
///
/// Uses JwkCache for signature verification. Entitlements are read directly
/// from the `service_entitlements` JWT claim (set by opa at mint time),
/// so no separate profile cache is needed.
///   - `aud` must match the **target** service (not "gateway")
///   - entitlements are checked against the **target** service
#[derive(Clone)]
pub struct GatewayAuth {
    jwk_cache: Arc<JwkCache>,
    /// When true, all C2S auth checks are bypassed. Requests are forwarded
    /// to backend services without token validation or entitlement checks.
    /// Set via GATEWAY_AUTH_PASSTHROUGH=1 env var (local testing only).
    passthrough: bool,
}

impl GatewayAuth {
    pub fn new(jwk_cache: Arc<JwkCache>, passthrough: bool) -> Self {
        Self { jwk_cache, passthrough }
    }

    /// Validate a C2S request against the per-route auth policy.
    ///
    /// - `NoAuth`: pass through.
    /// - `AnyUser`: verify token, check aud==target_service, reject S2S tokens.
    /// - `Entitled`: AnyUser + check entitlements against `service_id`.
    ///
    /// `entitlement_service` overrides which service name is used for the
    /// entitlement lookup (for vservices where aud targets the physical host
    /// but entitlements are keyed by the vservice name).
    ///
    /// When passthrough mode is enabled, all policies are treated as NoAuth.
    pub async fn validate_c2s(
        &self,
        auth_policy: gateway_tacplus::s2sm::rest_dispatch::AuthPolicy,
        service_id: &str,
        entitlement_service: &str,
        grpc_path: &str,
        auth_header: Option<&str>,
    ) -> Result<(), (StatusCode, String)> {
        use gateway_tacplus::s2sm::rest_dispatch::AuthPolicy;

        if self.passthrough {
            return Ok(());
        }

        match auth_policy {
            AuthPolicy::NoAuth => Ok(()),
            AuthPolicy::AnyUser => {
                self.authenticate(service_id, auth_header)?;
                Ok(())
            }
            AuthPolicy::Entitled => {
                self.authenticate(service_id, auth_header)?;
                let method = grpc_path.rsplit('/').next().unwrap_or(grpc_path);
                self.check_entitlements(auth_header.unwrap_or(""), entitlement_service, method)?;
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
    ///
    /// Reads the `service_entitlements` JWT claim (set by opa at mint time).
    /// Grants access if `any=true` or if the specific method is listed.
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

        // Extract service_entitlements claim (embedded by opa/kernel at mint time).
        let se_val = tw.custom_field("service_entitlements").ok_or_else(|| {
            (StatusCode::FORBIDDEN, "token missing service_entitlements claim".into())
        })?;

        // The claim may be a JSON string or a nested JSON object.
        let se_obj: serde_json::Value = if se_val.is_string() {
            serde_json::from_str(se_val.as_str().unwrap_or("{}")).unwrap_or(serde_json::Value::Null)
        } else {
            se_val.clone()
        };

        // Global all-entitlements bypass (admin users): {"all": true}
        if se_obj.get("all").and_then(|v| v.as_bool()).unwrap_or(false) {
            return Ok(());
        }

        let svc_ent = se_obj.get(target_service).ok_or_else(|| {
            (StatusCode::FORBIDDEN, format!("no entitlements for service {target_service}"))
        })?;

        // Entitlements are a repeated enum array. 99 = _ANY wildcard (numeric proto value).
        // Kernel serializes enum values as strings using tacplus json_return_value:
        //   SENTINEL_RPCS_ANY → "sentinel_rpcs_any", GATEWAY_RPCS_ANY → "gateway_rpcs_any", etc.
        // Check all representations of the ANY wildcard.
        if let Some(rpcs) = svc_ent.as_array() {
            for rpc in rpcs {
                if rpc.as_u64() == Some(99) {
                    return Ok(()); // numeric ANY
                }
                if let Some(s) = rpc.as_str() {
                    let u = s.to_ascii_uppercase();
                    if u == "ANY" || u.ends_with("_ANY") {
                        return Ok(()); // string ANY ("SENTINEL_RPCS_ANY", "any", etc.)
                    }
                }
            }
        }

        // Legacy format: {"any": true} → wildcard access.
        if svc_ent.get("any").and_then(|v| v.as_bool()).unwrap_or(false) {
            return Ok(());
        }

        Err((
            StatusCode::FORBIDDEN,
            format!("method {method} not entitled for service {target_service}"),
        ))
    }

    /// Check whether a bearer token has expired. Used for per-frame expiry
    #[allow(dead_code)] // TODO: used when per-frame expiry checking is wired for streaming RPCs
    /// checking on streaming RPCs (validate_c2s checks auth on the first frame;
    /// this checks expiry on subsequent frames without re-verifying the signature).
    pub fn check_token_expiry(
        &self,
        auth_header: Option<&str>,
    ) -> Result<(), (StatusCode, String)> {
        let token_str = extract_bearer(
            auth_header.ok_or_else(|| {
                (StatusCode::UNAUTHORIZED, "missing authorization header".into())
            })?,
        )
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "invalid authorization header".into()))?;

        let tw = Token::parse(token_str)
            .map_err(|e| (StatusCode::UNAUTHORIZED, format!("invalid token: {e}")))?;

        match tw.expiration() {
            Some(exp) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                if now >= exp {
                    return Err((StatusCode::UNAUTHORIZED, "token expired".into()));
                }
            }
            None => {
                return Err((StatusCode::UNAUTHORIZED, "token missing expiration".into()));
            }
        }

        Ok(())
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
