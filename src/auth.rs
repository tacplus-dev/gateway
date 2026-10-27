use std::sync::Arc;

use http::StatusCode;

use gateway_grpcserver::{authorizer::JwkCache, spiffe::is_at_or_below};
use gateway_model::grants;
use gateway_model::types::sys::jwk::jwk::Jwk as ProtoJwk;
use gateway_spiffe as spiffe;

// Generated libs for JWT parsing (no crypto needed — authorizer handles verification)
use gateway_token::token::Token;

use verified::VerifiedClaims;

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
    /// Requested via GATEWAY_AUTH_PASSTHROUGH=1 env var (local testing only),
    /// and only ever true in a `dev-bypass` build — see `new()`.
    passthrough: bool,
}

impl GatewayAuth {
    pub fn new(jwk_cache: Arc<JwkCache>, passthrough: bool) -> Self {
        Self {
            jwk_cache,
            // The C2S bypass exists only in `dev-bypass` builds. The shipped
            // image is a plain `cargo build --release` (Dockerfile.cross), where
            // this is a compile-time `false`: no env var, config value or
            // caller can turn auth off in a production binary.
            passthrough: cfg!(feature = "dev-bypass") && passthrough,
        }
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
        auth_policy: gateway_model::s2sm::rest_dispatch::AuthPolicy,
        service_id: &str,
        entitlement_service: &str,
        grpc_path: &str,
        auth_header: Option<&str>,
    ) -> Result<(), (StatusCode, String)> {
        self.verify_c2s(
            auth_policy,
            service_id,
            entitlement_service,
            grpc_path,
            auth_header,
        )
        .map(|_| ())
    }

    /// The shared body of the two `validate_c2s*` entry points.
    ///
    /// Returns the caller's `VerifiedClaims` when the policy required a token,
    /// and `None` when no token was verified (passthrough, or `NoAuth`). Every
    /// downstream check takes that value, so a check can only ever run on
    /// claims this function verified.
    fn verify_c2s(
        &self,
        auth_policy: gateway_model::s2sm::rest_dispatch::AuthPolicy,
        service_id: &str,
        entitlement_service: &str,
        grpc_path: &str,
        auth_header: Option<&str>,
    ) -> Result<Option<VerifiedClaims>, (StatusCode, String)> {
        use gateway_model::s2sm::rest_dispatch::AuthPolicy;

        if self.passthrough {
            return Ok(None);
        }

        match auth_policy {
            AuthPolicy::NoAuth => Ok(None),
            AuthPolicy::AnyUser => Ok(Some(self.authenticate(service_id, auth_header)?)),
            AuthPolicy::Entitled => {
                let claims = self.authenticate(service_id, auth_header)?;
                self.check_entitlements(&claims, entitlement_service, grpc_path)?;
                Ok(Some(claims))
            }
        }
    }

    /// Validate token/audience/entitlements and, when the generated proto
    /// metadata exposes a target namespace, enforce the level-or-below rule.
    pub async fn validate_c2s_with_target_namespace(
        &self,
        auth_policy: gateway_model::s2sm::rest_dispatch::AuthPolicy,
        service_id: &str,
        entitlement_service: &str,
        grpc_path: &str,
        auth_header: Option<&str>,
        target_namespace: Option<&str>,
    ) -> Result<(), (StatusCode, String)> {
        // `None` covers exactly the cases that skipped the namespace check
        // before: passthrough, and `NoAuth`.
        let claims = self.verify_c2s(
            auth_policy,
            service_id,
            entitlement_service,
            grpc_path,
            auth_header,
        )?;

        if let (Some(claims), Some(target_namespace)) = (claims.as_ref(), target_namespace) {
            self.check_target_namespace(claims, target_namespace)?;
        }

        Ok(())
    }

    /// Verify token signature + aud == target_service, then reject S2S tokens.
    ///
    /// The returned `VerifiedClaims` is the only handle on this token's claims
    /// the downstream checks accept, so verification cannot be skipped.
    fn authenticate(
        &self,
        target_service: &str,
        auth_header: Option<&str>,
    ) -> Result<VerifiedClaims, (StatusCode, String)> {
        VerifiedClaims::authenticate(&self.jwk_cache, target_service, auth_header)
    }

    /// Check entitlements against the **target** service (not gateway).
    ///
    /// Reads the `service_entitlements` JWT claim (set by opa at mint time).
    /// Apart from the admin `{"all": true}` bypass, the only way to authorize is
    /// `flat_grants_allow` — the generated catalog. There is no second path.
    ///
    /// Takes `VerifiedClaims` rather than the raw header: the claims read here
    /// are the ones `authenticate` already verified, and there is no way to
    /// call this on a token whose signature, expiry and audience were not
    /// checked first.
    fn check_entitlements(
        &self,
        claims: &VerifiedClaims,
        target_service: &str,
        grpc_path: &str,
    ) -> Result<(), (StatusCode, String)> {
        let method = grpc_path.rsplit('/').next().unwrap_or(grpc_path);

        // Extract service_entitlements claim (embedded by opa/kernel at mint time).
        let se_val = claims.custom_field("service_entitlements").ok_or_else(|| {
            (
                StatusCode::FORBIDDEN,
                "token missing service_entitlements claim".into(),
            )
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

        if flat_grants_allow(&se_obj, target_service, grpc_path) {
            return Ok(());
        }

        Err((
            StatusCode::FORBIDDEN,
            format!("method {method} not entitled for service {target_service}"),
        ))
    }

    /// Enforce the level-or-below rule on the caller's verified namespace claim.
    fn check_target_namespace(
        &self,
        claims: &VerifiedClaims,
        target_namespace: &str,
    ) -> Result<(), (StatusCode, String)> {
        if target_namespace.is_empty() {
            return Err((
                StatusCode::FORBIDDEN,
                "target namespace field is empty".into(),
            ));
        }

        let caller_namespace = claims.namespace();
        if caller_namespace.is_empty() {
            return Err((
                StatusCode::FORBIDDEN,
                "token has empty namespace claim".into(),
            ));
        }
        if !is_at_or_below(caller_namespace, target_namespace) {
            return Err((
                StatusCode::FORBIDDEN,
                format!(
                    "caller namespace \"{}\" is not at-or-above target \"{}\"",
                    caller_namespace, target_namespace
                ),
            ));
        }
        Ok(())
    }

    /// The tenant a caller's verified namespace claim names, for routing a
    /// tenant-owned service to `<svc>-<tenant>`.
    ///
    /// Runs the same `verify_c2s` every other check runs, so the namespace read
    /// here comes off a token whose signature, expiry and audience were checked
    /// — a claim is never parsed and trusted. The namespace itself is normalized
    /// by the generated `spiffe` chassis, which is also what rejects anything
    /// that is not rooted at `/system` or `/tenants`.
    ///
    /// A `/system/...` caller is REJECTED: a tenant-owned service has no shared
    /// instance to fall back to, so there is no tenant to route to. So is a
    /// caller with no verified claims at all (`NoAuth`, or a `dev-bypass`
    /// passthrough build) — same reason. See the decision doc's Open question 2.
    pub fn caller_tenant(
        &self,
        auth_policy: gateway_model::s2sm::rest_dispatch::AuthPolicy,
        service_id: &str,
        entitlement_service: &str,
        grpc_path: &str,
        auth_header: Option<&str>,
    ) -> Result<String, (StatusCode, String)> {
        let claims = self
            .verify_c2s(
                auth_policy,
                service_id,
                entitlement_service,
                grpc_path,
                auth_header,
            )?
            .ok_or_else(|| {
                (
                    StatusCode::FORBIDDEN,
                    format!(
                        "tenant-owned service \"{}\" cannot be routed for an unauthenticated caller",
                        service_id
                    ),
                )
            })?;

        let namespace = spiffe::normalize_namespace(claims.namespace()).map_err(|e| {
            (
                StatusCode::FORBIDDEN,
                format!("token namespace claim is malformed: {}", e),
            )
        })?;

        // normalize_namespace guarantees the path is rooted at /system or
        // /tenants and that a /tenants root is followed by a tenant name, so the
        // only case left to reject is the /system one.
        let mut segments = namespace.trim_start_matches('/').split('/');
        match (segments.next(), segments.next()) {
            (Some(spiffe::TENANTS_SEGMENT), Some(tenant)) => Ok(tenant.to_string()),
            _ => Err((
                StatusCode::FORBIDDEN,
                format!(
                    "caller namespace \"{}\" is not tenant-scoped; tenant-owned service \"{}\" has no instance to route to",
                    namespace, service_id
                ),
            )),
        }
    }

    /// Check whether a bearer token has expired.
    #[allow(dead_code)]
    pub fn check_token_expiry(
        &self,
        auth_header: Option<&str>,
    ) -> Result<(), (StatusCode, String)> {
        let token_str = extract_bearer(auth_header.ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "missing authorization header".into(),
            )
        })?)
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "invalid authorization header".into(),
            )
        })?;

        let tw = Token::parse(token_str)
            .map_err(|e| (StatusCode::UNAUTHORIZED, format!("invalid token: {e}")))?;

        ensure_not_expired(&tw)
    }

    /// Returns raw JWK protos for the JWKS endpoint.
    pub fn get_raw_jwks(&self) -> Vec<ProtoJwk> {
        self.jwk_cache.jwk_protos()
    }
}

/// `VerifiedClaims` and its only constructor.
///
/// The inner `Token` is private to this module and `authenticate` is the only
/// way to build a `VerifiedClaims`, so no code outside can produce one from a
/// token whose signature, expiry and audience were not checked. Handing that
/// value to the entitlement and namespace checks turns "authenticate() ran
/// first" from a call-ordering convention into a compile-time requirement: a
/// refactor that drops or reorders authentication no longer builds.
mod verified {
    use super::{ensure_not_expired, extract_bearer, JwkCache, StatusCode, Token};

    pub struct VerifiedClaims {
        token: Token,
    }

    impl VerifiedClaims {
        /// Verify token signature + aud == target_service, then reject S2S tokens.
        pub fn authenticate(
            jwk_cache: &JwkCache,
            target_service: &str,
            auth_header: Option<&str>,
        ) -> Result<Self, (StatusCode, String)> {
            let token_str = extract_bearer(auth_header.ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    "missing authorization header".into(),
                )
            })?)
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    "invalid authorization header".into(),
                )
            })?;

            // Parse token
            let tw = Token::parse(token_str)
                .map_err(|e| (StatusCode::UNAUTHORIZED, format!("invalid token: {e}")))?;

            // Verify signature using JWK cache
            let kid = tw.kid().ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    "token missing key ID (kid)".into(),
                )
            })?;

            let jwk = jwk_cache.get(kid).ok_or_else(|| {
                if jwk_cache.has_keys() {
                    (
                        StatusCode::UNAUTHORIZED,
                        format!("unknown signing key: {kid}"),
                    )
                } else {
                    // No keys loaded yet — fail CLOSED. Until the JWK cache has
                    // a key to verify against, no token can be trusted, so every
                    // request is rejected rather than waved through.
                    (StatusCode::UNAUTHORIZED, "no JWK keys loaded yet".into())
                }
            })?;

            tw.verify(&jwk).map_err(|e| {
                (
                    StatusCode::UNAUTHORIZED,
                    format!("token verification failed: {e}"),
                )
            })?;

            ensure_not_expired(&tw)?;

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

            Ok(Self { token: tw })
        }

        pub fn custom_field(&self, key: &str) -> Option<&serde_json::Value> {
            self.token.custom_field(key)
        }

        pub fn namespace(&self) -> &str {
            self.token.namespace().unwrap_or("")
        }
    }
}

/// Extract bearer token from Authorization header value.
fn extract_bearer(header_value: &str) -> Option<&str> {
    header_value
        .strip_prefix("Bearer ")
        .or_else(|| header_value.strip_prefix("bearer "))
}

fn ensure_not_expired(token: &Token) -> Result<(), (StatusCode, String)> {
    match token.expiration() {
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

/// Authorizes a call against the flat `grants` list by the GENERATED grant
/// catalog only.
///
/// Every decision goes through `grants::normalize`, which expands a wildcard to
/// the exact member tokens the generator computed for it and drops anything the
/// catalog does not know. Nothing is inferred from the SHAPE of a token: a
/// hand-rolled "ends in _ANY" rule is a second, divergent copy of the wildcard
/// vocabulary that tacplus already emits, and it grants by string spelling
/// rather than by what the wildcard actually covers — e.g. a bare "ANY" or a
/// `<SERVICE>_ANY` for a service with no catalog entry used to allow every
/// method of that service, including methods no C2S grant exists for.
fn flat_grants_allow(se_obj: &serde_json::Value, target_service: &str, grpc_path: &str) -> bool {
    let grant_tokens = collect_flat_grants(se_obj);
    if grant_tokens.is_empty() {
        return false;
    }

    let Some(expected) = method_grant_token(target_service, grpc_path) else {
        return false;
    };

    grants::normalize(grant_tokens.iter().map(String::as_str))
        .iter()
        .any(|token| *token == expected)
}

fn collect_flat_grants(value: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(grants) = value.get("grants") {
        collect_grant_tokens(grants, &mut out);
    }
    dedupe_preserving_order(out)
}

fn collect_grant_tokens(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) if !s.is_empty() => out.push(s.to_ascii_uppercase()),
        serde_json::Value::Array(items) => {
            for item in items {
                collect_grant_tokens(item, out);
            }
        }
        serde_json::Value::Object(obj) => {
            if let Some(token) = obj.get("token").and_then(|v| v.as_str()) {
                if !token.is_empty() {
                    out.push(token.to_ascii_uppercase());
                }
            }
        }
        _ => {}
    }
}

fn method_grant_token(target_service: &str, grpc_path: &str) -> Option<String> {
    let path = grpc_path.trim_start_matches('/');
    let (qualified_service, method) = path.split_once('/')?;
    if method.is_empty() {
        return None;
    }
    let service = qualified_service
        .rsplit('.')
        .next()
        .filter(|s| !s.is_empty())?;
    Some(format!(
        "{}_{}_{}",
        grant_token_part(target_service),
        grant_token_part(service),
        grant_token_part(method)
    ))
}

fn grant_token_part(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    let mut prev_was_sep = true;
    let mut prev_was_lower_or_digit = false;
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            let is_upper = ch.is_ascii_uppercase();
            if is_upper && prev_was_lower_or_digit && !prev_was_sep {
                out.push('_');
            }
            out.push(ch.to_ascii_uppercase());
            prev_was_sep = false;
            prev_was_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        } else if !out.ends_with('_') && !out.is_empty() {
            out.push('_');
            prev_was_sep = true;
            prev_was_lower_or_digit = false;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    out
}

fn dedupe_preserving_order(input: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::with_capacity(input.len());
    for item in input {
        if seen.insert(item.clone()) {
            out.push(item);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_jwk::jwk::{ImmutableJwk, Jwk};
    use gateway_key::{base64_utils, keys};
    use gateway_model::s2sm::rest_dispatch::AuthPolicy;

    /// Publish a throwaway signing key as the JWK the cache verifies against.
    fn jwk_for(key: &keys::ImmutableKey) -> ImmutableJwk {
        let keys::PublicKey::EcP256(ec) = key.public_key() else {
            panic!("these tests sign with P-256");
        };
        let point = ec.to_encoded_point(false);
        ImmutableJwk::new(Jwk {
            kty: "EC".to_string(),
            alg: Some(key.alg().to_string()),
            kid: key.id().to_string(),
            key_use: Some("sig".to_string()),
            n: None,
            e: None,
            crv: Some("P-256".to_string()),
            x: Some(base64_utils::encode_base64_url(point.x().expect("x"))),
            y: Some(base64_utils::encode_base64_url(point.y().expect("y"))),
            exp: None,
            created: None,
        })
        .expect("jwk")
    }

    /// Mint a signed user token carrying `entitlements` as its
    /// `service_entitlements` claim, audienced at `echo`.
    fn signed_header(key: &keys::ImmutableKey, entitlements: &serde_json::Value) -> String {
        let mut token = Token::new();
        token.set_kid(key.id()).expect("kid");
        token.set_alg(key.alg()).expect("alg");
        token.set_issuer("unit-test").expect("iss");
        token.set_subject("alice@example.com").expect("sub");
        token.set_audience("echo").expect("aud");
        token.set_namespace("acme").expect("ns");
        token
            .set_expiration(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_secs() as i64
                    + 3600,
            )
            .expect("exp");
        token
            .set_service_entitlements(entitlements.clone())
            .expect("service_entitlements");
        token.sign(key).expect("sign");
        format!("Bearer {}", token.base64().expect("base64"))
    }

    /// The passthrough switch must be honored only in a `dev-bypass` build.
    /// Same assertion in both directions so the guarantee is checked by
    /// `cargo test` and by `cargo test --features dev-bypass`.
    #[tokio::test]
    async fn passthrough_is_honored_only_in_dev_bypass_builds() {
        let auth = GatewayAuth::new(Arc::new(JwkCache::seeded(vec![])), true);
        let result = auth
            .validate_c2s(AuthPolicy::AnyUser, "echo", "echo", "/echo.Echo/Ping", None)
            .await;

        if cfg!(feature = "dev-bypass") {
            assert!(
                result.is_ok(),
                "dev-bypass build must honor passthrough: {result:?}"
            );
        } else {
            let (code, _) = result.expect_err("production build must ignore passthrough");
            assert_eq!(code, StatusCode::UNAUTHORIZED);
        }
    }

    /// Tokens the generated catalog does not know grant NOTHING, however they
    /// are spelled. `ECHO_RPCS_ANY` is the legacy per-service enum name; it is
    /// absent from the catalog, and kernel/opa already drop it as unknown.
    /// Gateway was the last consumer honoring it, by string shape alone.
    #[test]
    fn flat_grants_reject_tokens_outside_the_generated_catalog() {
        for token in ["ANY", "ECHO_RPCS_ANY", "NOTASERVICE_ANY"] {
            let entitlements = serde_json::json!({ "grants": [token] });
            assert!(
                !flat_grants_allow(&entitlements, "echo", "/echo.Echo/Ping"),
                "uncatalogued token {token} must not authorize"
            );
        }
    }

    // These use kernel's catalog entries, which every fleet gateway is built
    // with; they used to use the launch bundle's `echo` sample service, which
    // a fleet need not carry.
    #[test]
    fn flat_grants_accept_generated_package_wildcard() {
        let entitlements = serde_json::json!({"grants": ["KERNEL_ANY"]});
        assert!(flat_grants_allow(
            &entitlements,
            "kernel",
            "/kernel.TenantAdmin/ListTenants"
        ));
        assert!(!flat_grants_allow(
            &entitlements,
            "stratum",
            "/stratum.Stratum/Anything"
        ));
    }

    #[test]
    fn flat_grants_accept_object_wrapper_shape() {
        let entitlements = serde_json::json!({"grants": [{"token": "KERNEL_ANY"}]});
        assert!(flat_grants_allow(
            &entitlements,
            "kernel",
            "/kernel.TenantAdmin/ListTenants"
        ));
    }

    #[test]
    fn flat_grants_accept_exact_catalog_token() {
        let entitlements = serde_json::json!({"grants": ["KERNEL_TENANT_ADMIN_LIST_TENANTS"]});
        assert!(flat_grants_allow(
            &entitlements,
            "kernel",
            "/kernel.TenantAdmin/ListTenants"
        ));
    }

    /// Regression: the nested per-service claim shape must not authorize.
    ///
    /// Nothing mints `{"<service>": [...]}` any more — the generated
    /// `TokenEntitlements` has only flat repeated-string fields, kernel writes
    /// the claim solely through `flatServiceEntitlementsJson`, and opa's policy
    /// returns `{"token_entitlements": {"grants": [...]}}`. Gateway used to
    /// honor that shape anyway, by string spelling: a bare `"ANY"`, any
    /// `*_ANY`, or a legacy `{"any": true}` opened every method of the named
    /// service, catalog entry or not. Each token below took that path to `Ok`;
    /// all of them must now be FORBIDDEN.
    ///
    /// Also the before/after control for the `VerifiedClaims` refactor: the
    /// legitimate call path — verify, then check — still reaches
    /// `check_entitlements` and still denies exactly these tokens.
    #[test]
    fn nested_per_service_wildcards_no_longer_authorize() {
        let key = keys::generate_ec_p256_key().expect("signing key");
        let auth = GatewayAuth::new(Arc::new(JwkCache::seeded(vec![jwk_for(&key)])), false);

        for entitlements in [
            serde_json::json!({ "echo": ["ANY"] }),
            serde_json::json!({ "echo": ["ECHO_RPCS_ANY"] }),
            serde_json::json!({ "echo": ["NOTASERVICE_ANY"] }),
            serde_json::json!({ "echo": [99] }),
            serde_json::json!({ "echo": { "any": true } }),
        ] {
            let header = signed_header(&key, &entitlements);

            // `check_entitlements` takes nothing but `VerifiedClaims`, so this
            // is the only way to reach it.
            let claims = auth
                .authenticate("echo", Some(&header))
                .expect("token must authenticate");

            let (code, _) = auth
                .check_entitlements(&claims, "echo", "/echo.Echo/Ping")
                .expect_err(&format!("{entitlements} must not authorize"));
            assert_eq!(
                code,
                StatusCode::FORBIDDEN,
                "{entitlements} must be denied, not authorized by token shape"
            );
        }
    }

    /// The entitlement check is gated on verification by the type system.
    ///
    /// `check_entitlements`/`check_target_namespace` accept only
    /// `VerifiedClaims`, and `VerifiedClaims`'s single constructor is
    /// `authenticate` — its inner token is private to `mod verified`. So there
    /// is no expression that reaches either check for a token the JWK cache
    /// cannot verify; the attempt below stops at `authenticate` with a 401,
    /// and skipping that step does not compile.
    #[test]
    fn entitlement_check_is_unreachable_without_verification() {
        let key = keys::generate_ec_p256_key().expect("signing key");
        // A token signed by a key the cache does not know — well-formed, with
        // an entitlement claim that would otherwise authorize.
        let header = signed_header(&key, &serde_json::json!({ "grants": ["ECHO_ECHO_PING"] }));
        let auth = GatewayAuth::new(Arc::new(JwkCache::seeded(vec![])), false);

        let (code, _) = auth
            .authenticate("echo", Some(&header))
            .err()
            .expect("unverifiable token must not yield VerifiedClaims");
        assert_eq!(code, StatusCode::UNAUTHORIZED);
    }

    /// The namespace check reads the caller namespace off the same verified
    /// claims, and enforces level-or-below unchanged.
    #[test]
    fn target_namespace_check_uses_verified_claims() {
        let key = keys::generate_ec_p256_key().expect("signing key");
        let auth = GatewayAuth::new(Arc::new(JwkCache::seeded(vec![jwk_for(&key)])), false);

        let mut token = Token::new();
        token.set_kid(key.id()).expect("kid");
        token.set_alg(key.alg()).expect("alg");
        token.set_issuer("unit-test").expect("iss");
        token.set_subject("alice@example.com").expect("sub");
        token.set_audience("echo").expect("aud");
        token.set_namespace("acme").expect("ns");
        token
            .set_expiration(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_secs() as i64
                    + 3600,
            )
            .expect("exp");
        token.sign(&key).expect("sign");
        let header = format!("Bearer {}", token.base64().expect("base64"));

        let claims = auth
            .authenticate("echo", Some(&header))
            .expect("token must authenticate");

        assert!(auth.check_target_namespace(&claims, "acme/eu").is_ok());
        let (code, _) = auth
            .check_target_namespace(&claims, "other")
            .expect_err("a sibling namespace must be denied");
        assert_eq!(code, StatusCode::FORBIDDEN);
    }

    /// A route that requires no token verifies no claims, so there is no tenant
    /// to route to. A tenant-owned service must refuse rather than invent one.
    #[test]
    fn a_tenant_owned_service_refuses_a_caller_with_no_verified_claims() {
        use gateway_model::s2sm::rest_dispatch::AuthPolicy;

        let auth = GatewayAuth::new(Arc::new(JwkCache::seeded(vec![])), false);
        let (code, msg) = auth
            .caller_tenant(
                AuthPolicy::NoAuth,
                "docmanager",
                "docmanager",
                "/x.Y/Z",
                None,
            )
            .expect_err("an unauthenticated caller has no tenant");

        assert_eq!(code, StatusCode::FORBIDDEN);
        assert!(
            msg.contains("unauthenticated"),
            "the rejection must name the reason, got {msg:?}"
        );
    }

    #[test]
    fn method_grant_token_matches_catalog_shape() {
        assert_eq!(
            method_grant_token("echo", "/echo.Echo/Ping").as_deref(),
            Some("ECHO_ECHO_PING")
        );
    }
}
