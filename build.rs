// build.rs — generates REST→gRPC dispatch from tacplus/registry.json.
//
// Reads the registry tree, collects all gateway-exposed RPCs (those with http_path),
// and generates a Rust source file with typed dispatch match arms.

use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::env;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=target/generated-sources/tacplus/registry.json");

    let registry_path = Path::new("target/generated-sources/tacplus/registry.json");
    if !registry_path.exists() {
        // During initial cargo build before tacplus generation, skip.
        return;
    }

    let data: Value =
        serde_json::from_str(&fs::read_to_string(registry_path).expect("read registry.json"))
            .expect("parse registry.json");

    // Build package → full_path map from registry tree.
    let mut pkg_to_path: HashMap<String, String> = HashMap::new();
    build_pkg_map(&data, &mut pkg_to_path);

    // Extract named constants from the registry tree.
    let mut constants: HashMap<String, String> = HashMap::new();
    collect_constants(&data, &mut constants);

    // Collect gateway-exposed RPCs.
    let mut unary_arms: Vec<DispatchArm> = Vec::new();
    let mut stream_arms: Vec<DispatchArm> = Vec::new();
    collect_rpcs(&data, &pkg_to_path, &mut unary_arms, &mut stream_arms);

    // Collect all routes for the static route table (includes everything,
    // even services skipped by collect_rpcs like gateway.MintService).
    let mut route_entries: Vec<RouteEntry> = Vec::new();
    let mut no_auth_packages: BTreeSet<String> = BTreeSet::new();
    collect_routes(&data, &mut route_entries, &mut no_auth_packages);

    // Generate the output file.
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR");
    let out_path = Path::new(&out_dir).join("rest_dispatch.rs");
    let code = generate_dispatch(
        &unary_arms,
        &stream_arms,
        &pkg_to_path,
        &constants,
        &route_entries,
        &no_auth_packages,
    );
    fs::write(&out_path, code).expect("write rest_dispatch.rs");
}

struct DispatchArm {
    grpc_path: String,
    method_snake: String,
    input_type: String,  // proto FQN
    output_type: String, // proto FQN
    is_empty_input: bool,
    service_name: String,  // e.g. "BigDataService"
    package_name: String,  // e.g. "bigdata"
    client_streaming: bool,
}

/// A route entry collected from registry.json for the static route table.
struct RouteEntry {
    http_path: String,
    grpc_path: String,
    service_id: String,
    http_methods: Vec<String>,
    auth_policy: String, // "Require", "NoAuth"
    server_streaming: bool,
}

/// Walk the registry tree and build a mapping from proto package name to full_path.
fn build_pkg_map(node: &Value, pkg_map: &mut HashMap<String, String>) {
    let full_path = node
        .get("full_path")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Extract packages from types.
    if let Some(types) = node.get("types").and_then(|v| v.as_array()) {
        for t in types {
            if let Some(pkg) = t.get("package").and_then(|v| v.as_str()) {
                if !pkg.is_empty() && !full_path.is_empty() {
                    pkg_map.entry(pkg.to_string()).or_insert_with(|| full_path.to_string());
                }
            }
        }
    }

    // Extract packages from services.
    if let Some(services) = node.get("services").and_then(|v| v.as_array()) {
        for svc in services {
            if let Some(gs) = svc.get("grpc_service").and_then(|v| v.as_str()) {
                if let Some(pkg) = gs.split('.').next() {
                    if !pkg.is_empty() && !full_path.is_empty() {
                        pkg_map.entry(pkg.to_string()).or_insert_with(|| full_path.to_string());
                    }
                }
            }
        }
    }

    // Recurse into children.
    if let Some(children) = node.get("children").and_then(|v| v.as_array()) {
        for child in children {
            build_pkg_map(child, pkg_map);
        }
    }
}

/// Collect gateway-exposed RPCs from the registry tree.
fn collect_rpcs(
    node: &Value,
    pkg_map: &HashMap<String, String>,
    unary: &mut Vec<DispatchArm>,
    streaming: &mut Vec<DispatchArm>,
) {
    if let Some(services) = node.get("services").and_then(|v| v.as_array()) {
        for svc in services {
            let grpc_service = match svc.get("grpc_service").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => continue,
            };

            // Skip gateway.MintService — its RPCs (TokenMint, X509Mint) are
            // delegated to kernel and handled by special-case code in rest.rs
            // which uses kernel::MintServiceClient (correct gRPC path).
            // The generic dispatch would use gateway::MintServiceClient which
            // sends to /gateway.MintService/* — a path kernel doesn't serve.
            if grpc_service == "gateway.MintService" {
                continue;
            }

            // Skip internal services that don't have REST dispatch.
            if grpc_service.contains("ViewService")
                || grpc_service.contains("LockService")
                || grpc_service.contains("ClusterService")
                || grpc_service.contains("ConfigStateService")
                || grpc_service.contains("HealthStateService")
                || grpc_service.contains("TlsStateService")
                || grpc_service.contains("IdentityStateService")
                || grpc_service.contains("TrustedCaStateService")
                || grpc_service.contains("CaStateService")
            {
                // These are internal state/watch services handled by passthrough gRPC,
                // not exposed as REST. Only skip if none of their RPCs have http_path.
                let has_rest = svc
                    .get("rpcs")
                    .and_then(|v| v.as_array())
                    .map(|rpcs| rpcs.iter().any(|r| {
                        r.get("http_path").and_then(|v| v.as_str()).map(|s| !s.is_empty()).unwrap_or(false)
                    }))
                    .unwrap_or(false);
                if !has_rest {
                    continue;
                }
            }

            let parts: Vec<&str> = grpc_service.split('.').collect();
            if parts.len() != 2 {
                continue;
            }
            let pkg = parts[0];
            let svc_name = parts[1];

            let rpcs = match svc.get("rpcs").and_then(|v| v.as_array()) {
                Some(r) => r,
                None => continue,
            };

            for rpc in rpcs {
                let http_path = rpc.get("http_path").and_then(|v| v.as_str()).unwrap_or("");
                if http_path.is_empty() {
                    continue;
                }

                let grpc_path = rpc.get("grpc_path").and_then(|v| v.as_str()).unwrap_or("");
                let input_type = rpc.get("input_type").and_then(|v| v.as_str()).unwrap_or("");
                let output_type = rpc.get("output_type").and_then(|v| v.as_str()).unwrap_or("");
                let server_streaming = rpc
                    .get("server_streaming")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                // Method name from grpc_path: "/pkg.Service/MethodName" → "MethodName"
                let method_name = grpc_path
                    .rsplit('/')
                    .next()
                    .unwrap_or("");

                let client_streaming = rpc
                    .get("client_streaming")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let is_empty = input_type == "google.protobuf.Empty";

                let arm = DispatchArm {
                    grpc_path: grpc_path.to_string(),
                    method_snake: to_snake_case(method_name),
                    input_type: input_type.to_string(),
                    output_type: output_type.to_string(),
                    is_empty_input: is_empty,
                    service_name: svc_name.to_string(),
                    package_name: pkg.to_string(),
                    client_streaming,
                };

                if server_streaming {
                    streaming.push(arm);
                } else {
                    unary.push(arm);
                }
            }
        }
    }

    if let Some(children) = node.get("children").and_then(|v| v.as_array()) {
        for child in children {
            collect_rpcs(child, pkg_map, unary, streaming);
        }
    }
}

/// Collect all gateway-exposed routes from the registry tree for the static route table.
/// Unlike `collect_rpcs`, this does NOT skip services (e.g. MintService) — the route table
/// needs every RPC with an http_path for auth policy lookup.
fn collect_routes(
    node: &Value,
    routes: &mut Vec<RouteEntry>,
    no_auth_packages: &mut BTreeSet<String>,
) {
    let full_path = node
        .get("full_path")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if let Some(services) = node.get("services").and_then(|v| v.as_array()) {
        for svc in services {
            let grpc_service = match svc.get("grpc_service").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => continue,
            };

            // Skip view services, lock services, cluster services (internal only).
            if grpc_service.contains("ViewService")
                || grpc_service.contains("LockService")
                || grpc_service.contains("ClusterService")
            {
                continue;
            }

            // Derive service_id: "services/identity" → "identity"
            // For non-services/ paths, use event_tag from a sibling service entry.
            let service_id = if full_path.starts_with("services/") {
                full_path
                    .strip_prefix("services/")
                    .unwrap_or(full_path)
                    .to_string()
            } else {
                let tag = services.iter().find_map(|s| {
                    s.get("event_tag")
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string())
                });
                match tag {
                    Some(t) => t,
                    None => continue,
                }
            };

            let rpcs = match svc.get("rpcs").and_then(|v| v.as_array()) {
                Some(r) => r,
                None => continue,
            };

            // Track whether ALL RPCs in this service have auth_disabled
            let all_no_auth = !rpcs.is_empty()
                && rpcs.iter().all(|rpc| {
                    rpc.get("auth_disabled")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                });

            if all_no_auth {
                if let Some(pkg) = grpc_service.split('.').next() {
                    no_auth_packages.insert(pkg.to_string());
                }
            }

            for rpc in rpcs {
                let http_path = rpc.get("http_path").and_then(|v| v.as_str()).unwrap_or("");
                let grpc_path = rpc.get("grpc_path").and_then(|v| v.as_str()).unwrap_or("");

                let http_methods: Vec<String> = rpc
                    .get("http_methods")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();

                if http_path.is_empty() || http_methods.is_empty() {
                    continue;
                }

                let auth_disabled = rpc
                    .get("auth_disabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                let auth_policy = if auth_disabled {
                    "NoAuth".to_string()
                } else {
                    "Require".to_string()
                };

                let server_streaming = rpc
                    .get("server_streaming")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                // Convention path entry
                routes.push(RouteEntry {
                    http_path: http_path.to_string(),
                    grpc_path: grpc_path.to_string(),
                    service_id: service_id.clone(),
                    http_methods: http_methods.clone(),
                    auth_policy: auth_policy.clone(),
                    server_streaming,
                });

                // Alias path entry (same route info, different http_path)
                let alias_path = rpc
                    .get("http_alias_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                if !alias_path.is_empty() {
                    routes.push(RouteEntry {
                        http_path: alias_path.to_string(),
                        grpc_path: grpc_path.to_string(),
                        service_id: service_id.clone(),
                        http_methods,
                        auth_policy,
                        server_streaming,
                    });
                }
            }
        }
    }

    if let Some(children) = node.get("children").and_then(|v| v.as_array()) {
        for child in children {
            collect_routes(child, routes, no_auth_packages);
        }
    }
}

/// Collect named constants from all nodes in the registry tree.
fn collect_constants(node: &Value, constants: &mut HashMap<String, String>) {
    if let Some(consts) = node.get("constants").and_then(|v| v.as_object()) {
        for (name, value) in consts {
            if let Some(v) = value.as_str() {
                constants.entry(name.clone()).or_insert_with(|| v.to_string());
            }
        }
    }
    if let Some(children) = node.get("children").and_then(|v| v.as_array()) {
        for child in children {
            collect_constants(child, constants);
        }
    }
}

/// Generate the rest_dispatch.rs source code.
fn generate_dispatch(
    unary: &[DispatchArm],
    streaming: &[DispatchArm],
    pkg_map: &HashMap<String, String>,
    constants: &HashMap<String, String>,
    route_entries: &[RouteEntry],
    no_auth_packages: &BTreeSet<String>,
) -> String {
    let mut out = String::new();

    // Header
    writeln!(out, "// Generated by build.rs from tacplus/registry.json").unwrap();
    writeln!(out, "// DO NOT EDIT").unwrap();
    writeln!(out).unwrap();

    // Emit named constants from registry.json.
    if let Some(rest_root) = constants.get("REST_ROOT_PATH") {
        writeln!(out, "/// Base path for all REST endpoints, from kernel.proto REST_ROOT_PATH.").unwrap();
        writeln!(out, "pub const REST_ROOT_PATH: &str = \"{}\";", rest_root).unwrap();
        writeln!(out).unwrap();
    }

    writeln!(out, "use axum::http::StatusCode;").unwrap();
    writeln!(out, "use axum::response::{{IntoResponse, Response}};").unwrap();
    writeln!(out, "use tonic::transport::Channel;").unwrap();
    writeln!(out).unwrap();

    // Collect unique client imports, type imports, and from_json helper imports.
    let mut client_imports: BTreeSet<String> = BTreeSet::new();
    let mut type_imports: BTreeSet<String> = BTreeSet::new();
    let mut from_json_imports: BTreeSet<String> = BTreeSet::new();

    let all_arms: Vec<&DispatchArm> = unary.iter().chain(streaming.iter()).collect();

    for arm in &all_arms {
        // Client import
        let client_mod = format!("{}_client", to_snake_case(&arm.service_name));
        if let Some(full_path) = pkg_map.get(&arm.package_name) {
            let mod_path = full_path.replace('/', "::");
            client_imports.insert(format!(
                "use gateway_tacplus::types::{}::{}::{}::{}Client;",
                mod_path, arm.package_name, client_mod, arm.service_name,
            ));
        }

        // Input type import + from_json helper import
        if !arm.is_empty_input {
            if let Some(imp) = resolve_type_import(&arm.input_type, pkg_map) {
                type_imports.insert(imp);
            }
            if let Some(imp) = resolve_from_json_import(&arm.input_type, pkg_map) {
                from_json_imports.insert(imp);
            }
        }

        // Output type import (always needed)
        if arm.output_type != "google.protobuf.Empty" {
            if let Some(imp) = resolve_type_import(&arm.output_type, pkg_map) {
                type_imports.insert(imp);
            }
        }
    }

    for imp in &client_imports {
        writeln!(out, "{imp}").unwrap();
    }
    writeln!(out).unwrap();

    // Only add SSE imports if there are streaming arms.
    if !streaming.is_empty() {
        writeln!(out, "use axum::response::sse::{{Event, Sse}};").unwrap();
        writeln!(out, "use futures::StreamExt;").unwrap();
        let has_client_streaming = streaming.iter().any(|a| a.client_streaming);
        if has_client_streaming {
            writeln!(out, "use futures::stream;").unwrap();
        }
        writeln!(out).unwrap();
    }

    writeln!(out, "#[allow(unused_imports)]").unwrap();
    writeln!(out, "use serde_json;").unwrap();
    for imp in &type_imports {
        writeln!(out, "#[allow(unused_imports)]").unwrap();
        writeln!(out, "{imp}").unwrap();
    }
    for imp in &from_json_imports {
        writeln!(out, "#[allow(unused_imports)]").unwrap();
        writeln!(out, "{imp}").unwrap();
    }
    writeln!(out).unwrap();

    // Handler-specific imports
    writeln!(out, "use uuid::Uuid;").unwrap();
    writeln!(out, "use gateway_tacplus::types::libs::jwk::jwk::{{Jwks, OpenIdConfiguration}};").unwrap();
    writeln!(out, "use gateway_tacplus::types::services::kernel::kernel::kernel_mint_service_client::KernelMintServiceClient as KernelMintClient;").unwrap();
    // token_mint_request_from_json and x509_mint_request_from_json are imported dynamically above via from_json_imports
    writeln!(out).unwrap();

    // DispatchResult type
    writeln!(out, "/// Result type for REST→gRPC dispatch: JSON string on success, HTTP error on failure.").unwrap();
    writeln!(out, "pub type DispatchResult = Result<String, (StatusCode, String)>;").unwrap();
    writeln!(out).unwrap();

    // with_metadata helper
    writeln!(out, "/// Build a tonic Request with forwarded auth and request ID metadata.").unwrap();
    writeln!(out, "fn with_metadata<T>(req: T, auth_header: Option<&str>, request_id: &str) -> tonic::Request<T> {{").unwrap();
    writeln!(out, "    let mut request = tonic::Request::new(req);").unwrap();
    writeln!(out, "    if let Some(auth) = auth_header {{").unwrap();
    writeln!(out, "        if let Ok(val) = auth.parse() {{").unwrap();
    writeln!(out, "            request.metadata_mut().insert(\"authorization\", val);").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "    if let Ok(val) = request_id.parse() {{").unwrap();
    writeln!(out, "        request.metadata_mut().insert(\"x-request-id\", val);").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "    request").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // json_req helper
    writeln!(out, "/// Deserialize a JSON request body into a protobuf message type.").unwrap();
    writeln!(out, "#[allow(dead_code)]").unwrap();
    writeln!(out, "fn json_req<T: serde::de::DeserializeOwned + Default>(body: &[u8]) -> Result<T, (StatusCode, String)> {{").unwrap();
    writeln!(out, "    if body.is_empty() {{").unwrap();
    writeln!(out, "        return Ok(T::default());").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "    serde_json::from_slice(body).map_err(|e| {{").unwrap();
    writeln!(out, "        (StatusCode::BAD_REQUEST, format!(\"{{{{\\\"error\\\":\\\"invalid request body: {{}}\\\"}}}}\", e))").unwrap();
    writeln!(out, "    }})").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // json_ok helper
    writeln!(out, "/// Serialize a protobuf response to JSON.").unwrap();
    writeln!(out, "fn json_ok<T: serde::Serialize>(resp: &T) -> DispatchResult {{").unwrap();
    writeln!(out, "    serde_json::to_string(resp).map_err(|e| {{").unwrap();
    writeln!(out, "        (StatusCode::INTERNAL_SERVER_ERROR, format!(\"{{{{\\\"error\\\":\\\"failed to serialize response: {{}}\\\"}}}}\", e))").unwrap();
    writeln!(out, "    }})").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // grpc_err helper
    writeln!(out, "/// Convert a gRPC status to an HTTP error tuple.").unwrap();
    writeln!(out, "fn grpc_err(status: tonic::Status) -> (StatusCode, String) {{").unwrap();
    writeln!(out, "    let http_code = match status.code() {{").unwrap();
    writeln!(out, "        tonic::Code::NotFound => StatusCode::NOT_FOUND,").unwrap();
    writeln!(out, "        tonic::Code::InvalidArgument => StatusCode::BAD_REQUEST,").unwrap();
    writeln!(out, "        tonic::Code::Unauthenticated => StatusCode::UNAUTHORIZED,").unwrap();
    writeln!(out, "        tonic::Code::PermissionDenied => StatusCode::FORBIDDEN,").unwrap();
    writeln!(out, "        tonic::Code::Unimplemented => StatusCode::NOT_IMPLEMENTED,").unwrap();
    writeln!(out, "        tonic::Code::Unavailable => StatusCode::SERVICE_UNAVAILABLE,").unwrap();
    writeln!(out, "        tonic::Code::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,").unwrap();
    writeln!(out, "        tonic::Code::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,").unwrap();
    writeln!(out, "        _ => StatusCode::INTERNAL_SERVER_ERROR,").unwrap();
    writeln!(out, "    }};").unwrap();
    writeln!(out, "    (http_code, format!(\"{{{{\\\"error\\\":\\\"{{}}\\\"}}}}\", status.message()))").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // AuthPolicy enum
    writeln!(out, "/// Auth policy for a REST route.").unwrap();
    writeln!(out, "#[derive(Debug, Clone, Copy, PartialEq, Eq)]").unwrap();
    writeln!(out, "pub enum AuthPolicy {{").unwrap();
    writeln!(out, "    /// Authentication required — gateway verifies token.").unwrap();
    writeln!(out, "    Require,").unwrap();
    writeln!(out, "    /// No authentication needed.").unwrap();
    writeln!(out, "    NoAuth,").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // RouteInfo struct
    writeln!(out, "/// A REST route entry, generated at compile time from registry.json.").unwrap();
    writeln!(out, "#[allow(dead_code)]").unwrap();
    writeln!(out, "pub struct RouteInfo {{").unwrap();
    writeln!(out, "    pub http_path: &'static str,").unwrap();
    writeln!(out, "    pub grpc_path: &'static str,").unwrap();
    writeln!(out, "    pub service_id: &'static str,").unwrap();
    writeln!(out, "    pub http_methods: &'static [&'static str],").unwrap();
    writeln!(out, "    pub auth_policy: AuthPolicy,").unwrap();
    writeln!(out, "    pub server_streaming: bool,").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // Static ROUTES table
    writeln!(out, "/// All REST routes, generated from registry.json at compile time.").unwrap();
    writeln!(out, "pub static ROUTES: &[RouteInfo] = &[").unwrap();
    for entry in route_entries {
        let methods_literal: Vec<String> = entry
            .http_methods
            .iter()
            .map(|m| format!("\"{}\"", m))
            .collect();
        writeln!(out, "    RouteInfo {{").unwrap();
        writeln!(out, "        http_path: \"{}\",", entry.http_path).unwrap();
        writeln!(out, "        grpc_path: \"{}\",", entry.grpc_path).unwrap();
        writeln!(out, "        service_id: \"{}\",", entry.service_id).unwrap();
        writeln!(out, "        http_methods: &[{}],", methods_literal.join(", ")).unwrap();
        writeln!(out, "        auth_policy: AuthPolicy::{},", entry.auth_policy).unwrap();
        writeln!(out, "        server_streaming: {},", entry.server_streaming).unwrap();
        writeln!(out, "    }},").unwrap();
    }
    writeln!(out, "];").unwrap();
    writeln!(out).unwrap();

    // NO_AUTH_PACKAGES
    writeln!(out, "/// gRPC packages where ALL RPCs skip auth.").unwrap();
    write!(out, "pub static NO_AUTH_PACKAGES: &[&str] = &[").unwrap();
    for (i, pkg) in no_auth_packages.iter().enumerate() {
        if i > 0 {
            write!(out, ", ").unwrap();
        }
        write!(out, "\"{}\"", pkg).unwrap();
    }
    writeln!(out, "];").unwrap();
    writeln!(out).unwrap();

    // is_grpc_no_auth function
    writeln!(out, "/// Check whether a gRPC method path targets a no-auth package.").unwrap();
    writeln!(out, "pub fn is_grpc_no_auth(grpc_method: &str) -> bool {{").unwrap();
    writeln!(out, "    if let Some(trimmed) = grpc_method.strip_prefix('/') {{").unwrap();
    writeln!(out, "        if let Some(dot_idx) = trimmed.find('.') {{").unwrap();
    writeln!(out, "            let pkg = &trimmed[..dot_idx];").unwrap();
    writeln!(out, "            return NO_AUTH_PACKAGES.iter().any(|p| *p == pkg);").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "    false").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // dispatch() function — unary RPCs
    writeln!(out, "/// Dispatch a unary REST→gRPC call based on the gRPC path.").unwrap();
    writeln!(out, "pub async fn dispatch(").unwrap();
    writeln!(out, "    grpc_path: &str,").unwrap();
    writeln!(out, "    body: &[u8],").unwrap();
    writeln!(out, "    channel: Channel,").unwrap();
    writeln!(out, "    auth_header: Option<&str>,").unwrap();
    writeln!(out, "    request_id: &str,").unwrap();
    writeln!(out, ") -> DispatchResult {{").unwrap();
    writeln!(out, "    match grpc_path {{").unwrap();

    for arm in unary {
        writeln!(out, "        \"{}\" => {{", arm.grpc_path).unwrap();
        if arm.is_empty_input {
            writeln!(out, "            let resp = {}Client::new(channel)", arm.service_name).unwrap();
            writeln!(out, "                .{}(with_metadata((), auth_header, request_id))", arm.method_snake).unwrap();
        } else {
            let from_json_fn = resolve_from_json_fn_name(&arm.input_type);
            writeln!(out, "            let req = {}(body).map_err(|e| (StatusCode::BAD_REQUEST, format!(\"{{{{\\\"error\\\":\\\"invalid request body: {{}}\\\"}}}}\", e)))?;", from_json_fn).unwrap();
            writeln!(out, "            let resp = {}Client::new(channel)", arm.service_name).unwrap();
            writeln!(out, "                .{}(with_metadata(req, auth_header, request_id))", arm.method_snake).unwrap();
        }
        writeln!(out, "                .await").unwrap();
        writeln!(out, "                .map_err(grpc_err)?;").unwrap();
        writeln!(out, "            json_ok(&resp.into_inner())").unwrap();
        writeln!(out, "        }}").unwrap();
    }

    writeln!(out, "        _ => Err((").unwrap();
    writeln!(out, "            StatusCode::NOT_IMPLEMENTED,").unwrap();
    writeln!(out, "            format!(\"{{{{\\\"error\\\":\\\"unknown gRPC path: {{}}\\\"}}}}\", grpc_path),").unwrap();
    writeln!(out, "        )),").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // dispatch_stream() function — server-streaming RPCs
    writeln!(out, "/// Dispatch a server-streaming RPC, returning an SSE response.").unwrap();
    writeln!(out, "#[allow(unused_variables)]").unwrap();
    writeln!(out, "pub async fn dispatch_stream(").unwrap();
    writeln!(out, "    grpc_path: &str,").unwrap();
    writeln!(out, "    body: &[u8],").unwrap();
    writeln!(out, "    channel: Channel,").unwrap();
    writeln!(out, "    auth_header: Option<&str>,").unwrap();
    writeln!(out, "    request_id: &str,").unwrap();
    writeln!(out, ") -> Response {{").unwrap();
    writeln!(out, "    match grpc_path {{").unwrap();

    for arm in streaming {
        writeln!(out, "        \"{}\" => {{", arm.grpc_path).unwrap();

        // Deserialize input and call gRPC method
        if arm.is_empty_input {
            if arm.client_streaming {
                // Client-streaming with empty input: wrap () as a one-shot stream
                writeln!(out, "            let stream = match {}Client::new(channel)", arm.service_name).unwrap();
                writeln!(out, "                .{}(with_metadata(stream::once(futures::future::ready(())), auth_header, request_id))", arm.method_snake).unwrap();
            } else {
                writeln!(out, "            let stream = match {}Client::new(channel)", arm.service_name).unwrap();
                writeln!(out, "                .{}(with_metadata((), auth_header, request_id))", arm.method_snake).unwrap();
            }
        } else {
            let from_json_fn = resolve_from_json_fn_name(&arm.input_type);
            writeln!(out, "            let req = match {}(body) {{", from_json_fn).unwrap();
            writeln!(out, "                Ok(r) => r,").unwrap();
            writeln!(out, "                Err(e) => return (StatusCode::BAD_REQUEST, format!(\"{{{{\\\"error\\\":\\\"invalid request body: {{}}\\\"}}}}\", e)).into_response(),").unwrap();
            writeln!(out, "            }};").unwrap();
            if arm.client_streaming {
                // Client-streaming: wrap the single request as a one-shot stream
                writeln!(out, "            let stream = match {}Client::new(channel)", arm.service_name).unwrap();
                writeln!(out, "                .{}(with_metadata(stream::once(futures::future::ready(req)), auth_header, request_id))", arm.method_snake).unwrap();
            } else {
                writeln!(out, "            let stream = match {}Client::new(channel)", arm.service_name).unwrap();
                writeln!(out, "                .{}(with_metadata(req, auth_header, request_id))", arm.method_snake).unwrap();
            }
        }
        writeln!(out, "                .await").unwrap();
        writeln!(out, "            {{").unwrap();
        writeln!(out, "                Ok(resp) => {{").unwrap();
        writeln!(out, "                    tracing::info!(grpc_path = %grpc_path, request_id = %request_id, \"streaming RPC established\");").unwrap();
        writeln!(out, "                    resp.into_inner()").unwrap();
        writeln!(out, "                }}").unwrap();
        writeln!(out, "                Err(status) => {{").unwrap();
        writeln!(out, "                    tracing::warn!(").unwrap();
        writeln!(out, "                        grpc_path = %grpc_path,").unwrap();
        writeln!(out, "                        request_id = %request_id,").unwrap();
        writeln!(out, "                        code = ?status.code(),").unwrap();
        writeln!(out, "                        message = %status.message(),").unwrap();
        writeln!(out, "                        \"streaming RPC failed\"").unwrap();
        writeln!(out, "                    );").unwrap();
        writeln!(out, "                    let (code, msg) = grpc_err(status);").unwrap();
        writeln!(out, "                    return (code, msg).into_response();").unwrap();
        writeln!(out, "                }}").unwrap();
        writeln!(out, "            }};").unwrap();
        writeln!(out, "            let sse_stream = stream.map(|result| match result {{").unwrap();
        writeln!(out, "                Ok(msg) => {{").unwrap();
        writeln!(out, "                    let json = serde_json::to_string(&msg).unwrap_or_default();").unwrap();
        writeln!(out, "                    Ok::<_, std::convert::Infallible>(Event::default().data(json))").unwrap();
        writeln!(out, "                }}").unwrap();
        writeln!(out, "                Err(status) => {{").unwrap();
        writeln!(out, "                    let json = format!(\"{{{{\\\"error\\\":\\\"{{}}\\\"}}}}\", status.message());").unwrap();
        writeln!(out, "                    Ok(Event::default().event(\"error\").data(json))").unwrap();
        writeln!(out, "                }}").unwrap();
        writeln!(out, "            }});").unwrap();
        writeln!(out, "            Sse::new(sse_stream).into_response()").unwrap();
        writeln!(out, "        }}").unwrap();
    }

    writeln!(out, "        _ => (").unwrap();
    writeln!(out, "            StatusCode::NOT_IMPLEMENTED,").unwrap();
    writeln!(out, "            format!(\"{{{{\\\"error\\\":\\\"unknown streaming gRPC path: {{}}\\\"}}}}\", grpc_path),").unwrap();
    writeln!(out, "        ).into_response(),").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // Generate the full REST handler function
    generate_handler(&mut out, route_entries);

    out
}

/// Generate the REST handler function and json_response helper.
fn generate_handler(out: &mut String, route_entries: &[RouteEntry]) {
    // Categorize routes: MintService special cases vs standard dispatch
    let mut mint_oidc: Vec<&RouteEntry> = Vec::new();
    let mut mint_jwks: Vec<&RouteEntry> = Vec::new();
    let mut mint_token: Vec<&RouteEntry> = Vec::new();
    let mut mint_x509: Vec<&RouteEntry> = Vec::new();
    let mut standard: Vec<&RouteEntry> = Vec::new();

    for entry in route_entries {
        match entry.grpc_path.as_str() {
            "/gateway.MintService/OpenIdConfig" => mint_oidc.push(entry),
            "/gateway.MintService/Jwks" => mint_jwks.push(entry),
            "/gateway.MintService/TokenMint" => mint_token.push(entry),
            "/gateway.MintService/X509Mint" => mint_x509.push(entry),
            _ => standard.push(entry),
        }
    }

    // json_response helper
    writeln!(out, "/// Serialize a value to a JSON response.").unwrap();
    writeln!(out, "fn json_response<T: serde::Serialize>(value: &T) -> axum::response::Response {{").unwrap();
    writeln!(out, "    use axum::response::IntoResponse;").unwrap();
    writeln!(out, "    match serde_json::to_string(value) {{").unwrap();
    writeln!(out, "        Ok(json) => (").unwrap();
    writeln!(out, "            StatusCode::OK,").unwrap();
    writeln!(out, "            [(axum::http::header::CONTENT_TYPE, \"application/json\".to_string())],").unwrap();
    writeln!(out, "            json,").unwrap();
    writeln!(out, "        ).into_response(),").unwrap();
    writeln!(out, "        Err(e) => (").unwrap();
    writeln!(out, "            StatusCode::INTERNAL_SERVER_ERROR,").unwrap();
    writeln!(out, "            format!(\"{{{{\\\"error\\\":\\\"failed to serialize response: {{}}\\\"}}}}\", e),").unwrap();
    writeln!(out, "        ).into_response(),").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // rest_handler function
    writeln!(out, "/// Generated REST handler — dispatches requests based on compile-time route table.").unwrap();
    writeln!(out, "pub async fn rest_handler(").unwrap();
    writeln!(out, "    axum::extract::State(state): axum::extract::State<std::sync::Arc<crate::rest::AppState>>,").unwrap();
    writeln!(out, "    headers: axum::http::HeaderMap,").unwrap();
    writeln!(out, "    request: axum::http::Request<axum::body::Body>,").unwrap();
    writeln!(out, ") -> axum::response::Response {{").unwrap();
    writeln!(out, "    use axum::response::IntoResponse;").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "    let path = request.uri().path().to_string();").unwrap();
    writeln!(out, "    let req_method = request.method().clone();").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "    tracing::debug!(path = %path, method = %req_method, \"REST request\");").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "    let auth_header_value = headers").unwrap();
    writeln!(out, "        .get(\"authorization\")").unwrap();
    writeln!(out, "        .and_then(|v| v.to_str().ok())").unwrap();
    writeln!(out, "        .map(|s| s.to_string());").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "    let request_id = headers").unwrap();
    writeln!(out, "        .get(\"x-request-id\")").unwrap();
    writeln!(out, "        .and_then(|v| v.to_str().ok())").unwrap();
    writeln!(out, "        .map(|s| s.to_string())").unwrap();
    writeln!(out, "        .unwrap_or_else(|| Uuid::new_v4().to_string());").unwrap();
    writeln!(out).unwrap();

    // Body reading
    writeln!(out, "    let body_bytes = if req_method == axum::http::Method::GET {{").unwrap();
    writeln!(out, "        b\"{{}}\".to_vec()").unwrap();
    writeln!(out, "    }} else {{").unwrap();
    writeln!(out, "        match axum::body::to_bytes(request.into_body(), 10 * 1024 * 1024).await {{").unwrap();
    writeln!(out, "            Ok(b) => b.to_vec(),").unwrap();
    writeln!(out, "            Err(e) => {{").unwrap();
    writeln!(out, "                return (").unwrap();
    writeln!(out, "                    StatusCode::BAD_REQUEST,").unwrap();
    writeln!(out, "                    format!(\"{{{{\\\"error\\\":\\\"failed to read request body: {{}}\\\"}}}}\", e),").unwrap();
    writeln!(out, "                ).into_response();").unwrap();
    writeln!(out, "            }}").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }};").unwrap();
    writeln!(out).unwrap();

    // Route-specific variables (set by standard match arms, used by common dispatch)
    writeln!(out, "    let grpc_path: &str;").unwrap();
    writeln!(out, "    let service_id: &str;").unwrap();
    writeln!(out, "    let auth_policy: AuthPolicy;").unwrap();
    writeln!(out, "    let server_streaming: bool;").unwrap();
    writeln!(out, "    let allowed_methods: &[&str];").unwrap();
    writeln!(out).unwrap();

    // Match on path
    writeln!(out, "    match path.as_str() {{").unwrap();

    // OIDC special cases (serve locally, no backend)
    for entry in &mint_oidc {
        writeln!(out, "        \"{}\" => {{", entry.http_path).unwrap();
        writeln!(out, "            let host = headers.get(\"host\")").unwrap();
        writeln!(out, "                .and_then(|v| v.to_str().ok())").unwrap();
        writeln!(out, "                .unwrap_or(\"localhost\");").unwrap();
        writeln!(out, "            let base = format!(\"https://{{}}\", host);").unwrap();
        writeln!(out, "            let config = OpenIdConfiguration {{").unwrap();
        writeln!(out, "                issuer: base.clone(),").unwrap();
        writeln!(out, "                jwks_uri: format!(\"{{}}{{}}/.well-known/jwks.json\", base, REST_ROOT_PATH),").unwrap();
        writeln!(out, "                token_endpoint: format!(\"{{}}{{}}/Mint/TokenMint\", base, REST_ROOT_PATH),").unwrap();
        writeln!(out, "                subject_types_supported: vec![\"public\".to_string()],").unwrap();
        writeln!(out, "                id_token_signing_alg_values_supported: vec![\"EdDSA\".to_string()],").unwrap();
        writeln!(out, "                response_types_supported: vec![\"token\".to_string()],").unwrap();
        writeln!(out, "                grant_types_supported: vec![\"urn:ietf:params:oauth:grant-type:token-exchange\".to_string()],").unwrap();
        writeln!(out, "                ..Default::default()").unwrap();
        writeln!(out, "            }};").unwrap();
        writeln!(out, "            return json_response(&config);").unwrap();
        writeln!(out, "        }}").unwrap();
    }

    // JWKS special cases (serve locally from watched keys)
    for entry in &mint_jwks {
        writeln!(out, "        \"{}\" => {{", entry.http_path).unwrap();
        writeln!(out, "            let jwks = Jwks {{").unwrap();
        writeln!(out, "                keys: state.auth.get_raw_jwks(),").unwrap();
        writeln!(out, "            }};").unwrap();
        writeln!(out, "            return json_response(&jwks);").unwrap();
        writeln!(out, "        }}").unwrap();
    }

    // TokenMint special cases (delegate to kernel MintService)
    for entry in &mint_token {
        let methods_literal: Vec<String> = entry.http_methods.iter().map(|m| format!("\"{}\"", m)).collect();
        writeln!(out, "        \"{}\" => {{", entry.http_path).unwrap();
        emit_method_check(out, &methods_literal);
        emit_auth_check(out, &entry.auth_policy);
        writeln!(out, "            tracing::info!(request_id = %request_id, \"routing TokenMint to kernel\");").unwrap();
        writeln!(out, "            let req = match token_mint_request_from_json(&body_bytes) {{").unwrap();
        writeln!(out, "                Ok(r) => r,").unwrap();
        writeln!(out, "                Err(e) => return (StatusCode::BAD_REQUEST, format!(\"{{{{\\\"error\\\":\\\"invalid request body: {{}}\\\"}}}}\", e)).into_response(),").unwrap();
        writeln!(out, "            }};").unwrap();
        writeln!(out, "            let grpc_req = with_metadata(req, auth_header_value.as_deref(), &request_id);").unwrap();
        writeln!(out, "            let mut client = KernelMintClient::new(state.kernel_channel.clone());").unwrap();
        writeln!(out, "            return match client.token_mint(grpc_req).await {{").unwrap();
        writeln!(out, "                Ok(resp) => json_response(&resp.into_inner()),").unwrap();
        writeln!(out, "                Err(status) => {{").unwrap();
        writeln!(out, "                    tracing::warn!(request_id = %request_id, status = %status, \"kernel mint error\");").unwrap();
        writeln!(out, "                    let (code, msg) = grpc_err(status);").unwrap();
        writeln!(out, "                    (code, msg).into_response()").unwrap();
        writeln!(out, "                }}").unwrap();
        writeln!(out, "            }};").unwrap();
        writeln!(out, "        }}").unwrap();
    }

    // X509Mint special cases (delegate to kernel MintService)
    for entry in &mint_x509 {
        let methods_literal: Vec<String> = entry.http_methods.iter().map(|m| format!("\"{}\"", m)).collect();
        writeln!(out, "        \"{}\" => {{", entry.http_path).unwrap();
        emit_method_check(out, &methods_literal);
        emit_auth_check(out, &entry.auth_policy);
        writeln!(out, "            let req = match x509_mint_request_from_json(&body_bytes) {{").unwrap();
        writeln!(out, "                Ok(r) => r,").unwrap();
        writeln!(out, "                Err(e) => return (StatusCode::BAD_REQUEST, format!(\"{{{{\\\"error\\\":\\\"invalid request body: {{}}\\\"}}}}\", e)).into_response(),").unwrap();
        writeln!(out, "            }};").unwrap();
        writeln!(out, "            let grpc_req = with_metadata(req, auth_header_value.as_deref(), &request_id);").unwrap();
        writeln!(out, "            let mut client = KernelMintClient::new(state.kernel_channel.clone());").unwrap();
        writeln!(out, "            return match client.x509_mint(grpc_req).await {{").unwrap();
        writeln!(out, "                Ok(resp) => json_response(&resp.into_inner()),").unwrap();
        writeln!(out, "                Err(status) => {{").unwrap();
        writeln!(out, "                    tracing::warn!(request_id = %request_id, status = %status, \"kernel x509 mint error\");").unwrap();
        writeln!(out, "                    let (code, msg) = grpc_err(status);").unwrap();
        writeln!(out, "                    (code, msg).into_response()").unwrap();
        writeln!(out, "                }}").unwrap();
        writeln!(out, "            }};").unwrap();
        writeln!(out, "        }}").unwrap();
    }

    // Standard route arms (set variables, fall through to common dispatch)
    for entry in &standard {
        let methods_literal: Vec<String> = entry
            .http_methods
            .iter()
            .map(|m| format!("\"{}\"", m))
            .collect();
        writeln!(out, "        \"{}\" => {{", entry.http_path).unwrap();
        writeln!(out, "            grpc_path = \"{}\";", entry.grpc_path).unwrap();
        writeln!(out, "            service_id = \"{}\";", entry.service_id).unwrap();
        writeln!(out, "            auth_policy = AuthPolicy::{};", entry.auth_policy).unwrap();
        writeln!(out, "            server_streaming = {};", entry.server_streaming).unwrap();
        writeln!(out, "            allowed_methods = &[{}];", methods_literal.join(", ")).unwrap();
        writeln!(out, "        }}").unwrap();
    }

    // Catch-all
    writeln!(out, "        _ => {{").unwrap();
    writeln!(out, "            tracing::warn!(path = %path, \"no route found\");").unwrap();
    writeln!(out, "            return (").unwrap();
    writeln!(out, "                StatusCode::NOT_FOUND,").unwrap();
    writeln!(out, "                format!(\"{{{{\\\"error\\\":\\\"unknown route: {{}}\\\"}}}}\", path),").unwrap();
    writeln!(out, "            ).into_response();").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();

    // Common dispatch logic (runs after standard route arms)
    writeln!(out, "    if !allowed_methods.iter().any(|m| m.eq_ignore_ascii_case(req_method.as_str())) {{").unwrap();
    writeln!(out, "        return (").unwrap();
    writeln!(out, "            StatusCode::METHOD_NOT_ALLOWED,").unwrap();
    writeln!(out, "            format!(\"{{{{\\\"error\\\":\\\"method {{}} not allowed for {{}}\\\"}}}}\", req_method, path),").unwrap();
    writeln!(out, "        ).into_response();").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "    if auth_policy == AuthPolicy::Require {{").unwrap();
    writeln!(out, "        if let Err(status) = state.auth.validate_rest(&path, auth_header_value.as_deref()) {{").unwrap();
    writeln!(out, "            tracing::warn!(path = %path, has_auth = auth_header_value.is_some(), error = %status.message(), \"gateway auth rejected\");").unwrap();
    writeln!(out, "            return (").unwrap();
    writeln!(out, "                StatusCode::UNAUTHORIZED,").unwrap();
    writeln!(out, "                format!(\"{{{{\\\"error\\\":\\\"{{}}\\\"}}}}\", status.message()),").unwrap();
    writeln!(out, "            ).into_response();").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "    let channel = if service_id == \"gateway\" {{").unwrap();
    writeln!(out, "        state.kernel_channel.clone()").unwrap();
    writeln!(out, "    }} else {{").unwrap();
    writeln!(out, "        state.resolver.dial(service_id)").unwrap();
    writeln!(out, "    }};").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "    tracing::debug!(").unwrap();
    writeln!(out, "        grpc_path = %grpc_path,").unwrap();
    writeln!(out, "        service = %service_id,").unwrap();
    writeln!(out, "        request_id = %request_id,").unwrap();
    writeln!(out, "        streaming = server_streaming,").unwrap();
    writeln!(out, "        has_auth = auth_header_value.is_some(),").unwrap();
    writeln!(out, "        \"dispatching to backend\"").unwrap();
    writeln!(out, "    );").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "    if server_streaming {{").unwrap();
    writeln!(out, "        return dispatch_stream(grpc_path, &body_bytes, channel, auth_header_value.as_deref(), &request_id).await;").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out).unwrap();
    writeln!(out, "    match dispatch(grpc_path, &body_bytes, channel, auth_header_value.as_deref(), &request_id).await {{").unwrap();
    writeln!(out, "        Ok(json) => (").unwrap();
    writeln!(out, "            StatusCode::OK,").unwrap();
    writeln!(out, "            [(axum::http::header::CONTENT_TYPE, \"application/json\".to_string())],").unwrap();
    writeln!(out, "            json,").unwrap();
    writeln!(out, "        ).into_response(),").unwrap();
    writeln!(out, "        Err((status, body)) => {{").unwrap();
    writeln!(out, "            tracing::warn!(").unwrap();
    writeln!(out, "                grpc_path = %grpc_path,").unwrap();
    writeln!(out, "                request_id = %request_id,").unwrap();
    writeln!(out, "                status = %status,").unwrap();
    writeln!(out, "                \"backend dispatch error\"").unwrap();
    writeln!(out, "            );").unwrap();
    writeln!(out, "            (status, body).into_response()").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();
}

/// Emit a method check for a special-case route arm.
fn emit_method_check(out: &mut String, methods: &[String]) {
    writeln!(out, "            if ![{}].iter().any(|m| m.eq_ignore_ascii_case(req_method.as_str())) {{", methods.join(", ")).unwrap();
    writeln!(out, "                return (").unwrap();
    writeln!(out, "                    StatusCode::METHOD_NOT_ALLOWED,").unwrap();
    writeln!(out, "                    format!(\"{{{{\\\"error\\\":\\\"method {{}} not allowed for {{}}\\\"}}}}\", req_method, path),").unwrap();
    writeln!(out, "                ).into_response();").unwrap();
    writeln!(out, "            }}").unwrap();
}

/// Emit an auth check for a special-case route arm (only for Require policy).
fn emit_auth_check(out: &mut String, auth_policy: &str) {
    if auth_policy == "Require" {
        writeln!(out, "            if let Err(status) = state.auth.validate_rest(&path, auth_header_value.as_deref()) {{").unwrap();
        writeln!(out, "                tracing::warn!(path = %path, has_auth = auth_header_value.is_some(), error = %status.message(), \"gateway auth rejected\");").unwrap();
        writeln!(out, "                return (").unwrap();
        writeln!(out, "                    StatusCode::UNAUTHORIZED,").unwrap();
        writeln!(out, "                    format!(\"{{{{\\\"error\\\":\\\"{{}}\\\"}}}}\", status.message()),").unwrap();
        writeln!(out, "                ).into_response();").unwrap();
        writeln!(out, "            }}").unwrap();
    }
}

/// Resolve a proto type FQN to a Rust use statement.
/// e.g. "bigdata.QueryRequest" → "use gateway_tacplus::types::services::bigdata::QueryRequest;"
fn resolve_type_import(proto_fqn: &str, pkg_map: &HashMap<String, String>) -> Option<String> {
    if proto_fqn == "google.protobuf.Empty" {
        return None;
    }

    let dot = proto_fqn.find('.')?;
    let pkg = &proto_fqn[..dot];
    let type_name = &proto_fqn[dot + 1..];

    let full_path = pkg_map.get(pkg)?;
    let mod_path = full_path.replace('/', "::");

    Some(format!(
        "use gateway_tacplus::types::{}::{};",
        mod_path, type_name,
    ))
}

/// Resolve a proto type FQN to a `use` statement for the tacplus-generated `from_json` helper.
/// e.g. "tokenrequest.TokenMintRequest" → "use gateway_tacplus::types::common::tokenrequest::token_mint_request_from_json;"
fn resolve_from_json_import(proto_fqn: &str, pkg_map: &HashMap<String, String>) -> Option<String> {
    if proto_fqn == "google.protobuf.Empty" {
        return None;
    }

    let dot = proto_fqn.find('.')?;
    let pkg = &proto_fqn[..dot];
    let type_name = &proto_fqn[dot + 1..];

    let full_path = pkg_map.get(pkg)?;
    let mod_path = full_path.replace('/', "::");
    let fn_name = format!("{}_from_json", to_snake_case(type_name));

    Some(format!(
        "use gateway_tacplus::types::{}::{};",
        mod_path, fn_name,
    ))
}

/// Get the `from_json` function name for a proto type FQN.
/// e.g. "tokenrequest.TokenMintRequest" → "token_mint_request_from_json"
fn resolve_from_json_fn_name(proto_fqn: &str) -> String {
    let type_name = proto_fqn
        .rsplit('.')
        .next()
        .unwrap_or(proto_fqn);
    format!("{}_from_json", to_snake_case(type_name))
}

/// Convert a PascalCase name to snake_case.
/// e.g. "GetClusterInfo" → "get_cluster_info", "OAuthService" → "o_auth_service",
/// "X509Mint" → "x509_mint"
fn to_snake_case(name: &str) -> String {
    let mut result = String::new();
    let chars: Vec<char> = name.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if c.is_uppercase() {
            if i > 0 {
                let prev = chars[i - 1];
                let next_lower = i + 1 < chars.len() && chars[i + 1].is_lowercase();
                // Insert underscore when:
                // 1. Previous char is lowercase (camelCase boundary), OR
                // 2. Previous char is a digit (e.g. "X509Mint" → "x509_mint"), OR
                // 3. Previous char is uppercase AND next char is lowercase (acronym end: "OAuth" → "O_Auth")
                if prev.is_lowercase() || prev.is_ascii_digit() || (prev.is_uppercase() && next_lower) {
                    result.push('_');
                }
            }
            result.push(c.to_lowercase().next().unwrap());
        } else {
            result.push(c);
        }
    }
    result
}
