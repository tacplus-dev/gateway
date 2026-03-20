use std::collections::{HashMap, HashSet};

/// Embedded registry.json from tacplus generation.
const REGISTRY_JSON: &str = include_str!("../tacplus/registry.json");

/// Embedded registry schema.
const REGISTRY_SCHEMA_JSON: &str = include_str!("../tacplus/registry.schema.json");

/// Embedded AGENT.md.
const AGENT_MD: &str = include_str!("../tacplus/AGENT.md");

/// A single REST route entry derived from registry.json.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct RouteEntry {
    /// Service ID for backend resolution (e.g. "identity", "sentinel").
    pub service_id: String,
    /// Full gRPC method path (e.g. "/identity.IdentityService/ListProviders").
    pub grpc_path: String,
    /// Allowed HTTP methods (POST is always included).
    pub http_methods: Vec<String>,
    /// Whether this RPC skips authentication.
    pub no_auth: bool,
}

impl RouteEntry {
    /// Check whether a given HTTP method is allowed for this route.
    pub fn allows_method(&self, method: &str) -> bool {
        self.http_methods.iter().any(|m| m.eq_ignore_ascii_case(method))
    }
}

/// Registry holds parsed routing metadata from tacplus/registry.json.
pub struct Registry {
    /// REST route table: http_path → RouteEntry.
    pub routes: HashMap<String, RouteEntry>,
    /// Set of gRPC package names where all RPCs skip authentication.
    pub no_auth_packages: HashSet<String>,
}

impl Registry {
    /// Parses the embedded registry.json at startup, building the route table.
    pub fn load() -> Self {
        let data: serde_json::Value =
            serde_json::from_str(REGISTRY_JSON).expect("invalid registry.json");

        let mut routes = HashMap::new();
        let mut no_auth_packages = HashSet::new();

        walk_node(&data, &mut routes, &mut no_auth_packages);

        tracing::info!(
            rest_routes = routes.len(),
            no_auth_packages = no_auth_packages.len(),
            "registry loaded"
        );

        for (path, entry) in &routes {
            tracing::debug!(
                path = %path,
                methods = ?entry.http_methods,
                service = %entry.service_id,
                no_auth = entry.no_auth,
                "route registered"
            );
        }

        Self {
            routes,
            no_auth_packages,
        }
    }

    /// Look up a REST route by its HTTP path.
    pub fn lookup(&self, http_path: &str) -> Option<&RouteEntry> {
        self.routes.get(http_path)
    }

    /// Check whether a gRPC method path targets a no-auth package.
    pub fn is_grpc_no_auth(&self, grpc_method: &str) -> bool {
        if grpc_method.starts_with('/') {
            let trimmed = &grpc_method[1..];
            if let Some(dot_idx) = trimmed.find('.') {
                let pkg = &trimmed[..dot_idx];
                return self.no_auth_packages.contains(pkg);
            }
        }
        false
    }

    /// Returns the raw registry.json bytes.
    pub fn registry_json() -> &'static str {
        REGISTRY_JSON
    }

    /// Returns the raw registry.schema.json bytes.
    pub fn registry_schema_json() -> &'static str {
        REGISTRY_SCHEMA_JSON
    }

    /// Returns the raw AGENT.md bytes.
    pub fn agent_md() -> &'static str {
        AGENT_MD
    }
}

fn walk_node(
    node: &serde_json::Value,
    routes: &mut HashMap<String, RouteEntry>,
    no_auth_packages: &mut HashSet<String>,
) {
    let full_path = node.get("full_path").and_then(|v| v.as_str()).unwrap_or("");

    if let Some(services) = node.get("services").and_then(|v| v.as_array()) {
        for svc in services {
            let grpc_service = svc
                .get("grpc_service")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            // Skip state services, view services, and internal services
            if grpc_service.contains("StateService")
                || grpc_service.contains("ViewService")
                || grpc_service.contains("LockService")
                || grpc_service.contains("ClusterService")
            {
                continue;
            }

            // Derive service_id from tree path: "services/identity" → "identity"
            let service_id = if full_path.starts_with("services/") {
                full_path
                    .strip_prefix("services/")
                    .unwrap_or(full_path)
                    .to_string()
            } else {
                continue; // Skip non-service packages (libs/, etc.)
            };

            // Track no-auth packages for gRPC passthrough
            let rpcs = svc.get("rpcs").and_then(|v| v.as_array());
            if let Some(rpcs) = rpcs {
                let all_no_auth = !rpcs.is_empty()
                    && rpcs
                        .iter()
                        .all(|rpc| rpc.get("disable_auth").and_then(|v| v.as_bool()).unwrap_or(false));

                if all_no_auth {
                    if let Some(pkg) = grpc_service.split('.').next() {
                        no_auth_packages.insert(pkg.to_string());
                    }
                }

                // Build REST route entries from each RPC
                for rpc in rpcs {
                    let http_path = rpc
                        .get("http_path")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let grpc_path = rpc
                        .get("grpc_path")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let no_auth = rpc
                        .get("disable_auth")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    // Parse http_methods array
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

                    let entry = RouteEntry {
                        service_id: service_id.clone(),
                        grpc_path: grpc_path.to_string(),
                        http_methods: http_methods.clone(),
                        no_auth,
                    };

                    // Register convention path
                    routes.insert(http_path.to_string(), entry.clone());

                    // Register alias path (if present)
                    let alias_path = rpc
                        .get("http_alias_path")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    if !alias_path.is_empty() {
                        routes.insert(alias_path.to_string(), entry);
                    }
                }
            }
        }
    }

    // Recurse into children
    if let Some(children) = node.get("children").and_then(|v| v.as_array()) {
        for child in children {
            walk_node(child, routes, no_auth_packages);
        }
    }
}
