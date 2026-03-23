/// Embedded registry.json from tacplus generation.
const REGISTRY_JSON: &str = include_str!("../target/generated-sources/tacplus/registry.json");

/// Embedded registry schema.
const REGISTRY_SCHEMA_JSON: &str =
    include_str!("../target/generated-sources/tacplus/registry.schema.json");

/// Embedded AGENT.md.
const AGENT_MD: &str = include_str!("../target/generated-sources/tacplus/AGENT.md");

/// Registry provides access to embedded registry files for serving via REST.
/// Route table and auth policies are generated at compile time in rest_dispatch.rs.
pub struct Registry;

impl Registry {
    /// Log the compile-time route table size.
    pub fn load() -> Self {
        tracing::info!(
            rest_routes = crate::rest_dispatch::ROUTES.len(),
            no_auth_packages = crate::rest_dispatch::NO_AUTH_PACKAGES.len(),
            "registry loaded (compile-time route table)"
        );
        Self
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
