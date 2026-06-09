/// Embedded registry.json from tacplus generation.
const REGISTRY_JSON: &str = include_str!("../target/generated-sources/model/registry.json");

/// Embedded registry schema.
const REGISTRY_SCHEMA_JSON: &str =
    include_str!("../target/generated-sources/model/registry.schema.json");

/// Embedded AGENT.md.
const AGENT_MD: &str = include_str!("../target/generated-sources/model/AGENT.md");

/// Registry provides access to embedded registry files for serving via REST.
/// Route table and auth policies are generated at compile time in rest_dispatch.rs.
pub struct Registry;

impl Registry {
    /// Log the compile-time route table size.
    pub fn load() -> Self {
        tracing::info!(
            rest_routes = gateway_model::s2sm::rest_dispatch::ROUTES.len(),
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
