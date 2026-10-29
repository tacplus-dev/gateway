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

/// The set of proto packages `registry.json` marks `(spec.service).tenant_owned`.
///
/// This is the ONLY answer to "is this service tenant-owned" — there is no
/// gateway-side allowlist, matching the operator (item 4 §2.2), which reads the
/// same tacplus-emitted flag off the same file.
///
/// Keyed by `ServiceInfo.package`, not by the registry node name: the node name
/// is what the operator deploys under, while `RouteInfo.service_id` — the value
/// the whole routing path uses — is the proto package, and the two differ today
/// for `saml` (package `samlsvc`).
pub fn tenant_owned_services() -> std::collections::HashSet<String> {
    parse_tenant_owned(REGISTRY_JSON)
}

/// The registry walk behind `tenant_owned_services`, split out so it can be run
/// against a fixture registry as well as the embedded one.
fn parse_tenant_owned(registry_json: &str) -> std::collections::HashSet<String> {
    let root: serde_json::Value = match serde_json::from_str(registry_json) {
        Ok(v) => v,
        Err(e) => {
            // The embedded registry is generated and validated at build time, so
            // this cannot happen for the real input; a fixture typo must not be
            // silently read as "no service is tenant-owned".
            tracing::error!(error = %e, "registry.json did not parse; no service treated as tenant-owned");
            return Default::default();
        }
    };

    let mut out = std::collections::HashSet::new();
    collect_tenant_owned(&root, &mut out);
    out
}

/// Walks the registry's `children` tree, collecting the package of every
/// `services[]` entry carrying `tenant_owned: true`. "Any entry" is deliberate:
/// the annotation is file-level in the proto, so tacplus stamps it onto every
/// `ServiceInfo` the package produces (item 4 §2.2).
fn collect_tenant_owned(node: &serde_json::Value, out: &mut std::collections::HashSet<String>) {
    if let Some(services) = node.get("services").and_then(|s| s.as_array()) {
        for svc in services {
            if svc.get("tenant_owned").and_then(|t| t.as_bool()) == Some(true) {
                if let Some(pkg) = svc.get("package").and_then(|p| p.as_str()) {
                    out.insert(pkg.to_string());
                }
            }
        }
    }
    if let Some(children) = node.get("children").and_then(|c| c.as_array()) {
        for child in children {
            collect_tenant_owned(child, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape tacplus emits: a `children` tree whose `services[]` entries are
    /// `ServiceInfo`s. `docmanager` declares the annotation, `tasks` does not,
    /// and `saml` shows why the key is the PACKAGE and not the node name.
    const FIXTURE: &str = r#"{
      "name": "root",
      "children": [
        {
          "name": "types",
          "children": [
            {
              "name": "services",
              "children": [
                {
                  "name": "docmanager",
                  "services": [
                    {"name": "DocManager", "package": "docmanager", "tenant_owned": true},
                    {"name": "DocManagerStateService", "package": "docmanager", "tenant_owned": true}
                  ]
                },
                {
                  "name": "tasks",
                  "services": [{"name": "Tasks", "package": "tasks"}]
                },
                {
                  "name": "saml",
                  "services": [{"name": "Saml", "package": "samlsvc", "tenant_owned": true}]
                }
              ]
            }
          ]
        }
      ]
    }"#;

    #[test]
    fn tenant_owned_is_read_off_the_annotation_and_keyed_by_package() {
        let owned = parse_tenant_owned(FIXTURE);

        assert!(
            owned.contains("docmanager"),
            "a service declaring tenant_owned must be found: {owned:?}"
        );
        assert!(
            !owned.contains("tasks"),
            "proto3 omits a false bool entirely; absence must read as not tenant-owned"
        );
        assert!(
            owned.contains("samlsvc"),
            "the key must be ServiceInfo.package, which is what RouteInfo.service_id holds"
        );
        assert!(
            !owned.contains("saml"),
            "the registry NODE name is the operator's key, not the gateway's"
        );
        assert_eq!(owned.len(), 2, "no other service may be marked: {owned:?}");
    }

    /// The live registry's tenant-owned set is exactly the services that declare
    /// the annotation: tenantecho (the two-tenant routing proof), doppelganger
    /// (one instance per tenant, shared by its users) and stratum (one instance
    /// per tenant, tacplus-dev/roadmap decisions/stratum-per-tenant-2026-10-25.md,
    /// stratum#2), and nothing else. A new
    /// entry here is a new live tenant-owned route and is meant to be noticed
    /// (decision-goalA-item5 Open question 1 is live now).
    #[test]
    fn the_embedded_registry_marks_exactly_the_declared_tenant_owned_services() {
        let owned = tenant_owned_services();
        assert_eq!(
            owned,
            std::collections::HashSet::from([
                "tenantecho".to_string(),
                "doppelganger".to_string(),
                "stratum".to_string(),
            ]),
            "the fleet's tenant-owned services: {owned:?}"
        );
    }

    /// A registry that does not parse must fail closed: treating it as "nothing
    /// is tenant-owned" keeps shared routing working, which is the safe half.
    #[test]
    fn an_unparseable_registry_marks_nothing() {
        assert!(parse_tenant_owned("{not json").is_empty());
    }
}
