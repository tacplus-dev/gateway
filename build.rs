// build.rs — generates REST→gRPC dispatch from tacplus/registry.json.
//
// Uses the shared rest-dispatch-gen utility crate.

use std::env;
use std::path::PathBuf;

fn main() {
    rest_dispatch_gen::generate(&rest_dispatch_gen::Config {
        registry_json_path: "target/generated-sources/tacplus/registry.json".into(),
        crate_prefix: "gateway_tacplus".into(),
        output_path: PathBuf::from(env::var("OUT_DIR").unwrap()).join("rest_dispatch.rs"),
        app_state_path: "crate::rest::AppState".into(),
        mint_handling: rest_dispatch_gen::MintHandling::Gateway,
    });
}
