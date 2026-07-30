#![cfg(feature = "m0-test-profile")]
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]

use secure_onboard::m0_fixture_manifest::validate_fixture_manifest;
use std::fs;
use std::path::Path;

const MANIFESTS: [&str; 2] = [
    "tests/fixtures/m0/manifests/claude-2.1.220-macos-arm64.json",
    "tests/fixtures/m0/manifests/codex-0.146.0-macos-arm64.json",
];

#[test]
#[ignore = "requires the exact pinned local Claude and Codex executables"]
fn checked_manifests_bind_the_current_host_clients_and_product_artifacts() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixture_root = root.join("tests/fixtures/m0");

    for relative in MANIFESTS {
        let bytes = fs::read(root.join(relative)).expect("read checked manifest");
        validate_fixture_manifest(&bytes, &fixture_root).expect("validate checked manifest");
    }
}
