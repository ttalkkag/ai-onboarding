use secure_onboard::strict_json::from_slice;
use serde_json::Value;
use std::fs;
use std::path::Path;

fn parse(path: &str) -> Value {
    from_slice(&fs::read(path).expect("read manifest")).expect("strict JSON")
}

#[test]
fn both_test_plugins_have_versioned_manifests_and_explicit_hook_timeouts() {
    for (manifest, hooks, expected_name) in [
        (
            "plugins/claude-m0/.claude-plugin/plugin.json",
            "plugins/claude-m0/hooks/hooks.json",
            "secure-onboard-m0-claude",
        ),
        (
            "plugins/codex-m0/.codex-plugin/plugin.json",
            "plugins/codex-m0/hooks/hooks.json",
            "secure-onboard-m0-codex",
        ),
    ] {
        let manifest = parse(manifest);
        assert_eq!(manifest["name"], expected_name);
        assert_eq!(manifest["version"], "0.1.0");
        let hooks = parse(hooks);
        let events = hooks["hooks"].as_object().expect("hook events");
        assert!(events.contains_key("UserPromptSubmit"));
        assert!(events.contains_key("PreToolUse"));
        assert!(events.contains_key("PostToolUse"));
        assert!(events.contains_key("Stop"));
        for groups in events.values() {
            for group in groups.as_array().expect("hook groups") {
                for hook in group["hooks"].as_array().expect("command hooks") {
                    assert_eq!(hook["type"], "command");
                    assert_eq!(hook["timeout"], 5);
                    assert_ne!(hook["command"], "");
                    assert!(hook.get("async").is_none());
                }
            }
        }
    }
}

#[test]
fn plugin_hook_paths_are_inside_the_bundle_and_test_profiles_are_not_project_owned() {
    assert!(Path::new("plugins/claude-m0/hooks/hooks.json").is_file());
    assert!(Path::new("plugins/codex-m0/hooks/hooks.json").is_file());
    let claude = fs::read_to_string("plugins/claude-m0/hooks/hooks.json").unwrap();
    let codex = fs::read_to_string("plugins/codex-m0/hooks/hooks.json").unwrap();
    for hooks in [claude, codex] {
        for placeholder in [
            "__SECURE_ONBOARD_M0_TRUSTED_ROOT__",
            "__SECURE_ONBOARD_M0_TARGET_ROOT__",
            "__SECURE_ONBOARD_M0_STATE_ROOT__",
            "__SECURE_ONBOARD_M0_EVIDENCE_ROOT__",
        ] {
            assert!(hooks.contains(placeholder));
        }
        assert!(!hooks.contains("/private/tmp/secure-onboard-m0-v1"));
        assert!(!hooks.contains("\"--core\""));
        assert!(!hooks.contains(" --core "));
        assert!(!hooks.contains("${CLAUDE_PROJECT_DIR}/"));
        assert!(!hooks.contains(" 600"));
    }
}
