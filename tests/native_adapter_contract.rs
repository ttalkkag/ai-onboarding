#![cfg(feature = "m0-test-profile")]

use secure_onboard::contracts::{
    CwdAssurance, CwdResolutionSource, HookEnvelope, HookEvent, ToolOutcome,
};
use secure_onboard::m0::Client;
use secure_onboard::native::{
    CwdBinding, NativeMapContext, NativeMapError, PreResponse, SourceAssurance,
    encode_pre_response, map_claude_native, map_claude_prompt, map_codex_native, map_codex_prompt,
};

fn context(cwd_binding: CwdBinding) -> NativeMapContext {
    NativeMapContext {
        envelope_id: "envelope-fixture".into(),
        occurred_at: "2026-07-22T00:00:00Z".into(),
        cwd_binding,
    }
}

#[test]
fn claude_exact_native_lifecycle_maps_to_tagged_envelopes() {
    let pre = map_claude_native(
        include_bytes!("fixtures/m0/native/claude-2.1.220-macos-arm64-pre.json"),
        &context(CwdBinding::VerifiedSimpleInvocation),
    )
    .expect("Claude PreToolUse fixture");
    assert_eq!(pre.hook_event(), HookEvent::PreToolUse);
    match pre {
        HookEnvelope::PreToolUse {
            client,
            adapter_turn_id,
            prompt_context_id,
            physical_cwd,
            cwd_assurance,
            cwd_resolution_source,
            tool_name,
            ..
        } => {
            assert_eq!(client, Client::Claude);
            assert_eq!(adapter_turn_id, None);
            assert_eq!(prompt_context_id, None);
            assert_eq!(physical_cwd.as_deref(), Some("/private/tmp"));
            assert_eq!(cwd_assurance, CwdAssurance::Verified);
            assert_eq!(
                cwd_resolution_source,
                CwdResolutionSource::M0EffectiveCwdBinding
            );
            assert_eq!(tool_name, "shell_exec");
        }
        _ => panic!("wrong event"),
    }

    let result = map_claude_native(
        include_bytes!("fixtures/m0/native/claude-2.1.220-macos-arm64-post-success.json"),
        &context(CwdBinding::VerifiedSimpleInvocation),
    )
    .expect("Claude PostToolUse fixture");
    match result {
        HookEnvelope::ToolResult {
            outcome,
            exit_code,
            native_tool_call_id,
            ..
        } => {
            assert_eq!(outcome, ToolOutcome::Success);
            assert_eq!(exit_code, None);
            assert_eq!(native_tool_call_id, "toolu_mock_bash");
        }
        _ => panic!("wrong event"),
    }

    let failure = map_claude_native(
        include_bytes!("fixtures/m0/native/claude-2.1.220-macos-arm64-post-failure.json"),
        &context(CwdBinding::VerifiedSimpleInvocation),
    )
    .expect("Claude PostToolUseFailure fixture");
    assert!(matches!(
        failure,
        HookEnvelope::ToolResult {
            outcome: ToolOutcome::Failure,
            exit_code: None,
            ..
        }
    ));

    let stop = map_claude_native(
        include_bytes!("fixtures/m0/native/claude-2.1.220-macos-arm64-stop.json"),
        &context(CwdBinding::VerifiedSimpleInvocation),
    )
    .expect("Claude Stop fixture");
    assert!(matches!(
        stop,
        HookEnvelope::AssistantStop {
            last_assistant_message: Some(ref message),
            ..
        } if message == "Local hook test complete."
    ));
}

#[test]
fn native_prompt_payloads_are_strictly_mapped_without_claiming_human_provenance() {
    let claude = map_claude_prompt(include_bytes!(
        "fixtures/m0/native/claude-2.1.220-macos-arm64-prompt.json"
    ))
    .expect("Claude prompt fixture");
    assert_eq!(claude.source_assurance, SourceAssurance::Unverified);
    assert_eq!(claude.adapter_turn_id, None);
    assert_eq!(
        claude.native_prompt_id.as_deref(),
        Some("b2439dee-46c1-421d-88b2-d65263ec5d55")
    );
    assert_eq!(claude.prompt, "SECURE_ONBOARD_HUMAN_PROMPT\n");

    let codex = map_codex_prompt(include_bytes!(
        "fixtures/m0/native/codex-0.146.0-macos-arm64-prompt.json"
    ))
    .expect("Codex prompt fixture");
    assert_eq!(codex.source_assurance, SourceAssurance::Unverified);
    assert_eq!(
        codex.adapter_turn_id.as_deref(),
        Some("019fade6-ec95-7071-800d-9af126a69c8a")
    );
    assert_eq!(codex.native_prompt_id, None);
    assert_eq!(codex.prompt, "SECURE_ONBOARD_HUMAN_PROMPT");
}

#[test]
fn codex_turn_is_preserved_but_hidden_workdir_forces_unverified_cwd() {
    let pre = map_codex_native(
        include_bytes!("fixtures/m0/native/codex-0.146.0-macos-arm64-pre.json"),
        &context(CwdBinding::UnsupportedPerCallWorkdir),
    )
    .expect("Codex PreToolUse fixture");
    match pre {
        HookEnvelope::PreToolUse {
            adapter_turn_id,
            native_session_cwd,
            physical_cwd,
            cwd_assurance,
            cwd_resolution_source,
            ..
        } => {
            assert_eq!(
                adapter_turn_id.as_deref(),
                Some("019fade8-bb36-7e73-8931-d40ad8194097")
            );
            assert_eq!(
                native_session_cwd,
                "/var/folders/ng/pwjn4kt530j3hxk34qbh5hy80000gn/T/secure-onboard-codex-m0-live.H47xIc/project"
            );
            assert_eq!(physical_cwd, None);
            assert_eq!(cwd_assurance, CwdAssurance::Unverified);
            assert_eq!(cwd_resolution_source, CwdResolutionSource::Unavailable);
        }
        _ => panic!("wrong event"),
    }
}

#[test]
fn codex_ambiguous_results_are_rejected_instead_of_inventing_success() {
    for fixture in [
        include_bytes!("fixtures/m0/native/codex-0.146.0-macos-arm64-post-success.json").as_slice(),
        include_bytes!("fixtures/m0/native/codex-0.146.0-macos-arm64-post-failure.json").as_slice(),
    ] {
        let result = map_codex_native(fixture, &context(CwdBinding::UnsupportedPerCallWorkdir));
        assert!(matches!(
            &result,
            Err(NativeMapError::UnverifiedCodexResult)
        ));
    }

    let stop = map_codex_native(
        include_bytes!("fixtures/m0/native/codex-0.146.0-macos-arm64-stop.json"),
        &context(CwdBinding::UnsupportedPerCallWorkdir),
    )
    .expect("Codex Stop fixture");
    assert!(matches!(
        stop,
        HookEnvelope::AssistantStop {
            native_tool_call_id: None,
            last_assistant_message: Some(ref message),
            ..
        } if message == "M0 probe complete"
    ));
}

#[test]
fn exact_version_mapper_rejects_unknown_native_fields_and_events() {
    let with_unknown = br#"{"session_id":"s","transcript_path":null,"cwd":"/tmp","prompt_id":"p","permission_mode":"dontAsk","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"printf ok"},"tool_use_id":"t","new_native_field":true}"#;
    assert!(matches!(
        map_claude_native(with_unknown, &context(CwdBinding::VerifiedSimpleInvocation)),
        Err(NativeMapError::Schema(_))
    ));

    let unsupported = br#"{"hook_event_name":"UserPromptSubmit"}"#;
    assert!(matches!(
        map_codex_native(unsupported, &context(CwdBinding::UnsupportedPerCallWorkdir)),
        Err(NativeMapError::UnsupportedEvent)
    ));

    let execution_changing_tool_input = br#"{"session_id":"s","transcript_path":null,"cwd":"/tmp","turn_id":"turn","hook_event_name":"PreToolUse","model":"gpt","permission_mode":"never","tool_name":"Bash","tool_input":{"command":"printf ok","workdir":"/different"},"tool_use_id":"t"}"#;
    assert!(matches!(
        map_codex_native(
            execution_changing_tool_input,
            &context(CwdBinding::UnsupportedPerCallWorkdir)
        ),
        Err(NativeMapError::Schema(_))
    ));
}

#[test]
fn verified_simple_cwd_must_reobserve_an_existing_physical_directory() {
    let missing = br#"{"session_id":"s","transcript_path":"/tmp/t.jsonl","cwd":"/path/that/does/not/exist","prompt_id":"p","permission_mode":"default","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"printf ok"},"tool_use_id":"t"}"#;

    assert!(matches!(
        map_claude_native(missing, &context(CwdBinding::VerifiedSimpleInvocation)),
        Err(NativeMapError::Schema(_))
    ));
}

#[test]
fn claude_2_1_220_accepts_only_the_observed_optional_effort_shape() {
    let observed = br#"{"session_id":"s","transcript_path":"/tmp/t.jsonl","cwd":"/tmp","prompt_id":"p","permission_mode":"bypassPermissions","effort":{"level":"high"},"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"printf ok"},"tool_use_id":"t"}"#;
    map_claude_native(observed, &context(CwdBinding::VerifiedSimpleInvocation))
        .expect("observed Claude effort field");

    for invalid in [
        br#"{"session_id":"s","transcript_path":"/tmp/t.jsonl","cwd":"/tmp","prompt_id":"p","permission_mode":"bypassPermissions","effort":{"level":"extreme"},"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"printf ok"},"tool_use_id":"t"}"#
            .as_slice(),
        br#"{"session_id":"s","transcript_path":"/tmp/t.jsonl","cwd":"/tmp","prompt_id":"p","permission_mode":"bypassPermissions","effort":{"level":"high","extra":true},"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"printf ok"},"tool_use_id":"t"}"#
            .as_slice(),
    ] {
        assert!(matches!(
            map_claude_native(invalid, &context(CwdBinding::VerifiedSimpleInvocation)),
            Err(NativeMapError::Schema(_))
        ));
    }
}

#[test]
fn native_responses_never_auto_approve_and_have_exact_bytes() {
    for client in [Client::Claude, Client::Codex] {
        let high = encode_pre_response(
            client,
            &PreResponse::High {
                system_message: "Secure Onboard M0 HIGH".into(),
                reason: "M0 sentinel blocked".into(),
            },
        )
        .expect("high response");
        assert_eq!(
            high,
            b"{\"systemMessage\":\"Secure Onboard M0 HIGH\",\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"M0 sentinel blocked\"}}\n"
        );

        let low = encode_pre_response(
            client,
            &PreResponse::Low {
                system_message: "Secure Onboard M0 LOW".into(),
            },
        )
        .expect("low response");
        assert_eq!(low, b"{\"systemMessage\":\"Secure Onboard M0 LOW\"}\n");

        let info = encode_pre_response(client, &PreResponse::Info).expect("neutral info response");
        assert_eq!(info, b"{}\n");
        for output in [&high, &low, &info] {
            let text = std::str::from_utf8(output).unwrap();
            assert!(!text.contains("\"permissionDecision\":\"allow\""));
            assert!(!text.contains("\"permissionDecision\":\"ask\""));
            assert!(!text.contains("\"continue\":false"));
        }
    }
}
