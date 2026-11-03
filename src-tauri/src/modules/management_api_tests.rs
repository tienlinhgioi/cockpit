use super::*;
use axum::http::HeaderValue;

fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (k, v) in pairs {
        map.insert(
            axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
            HeaderValue::from_str(v).unwrap(),
        );
    }
    map
}

fn sample_config() -> ManagementConfig {
    let mut config = ManagementConfig::default();
    config.enabled = true;
    config.read_token = StoredToken {
        sealed: String::new(),
        sha256: sha256_hex("read-token"),
        created_at: 0,
    };
    config.control_token = StoredToken {
        sealed: String::new(),
        sha256: sha256_hex("control-token"),
        created_at: 0,
    };
    config
}

#[test]
fn masks_emails() {
    assert_eq!(mask_email("alice@example.com"), "al***@example.com");
    assert_eq!(mask_email("a@example.com"), "a***@example.com");
    assert_eq!(mask_email("not-an-email"), "no***");
    assert_eq!(mask_email(""), "");
}

#[test]
fn redacts_credentials_from_free_text() {
    let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl";
    let samples = [
        format!("Authorization: Bearer abcdefghijklmnop1234"),
        format!("id_token={jwt}"),
        "upstream said api_key=sk-proj-AAAAAAAAAAAAAAAAAAAAAAAA invalid".to_string(),
        "{\"refresh_token\": \"rt_0123456789abcdef\"}".to_string(),
        "cookie=sessionKey123456".to_string(),
        "mgmt ckpt_c_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
    ];
    for sample in samples {
        let out = redact(&sample);
        assert!(out.contains("REDACTED"), "not redacted: {sample} -> {out}");
        for secret in [
            "abcdefghijklmnop1234",
            jwt,
            "sk-proj-AAAAAAAAAAAAAAAAAAAAAAAA",
            "rt_0123456789abcdef",
            "sessionKey123456",
            "ckpt_c_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert!(!out.contains(secret), "secret leaked in: {out}");
        }
    }
    // Ordinary diagnostics survive.
    assert_eq!(redact("HTTP 429 rate limited on model gpt-5"), "HTTP 429 rate limited on model gpt-5");
}

#[test]
fn clip_is_char_safe() {
    assert_eq!(clip("héllo wörld", 5), "héllo…");
    assert_eq!(clip("short", 10), "short");
}

#[test]
fn token_scope_resolution_uses_hashes() {
    let config = sample_config();
    assert_eq!(scope_for_token(&config, "read-token"), Some(Scope::Read));
    assert_eq!(scope_for_token(&config, "control-token"), Some(Scope::Control));
    assert_eq!(scope_for_token(&config, "other"), None);
    assert_eq!(scope_for_token(&config, ""), None);
}

#[test]
fn bearer_header_parsing() {
    assert_eq!(bearer_token(&headers(&[("authorization", "Bearer abc")])), Some("abc"));
    assert_eq!(bearer_token(&headers(&[("authorization", "bearer abc")])), Some("abc"));
    assert_eq!(bearer_token(&headers(&[("authorization", "Basic abc")])), None);
    assert_eq!(bearer_token(&headers(&[("authorization", "Bearer ")])), None);
    assert_eq!(bearer_token(&headers(&[])), None);
}

#[test]
fn host_and_origin_checks_block_dns_rebinding() {
    assert!(host_and_origin_allowed(&headers(&[("host", "127.0.0.1:17890")]), false));
    assert!(host_and_origin_allowed(&headers(&[("host", "localhost:17890")]), false));
    assert!(host_and_origin_allowed(&headers(&[("host", "[::1]:17890")]), false));
    assert!(host_and_origin_allowed(&headers(&[]), false));
    assert!(!host_and_origin_allowed(&headers(&[("host", "evil.example.com")]), false));
    assert!(!host_and_origin_allowed(
        &headers(&[("host", "127.0.0.1:17890"), ("origin", "https://evil.example.com")]),
        false
    ));
    assert!(host_and_origin_allowed(
        &headers(&[("host", "127.0.0.1:17890"), ("origin", "http://localhost:3000")]),
        false
    ));
    // LAN mode relies on the token alone.
    assert!(host_and_origin_allowed(&headers(&[("host", "192.168.1.5:17890")]), true));
}

#[test]
fn control_gate_requires_scope_and_unexpired_grant() {
    let mut config = sample_config();
    let now = 1_000_000;
    // Read token never passes.
    assert!(matches!(control_gate(Scope::Read, &config, now), Some(ToolOutcome::Denied(_))));
    // Control token without a grant is denied.
    assert!(matches!(control_gate(Scope::Control, &config, now), Some(ToolOutcome::Denied(_))));
    // Expired grant is denied.
    config.control_granted_until = Some(now - 1);
    assert!(matches!(control_gate(Scope::Control, &config, now), Some(ToolOutcome::Denied(_))));
    // Active grant passes.
    config.control_granted_until = Some(now + 60_000);
    assert!(control_gate(Scope::Control, &config, now).is_none());
}

#[test]
fn tool_catalogue_matches_requested_surface() {
    let names: Vec<&str> = tool_defs().iter().map(|d| d.name).collect();
    for expected in [
        "get_accounts",
        "get_quota",
        "get_usage_statistics",
        "get_gateway_status",
        "get_error_logs",
        "get_account_health",
        "switch_account",
        "configure_routing",
        "restart_gateway",
    ] {
        assert!(names.contains(&expected), "missing tool {expected}");
    }
    for def in tool_defs() {
        let mutating = matches!(def.name, "switch_account" | "configure_routing" | "restart_gateway");
        assert_eq!(def.scope == Scope::Control, mutating, "{}", def.name);
        assert_eq!((def.schema)()["type"], "object");
    }
    // Strategies that need extra user data or widen exposure are not remotely selectable.
    assert!(!ALLOWED_ROUTING_STRATEGIES.contains(&"custom"));
    assert!(!ALLOWED_ROUTING_STRATEGIES.contains(&"single_account"));
}

#[test]
fn allowed_strategies_parse_into_gateway_enum() {
    for strategy in ALLOWED_ROUTING_STRATEGIES {
        serde_json::from_value::<crate::models::codex_local_access::CodexLocalAccessRoutingStrategy>(
            json!(strategy),
        )
        .unwrap_or_else(|e| panic!("{strategy}: {e}"));
    }
}

fn input(id: &str, remaining: Option<f64>, failures: u32) -> HealthInput {
    HealthInput {
        platform: "codex".into(),
        account_id: id.into(),
        label: id.into(),
        available: Some(true),
        consecutive_failures: failures,
        cooldown_active: false,
        requires_reauth: false,
        min_remaining_percent: remaining,
    }
}

#[test]
fn recommendation_prefers_headroom_and_excludes_unusable() {
    let mut cooling = input("cooling", Some(99.0), 0);
    cooling.cooldown_active = true;
    let mut reauth = input("reauth", Some(99.0), 0);
    reauth.requires_reauth = true;
    let mut down = input("down", Some(99.0), 0);
    down.available = Some(false);
    let inputs = vec![
        input("low", Some(5.0), 0),
        input("high", Some(80.0), 0),
        input("flaky", Some(90.0), 3), // 90 - 45 = 45
        input("unknown", None, 0),     // neutral 50
        cooling,
        reauth,
        down,
    ];
    let ranked = recommend(&inputs);
    let order: Vec<&str> = ranked.iter().map(|r| r.account_id.as_str()).collect();
    assert_eq!(order, vec!["high", "unknown", "flaky", "low"]);
    assert!(ranked[0].reasons[0].contains("80%"));
}

#[test]
fn recommendation_handles_empty_input() {
    assert!(recommend(&[]).is_empty());
}

#[test]
fn failed_auth_attempts_lock_out_then_expire() {
    {
        let mut failures = auth_failures().lock().unwrap();
        failures.clear();
    }
    assert!(!auth_locked_out());
    for _ in 0..AUTH_FAIL_LIMIT {
        record_auth_failure();
    }
    assert!(auth_locked_out());
    {
        let mut failures = auth_failures().lock().unwrap();
        failures.clear();
    }
    assert!(!auth_locked_out());
}

#[test]
fn sealed_tokens_round_trip_on_non_android() {
    #[cfg(not(target_os = "android"))]
    {
        let sealed = seal("secret-value").unwrap();
        assert!(sealed.starts_with("plain:"));
        assert_eq!(unseal(&sealed).unwrap(), "secret-value");
    }
    assert!(unseal("garbage").is_err());
}

// ---------------------------------------------------------------------------------------
// End-to-end over real HTTP against the real server and the real (empty) test data dir.
// These exercise the actual axum router, auth, MCP framing and gating; they do not talk
// to any external AI service.
// ---------------------------------------------------------------------------------------

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn http() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

async fn rpc(client: &reqwest::Client, url: &str, token: &str, body: Value) -> Value {
    let response = client
        .post(url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success(), "status {}", response.status());
    response.json().await.unwrap()
}

#[tokio::test]
async fn management_server_end_to_end() {
    let port = free_port();
    {
        let mut failures = auth_failures().lock().unwrap();
        failures.clear();
    }
    let status = update_settings(ManagementSettingsUpdate {
        enabled: Some(true),
        port: Some(port),
        bind_lan: Some(false),
        reveal_email: Some(false),
    })
    .await
    .expect("start server");
    assert!(status.running);
    assert!(status.mcp_url.contains("127.0.0.1"));

    let read = reveal_token("read").unwrap();
    let control = reveal_token("control").unwrap();
    assert!(read.starts_with("ckpt_r_") && control.starts_with("ckpt_c_"));
    assert_ne!(read, control);

    let client = http();
    let base = format!("http://127.0.0.1:{port}");
    let mcp = format!("{base}/mcp");

    // Unauthenticated health probe leaks nothing but liveness.
    let health: Value = client.get(format!("{base}/healthz")).send().await.unwrap().json().await.unwrap();
    assert_eq!(health["status"], "ok");

    // No / wrong token.
    let response = client.post(&mcp).json(&json!({"jsonrpc":"2.0","id":1,"method":"ping"})).send().await.unwrap();
    assert_eq!(response.status(), 401);
    let response = client.post(&mcp).bearer_auth("nope").json(&json!({"jsonrpc":"2.0","id":1,"method":"ping"})).send().await.unwrap();
    assert_eq!(response.status(), 401);

    // Rebinding defence.
    let response = client
        .post(&mcp)
        .bearer_auth(&read)
        .header("Origin", "https://evil.example.com")
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"ping"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    let response = client
        .post(&mcp)
        .bearer_auth(&read)
        .header("Host", "evil.example.com")
        .json(&json!({"jsonrpc":"2.0","id":1,"method":"ping"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);

    // MCP handshake.
    let init = rpc(&client, &mcp, &read, json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0"}}})).await;
    assert_eq!(init["result"]["protocolVersion"], "2025-03-26");
    assert_eq!(init["result"]["serverInfo"]["name"], "cockpit-management");
    let response = client.post(&mcp).bearer_auth(&read).json(&json!({"jsonrpc":"2.0","method":"notifications/initialized"})).send().await.unwrap();
    assert_eq!(response.status(), 202);

    let list = rpc(&client, &mcp, &read, json!({"jsonrpc":"2.0","id":2,"method":"tools/list"})).await;
    assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 9);

    // Read tools work with the read token (data dir is empty in tests, so lists are empty).
    for name in ["get_accounts", "get_quota", "get_usage_statistics", "get_gateway_status", "get_error_logs", "get_account_health"] {
        let reply = rpc(&client, &mcp, &read, json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":name,"arguments":{}}})).await;
        assert_eq!(reply["result"]["isError"], false, "{name}: {reply}");
        let text = reply["result"]["content"][0]["text"].as_str().unwrap();
        for forbidden in ["access_token", "refresh_token", "id_token", "openai_api_key", &read, &control] {
            assert!(!text.contains(forbidden), "{name} leaked {forbidden}");
        }
    }

    // Mutating tools: read token is rejected.
    let reply = rpc(&client, &mcp, &read, json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"restart_gateway","arguments":{"confirm":true}}})).await;
    assert_eq!(reply["result"]["isError"], true);
    assert_eq!(reply["result"]["structuredContent"]["status"], "denied");

    // Control token but no user grant: still denied, even with confirm=true.
    set_control_grant(0).await.unwrap();
    let reply = rpc(&client, &mcp, &control, json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"configure_routing","arguments":{"strategy":"random","confirm":true}}})).await;
    assert_eq!(reply["result"]["structuredContent"]["status"], "denied");
    assert!(reply["result"]["structuredContent"]["reason"].as_str().unwrap().contains("not granted"));

    // With a grant: no confirm -> preview only; disallowed strategy -> denied.
    set_control_grant(5).await.unwrap();
    let reply = rpc(&client, &mcp, &control, json!({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"configure_routing","arguments":{"strategy":"random"}}})).await;
    assert_eq!(reply["result"]["structuredContent"]["status"], "confirmation_required");
    assert_eq!(reply["result"]["isError"], false);
    let reply = rpc(&client, &mcp, &control, json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"configure_routing","arguments":{"strategy":"custom","confirm":true}}})).await;
    assert_eq!(reply["result"]["structuredContent"]["status"], "denied");
    let reply = rpc(&client, &mcp, &control, json!({"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"restart_gateway","arguments":{}}})).await;
    assert_eq!(reply["result"]["structuredContent"]["status"], "confirmation_required");
    let reply = rpc(&client, &mcp, &control, json!({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"switch_account","arguments":{"platform":"codex","account_id":"does-not-exist","confirm":true}}})).await;
    assert_eq!(reply["result"]["isError"], true);

    // Unknown tool / method / malformed JSON.
    let reply = rpc(&client, &mcp, &read, json!({"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"drop_database","arguments":{}}})).await;
    assert_eq!(reply["result"]["isError"], true);
    let reply = rpc(&client, &mcp, &read, json!({"jsonrpc":"2.0","id":11,"method":"resources/list"})).await;
    assert_eq!(reply["error"]["code"], -32601);

    // REST mirror.
    let response = client.post(format!("{base}/api/v1/tools/get_gateway_status")).bearer_auth(&read).send().await.unwrap();
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    assert!(body["gateway"].is_object());
    let response = client.post(format!("{base}/api/v1/tools/restart_gateway")).bearer_auth(&read).json(&json!({"confirm":true})).send().await.unwrap();
    assert_eq!(response.status(), 422);

    // Audit trail records calls and never contains tokens.
    let audit_json = serde_json::to_string(&audit_entries()).unwrap();
    assert!(audit_json.contains("restart_gateway"));
    assert!(!audit_json.contains(&read) && !audit_json.contains(&control));

    // Rotating a token invalidates the old one immediately.
    let new_read = rotate_token("read").unwrap();
    assert_ne!(new_read, read);
    let response = client.post(&mcp).bearer_auth(&read).json(&json!({"jsonrpc":"2.0","id":1,"method":"ping"})).send().await.unwrap();
    assert_eq!(response.status(), 401);
    let reply = rpc(&client, &mcp, &new_read, json!({"jsonrpc":"2.0","id":1,"method":"ping"})).await;
    assert!(reply["result"].is_object());

    // Disabling stops the listener.
    update_settings(ManagementSettingsUpdate { enabled: Some(false), ..Default::default() }).await.unwrap();
    assert!(client.get(format!("{base}/healthz")).send().await.is_err());
    {
        let mut failures = auth_failures().lock().unwrap();
        failures.clear();
    }
}
