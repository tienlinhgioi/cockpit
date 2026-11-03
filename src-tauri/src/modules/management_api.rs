//! Management API + MCP server.
//!
//! A small authenticated HTTP service that lets an *operator tool* (Claude Code, curl,
//! a script) inspect and — with explicit, time-limited permission — adjust Cockpit.
//!
//! Security model
//! * Disabled by default. Listens on `127.0.0.1` only unless the user opts into LAN.
//! * Two bearer tokens: `read` (inspection only) and `control` (may also call mutating
//!   tools). Tokens are sealed at rest (Android Keystore on Android) and only the SHA-256
//!   is used for verification. They are never written to logs.
//! * Mutating tools additionally require (1) the control token, (2) a *control grant* the
//!   user switched on in the app (expires automatically) and (3) `confirm: true` in the
//!   call. Without `confirm` the tool returns a dry-run preview and changes nothing.
//! * No tool returns OAuth tokens, API keys, cookies or passwords. Emails are masked
//!   unless the user enables `revealEmail`. Free text is passed through [`redact`].
//! * `Host` / `Origin` headers are validated on loopback binds (DNS-rebinding defence).
//!
//! Transports: MCP "streamable HTTP" (`POST /mcp`, JSON responses) and a plain REST
//! mirror (`POST /api/v1/tools/{name}`).

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path as AxPath, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const DEFAULT_PORT: u16 = 17890;
const CONFIG_FILE: &str = "management_api.json";
const MAX_BODY_BYTES: usize = 256 * 1024;
const AUDIT_CAPACITY: usize = 200;
const MAX_GRANT_MINUTES: u32 = 240;
const AUTH_FAIL_LIMIT: usize = 10;
const AUTH_FAIL_WINDOW: Duration = Duration::from_secs(60);
const SUPPORTED_PROTOCOLS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

/// Routing strategies Claude (or any operator) may select. `single_account` and `custom`
/// need extra user-supplied data, so they stay UI-only.
pub const ALLOWED_ROUTING_STRATEGIES: [&str; 7] = [
    "auto",
    "random",
    "quota_high_first",
    "quota_low_first",
    "plan_high_first",
    "plan_low_first",
    "expiry_soon_first",
];

// ---------------------------------------------------------------------------------------
// Scopes, config, token storage
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Read,
    Control,
}

impl Scope {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "read" => Ok(Scope::Read),
            "control" => Ok(Scope::Control),
            other => Err(format!("unknown scope: {other}")),
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Read => "read",
            Scope::Control => "control",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct StoredToken {
    /// Sealed token (see [`seal`]). Needed so the user can re-display it in the app.
    sealed: String,
    /// Hex SHA-256 of the token; the only thing used to authenticate requests.
    sha256: String,
    created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManagementConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default = "default_port")]
    port: u16,
    /// Bind 0.0.0.0 instead of 127.0.0.1. Off by default; the UI warns before enabling.
    #[serde(default)]
    bind_lan: bool,
    #[serde(default)]
    reveal_email: bool,
    /// Epoch ms until which mutating tools are permitted. `None` / past = read-only.
    #[serde(default)]
    control_granted_until: Option<i64>,
    #[serde(default)]
    read_token: StoredToken,
    #[serde(default)]
    control_token: StoredToken,
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

impl Default for ManagementConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            port: DEFAULT_PORT,
            bind_lan: false,
            reveal_email: false,
            control_granted_until: None,
            read_token: StoredToken::default(),
            control_token: StoredToken::default(),
        }
    }
}

fn config_path() -> Result<PathBuf, String> {
    Ok(crate::modules::account::get_data_dir()?.join(CONFIG_FILE))
}

fn config_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Seal a secret for storage. Android: wrapped by the non-exportable Keystore key and fails
/// closed. Other platforms: stored as-is in a 0600 file (the desktop app already keeps its
/// own credentials in user-private files).
fn seal(plain: &str) -> Result<String, String> {
    #[cfg(target_os = "android")]
    {
        let blob = crate::modules::android_platform::keystore_encrypt(plain.as_bytes())?;
        Ok(format!("ks1:{}", general_purpose::STANDARD.encode(blob)))
    }
    #[cfg(not(target_os = "android"))]
    {
        Ok(format!("plain:{plain}"))
    }
}

fn unseal(sealed: &str) -> Result<String, String> {
    if let Some(rest) = sealed.strip_prefix("ks1:") {
        let blob = general_purpose::STANDARD
            .decode(rest)
            .map_err(|e| format!("invalid sealed token: {e}"))?;
        let plain = crate::modules::android_platform::keystore_decrypt(&blob)?;
        return String::from_utf8(plain).map_err(|e| e.to_string());
    }
    if let Some(rest) = sealed.strip_prefix("plain:") {
        return Ok(rest.to_string());
    }
    Err("unrecognised sealed token format".to_string())
}

fn sha256_hex(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn generate_token(scope: Scope) -> Result<(String, StoredToken), String> {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let prefix = match scope {
        Scope::Read => "ckpt_r_",
        Scope::Control => "ckpt_c_",
    };
    let token = format!(
        "{prefix}{}",
        general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    );
    let stored = StoredToken {
        sealed: seal(&token)?,
        sha256: sha256_hex(&token),
        created_at: now_ms(),
    };
    Ok((token, stored))
}

fn load_config_locked() -> Result<ManagementConfig, String> {
    let path = config_path()?;
    let mut config: ManagementConfig = match std::fs::read_to_string(&path) {
        Ok(raw) => serde_json::from_str(&raw).map_err(|e| format!("management config: {e}"))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => ManagementConfig::default(),
        Err(error) => return Err(format!("management config: {error}")),
    };
    let mut changed = false;
    if config.read_token.sha256.is_empty() {
        config.read_token = generate_token(Scope::Read)?.1;
        changed = true;
    }
    if config.control_token.sha256.is_empty() {
        config.control_token = generate_token(Scope::Control)?.1;
        changed = true;
    }
    if config.port == 0 {
        config.port = DEFAULT_PORT;
        changed = true;
    }
    if changed {
        save_config_locked(&config)?;
    }
    Ok(config)
}

fn save_config_locked(config: &ManagementConfig) -> Result<(), String> {
    let path = config_path()?;
    let raw = serde_json::to_string_pretty(config).map_err(|e| e.to_string())?;
    crate::modules::atomic_write::write_secret_string_atomic(&path, &raw)
}

fn load_config() -> Result<ManagementConfig, String> {
    let _guard = config_lock().lock().unwrap_or_else(|e| e.into_inner());
    load_config_locked()
}

fn update_config<T>(
    mutate: impl FnOnce(&mut ManagementConfig) -> Result<T, String>,
) -> Result<T, String> {
    let _guard = config_lock().lock().unwrap_or_else(|e| e.into_inner());
    let mut config = load_config_locked()?;
    let value = mutate(&mut config)?;
    save_config_locked(&config)?;
    Ok(value)
}

// ---------------------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------------------

fn ct_eq(a: &str, b: &str) -> bool {
    ring::constant_time::verify_slices_are_equal(a.as_bytes(), b.as_bytes()).is_ok()
}

/// Resolve a presented bearer token to a scope using only hashes.
fn scope_for_token(config: &ManagementConfig, presented: &str) -> Option<Scope> {
    let digest = sha256_hex(presented);
    // Evaluate both comparisons so timing does not reveal which token matched.
    let is_control = ct_eq(&digest, &config.control_token.sha256);
    let is_read = ct_eq(&digest, &config.read_token.sha256);
    if is_control {
        Some(Scope::Control)
    } else if is_read {
        Some(Scope::Read)
    } else {
        None
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") {
        let token = token.trim();
        (!token.is_empty()).then_some(token)
    } else {
        None
    }
}

fn auth_failures() -> &'static Mutex<VecDeque<Instant>> {
    static FAILURES: OnceLock<Mutex<VecDeque<Instant>>> = OnceLock::new();
    FAILURES.get_or_init(|| Mutex::new(VecDeque::new()))
}

fn auth_locked_out() -> bool {
    let mut failures = auth_failures().lock().unwrap_or_else(|e| e.into_inner());
    while failures
        .front()
        .map(|t| t.elapsed() > AUTH_FAIL_WINDOW)
        .unwrap_or(false)
    {
        failures.pop_front();
    }
    failures.len() >= AUTH_FAIL_LIMIT
}

fn record_auth_failure() {
    let mut failures = auth_failures().lock().unwrap_or_else(|e| e.into_inner());
    failures.push_back(Instant::now());
    while failures.len() > AUTH_FAIL_LIMIT * 2 {
        failures.pop_front();
    }
}

/// DNS-rebinding defence for loopback-only binds.
fn host_and_origin_allowed(headers: &HeaderMap, lan: bool) -> bool {
    if lan {
        return true;
    }
    fn is_loopback_host(host: &str) -> bool {
        let host = host.trim();
        let name = if let Some(stripped) = host.strip_prefix('[') {
            stripped.split(']').next().unwrap_or("")
        } else {
            host.split(':').next().unwrap_or("")
        };
        matches!(name, "127.0.0.1" | "localhost" | "::1")
    }
    if let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok()) {
        if !is_loopback_host(host) {
            return false;
        }
    }
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let authority = origin
            .split_once("://")
            .map(|(_, rest)| rest)
            .unwrap_or(origin);
        if !is_loopback_host(authority) {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------------------
// Redaction / masking helpers (pure, unit-tested)
// ---------------------------------------------------------------------------------------

/// Mask `alice@example.com` -> `al***@example.com`.
pub fn mask_email(email: &str) -> String {
    match email.split_once('@') {
        Some((local, domain)) if !local.is_empty() => {
            let keep: String = local.chars().take(2).collect();
            format!("{keep}***@{domain}")
        }
        _ => {
            let keep: String = email.chars().take(2).collect();
            if email.is_empty() {
                String::new()
            } else {
                format!("{keep}***")
            }
        }
    }
}

fn redaction_patterns() -> &'static Vec<(regex::Regex, &'static str)> {
    static PATTERNS: OnceLock<Vec<(regex::Regex, &'static str)>> = OnceLock::new();
    PATTERNS.get_or_init(|| {
        let build = |pattern: &str| regex::Regex::new(pattern).expect("valid redaction regex");
        vec![
            (build(r"(?i)bearer\s+[A-Za-z0-9._~+/=\-]{8,}"), "Bearer [REDACTED]"),
            (
                build(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-]*"),
                "[REDACTED_JWT]",
            ),
            (build(r"sk-[A-Za-z0-9_\-]{16,}"), "[REDACTED_KEY]"),
            (build(r"ckpt_[rc]_[A-Za-z0-9_\-]{20,}"), "[REDACTED_KEY]"),
            (
                build(
                    r#"(?i)(api[_\-]?key|access[_\-]?token|refresh[_\-]?token|id[_\-]?token|token|secret|password|passwd|cookie|authorization|session[_\-]?key)(["']?\s*[:=]\s*["']?)[^\s"',;&}]{4,}"#,
                ),
                "$1$2[REDACTED]",
            ),
            (build(r"[A-Za-z0-9_\-]{48,}"), "[REDACTED_LONG]"),
        ]
    })
}

/// Remove anything that looks like a credential from free text.
pub fn redact(text: &str) -> String {
    let mut out = text.to_string();
    for (pattern, replacement) in redaction_patterns() {
        out = pattern.replace_all(&out, *replacement).into_owned();
    }
    out
}

fn clip(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        text.to_string()
    } else {
        let mut clipped: String = text.chars().take(max).collect();
        clipped.push('…');
        clipped
    }
}

fn safe_text(text: &str, max: usize) -> String {
    clip(&redact(text), max)
}

// ---------------------------------------------------------------------------------------
// Audit log (in memory + append-only file, never contains secrets)
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEntry {
    pub timestamp: i64,
    pub tool: String,
    pub scope: String,
    pub outcome: String,
    pub detail: String,
}

fn audit_log() -> &'static Mutex<VecDeque<AuditEntry>> {
    static AUDIT: OnceLock<Mutex<VecDeque<AuditEntry>>> = OnceLock::new();
    AUDIT.get_or_init(|| Mutex::new(VecDeque::new()))
}

fn audit(tool: &str, scope: Scope, outcome: &str, detail: &str) {
    let entry = AuditEntry {
        timestamp: now_ms(),
        tool: tool.to_string(),
        scope: scope.as_str().to_string(),
        outcome: outcome.to_string(),
        detail: safe_text(detail, 200),
    };
    crate::modules::logger::log_info(&format!(
        "[ManagementAPI] tool={} scope={} outcome={} detail={}",
        entry.tool, entry.scope, entry.outcome, entry.detail
    ));
    let mut log = audit_log().lock().unwrap_or_else(|e| e.into_inner());
    log.push_back(entry);
    while log.len() > AUDIT_CAPACITY {
        log.pop_front();
    }
}

pub fn audit_entries() -> Vec<AuditEntry> {
    audit_log()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .rev()
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------------------
// Tool catalogue
// ---------------------------------------------------------------------------------------

struct ToolDef {
    name: &'static str,
    description: &'static str,
    scope: Scope,
    schema: fn() -> Value,
}

fn tool_defs() -> &'static [ToolDef] {
    static DEFS: [ToolDef; 9] = [
        ToolDef {
            name: "get_accounts",
            description: "List managed AI accounts (Claude, Codex, Antigravity) with plan, \
                          auth mode and health flags. Emails are masked unless the user \
                          enabled revealEmail. Never returns tokens or API keys.",
            scope: Scope::Read,
            schema: || {
                json!({"type":"object","properties":{
                    "platform":{"type":"string","enum":["claude","codex","antigravity"],
                        "description":"Optional platform filter"}},
                    "additionalProperties":false})
            },
        },
        ToolDef {
            name: "get_quota",
            description: "Cached quota windows and reset times for all platforms Cockpit \
                          tracks. Values come from the last refresh done inside the app.",
            scope: Scope::Read,
            schema: || {
                json!({"type":"object","properties":{
                    "platform":{"type":"string","description":"Optional case-insensitive service filter, e.g. codex"}},
                    "additionalProperties":false})
            },
        },
        ToolDef {
            name: "get_usage_statistics",
            description: "Request/token/cost statistics from the local API gateway.",
            scope: Scope::Read,
            schema: || {
                json!({"type":"object","properties":{
                    "window":{"type":"string","enum":["daily","weekly","monthly","total"],"default":"daily"}},
                    "additionalProperties":false})
            },
        },
        ToolDef {
            name: "get_gateway_status",
            description: "State of the local API gateway, management API and Android \
                          foreground service. Does not include API keys.",
            scope: Scope::Read,
            schema: || json!({"type":"object","properties":{},"additionalProperties":false}),
        },
        ToolDef {
            name: "get_error_logs",
            description: "Recent failed gateway requests and warnings/errors from the app log \
                          (credentials redacted).",
            scope: Scope::Read,
            schema: || {
                json!({"type":"object","properties":{
                    "source":{"type":"string","enum":["gateway","app","both"],"default":"both"},
                    "limit":{"type":"integer","minimum":1,"maximum":100,"default":20}},
                    "additionalProperties":false})
            },
        },
        ToolDef {
            name: "get_account_health",
            description: "Per-account gateway health (failures, cooldowns), quota headroom and \
                          a ranked recommendation of which accounts to prefer.",
            scope: Scope::Read,
            schema: || json!({"type":"object","properties":{},"additionalProperties":false}),
        },
        ToolDef {
            name: "switch_account",
            description: "Make an account the active one for its platform inside Cockpit. \
                          Requires the control token, an active control grant and confirm=true; \
                          without confirm it returns a preview only.",
            scope: Scope::Control,
            schema: || {
                json!({"type":"object","properties":{
                    "platform":{"type":"string","enum":["claude","codex","antigravity"]},
                    "account_id":{"type":"string"},
                    "confirm":{"type":"boolean","default":false}},
                    "required":["platform","account_id"],"additionalProperties":false})
            },
        },
        ToolDef {
            name: "configure_routing",
            description: "Change the gateway account-routing strategy to one of the allowed \
                          policies. Requires the control token, an active control grant and \
                          confirm=true; without confirm it returns a preview only. Cannot \
                          change keys, ports, exposure scope or quotas.",
            scope: Scope::Control,
            schema: || {
                json!({"type":"object","properties":{
                    "strategy":{"type":"string","enum":ALLOWED_ROUTING_STRATEGIES},
                    "confirm":{"type":"boolean","default":false}},
                    "required":["strategy"],"additionalProperties":false})
            },
        },
        ToolDef {
            name: "restart_gateway",
            description: "Restart the local API gateway (keeps accounts, keys and settings). \
                          Requires the control token, an active control grant and confirm=true; \
                          without confirm it returns a preview only.",
            scope: Scope::Control,
            schema: || {
                json!({"type":"object","properties":{
                    "confirm":{"type":"boolean","default":false}},
                    "additionalProperties":false})
            },
        },
    ];
    &DEFS
}

fn tool_def(name: &str) -> Option<&'static ToolDef> {
    tool_defs().iter().find(|def| def.name == name)
}

fn tools_list_json() -> Value {
    let tools: Vec<Value> = tool_defs()
        .iter()
        .map(|def| {
            let mutating = def.scope == Scope::Control;
            json!({
                "name": def.name,
                "description": def.description,
                "inputSchema": (def.schema)(),
                "annotations": {
                    "readOnlyHint": !mutating,
                    "destructiveHint": false,
                    "idempotentHint": !mutating,
                    "openWorldHint": false
                },
                "x-cockpit-scope": def.scope.as_str()
            })
        })
        .collect();
    json!({ "tools": tools })
}

// ---------------------------------------------------------------------------------------
// Tool results
// ---------------------------------------------------------------------------------------

#[derive(Debug)]
pub enum ToolOutcome {
    Ok(Value),
    /// Nothing was changed; the caller must resend with `confirm: true`.
    NeedsConfirmation(Value),
    Denied(String),
    Error(String),
}

impl ToolOutcome {
    fn label(&self) -> &'static str {
        match self {
            ToolOutcome::Ok(_) => "ok",
            ToolOutcome::NeedsConfirmation(_) => "needs_confirmation",
            ToolOutcome::Denied(_) => "denied",
            ToolOutcome::Error(_) => "error",
        }
    }

    fn into_value(self) -> (Value, bool) {
        match self {
            ToolOutcome::Ok(value) => (value, false),
            ToolOutcome::NeedsConfirmation(preview) => (
                json!({
                    "status": "confirmation_required",
                    "message": "No change was made. Ask the user, then call again with confirm=true.",
                    "preview": preview
                }),
                false,
            ),
            ToolOutcome::Denied(reason) => (json!({"status":"denied","reason":reason}), true),
            ToolOutcome::Error(message) => {
                (json!({"status":"error","message":safe_text(&message, 400)}), true)
            }
        }
    }
}

fn arg_bool(args: &Value, key: &str) -> bool {
    args.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn arg_str<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key).and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty())
}

/// Gate shared by every mutating tool. Returns `Some(outcome)` to short-circuit.
fn control_gate(scope: Scope, config: &ManagementConfig, now: i64) -> Option<ToolOutcome> {
    if scope < Scope::Control {
        return Some(ToolOutcome::Denied(
            "this tool needs the control token (current token is read-only)".to_string(),
        ));
    }
    match config.control_granted_until {
        Some(until) if until > now => None,
        _ => Some(ToolOutcome::Denied(
            "control is not granted: the user must enable 'Allow control' in Cockpit \
             (Settings → Management API) first; grants expire automatically"
                .to_string(),
        )),
    }
}

fn label_for(email: &str, reveal: bool) -> String {
    if reveal {
        email.to_string()
    } else {
        mask_email(email)
    }
}

// ---------------------------------------------------------------------------------------
// Data collection (read tools)
// ---------------------------------------------------------------------------------------

fn ts_ms_from_seconds_or_ms(value: i64) -> i64 {
    if value > 10_000_000_000 {
        value
    } else {
        value * 1000
    }
}

fn enum_label<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct QuotaWindow {
    name: String,
    used_percent: Option<f64>,
    remaining_percent: Option<f64>,
    reset_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AccountSummary {
    platform: &'static str,
    account_id: String,
    label: String,
    plan: Option<String>,
    auth_mode: Option<String>,
    status: String,
    current: bool,
    requires_reauth: bool,
    quota_error: Option<String>,
    last_used: Option<i64>,
    quota: Vec<QuotaWindow>,
}

fn window(name: &str, used: Option<f64>, remaining: Option<f64>, reset: Option<i64>) -> QuotaWindow {
    QuotaWindow {
        name: name.to_string(),
        used_percent: used,
        remaining_percent: remaining,
        reset_at: reset.map(ts_ms_from_seconds_or_ms),
    }
}

fn collect_codex(reveal: bool) -> Vec<AccountSummary> {
    let current = crate::modules::codex_account::get_current_account().map(|a| a.id);
    crate::modules::codex_account::list_accounts()
        .into_iter()
        .map(|account| {
            let quota = account
                .quota
                .as_ref()
                .map(|q| {
                    // Codex stores the REMAINING percentage.
                    vec![
                        window(
                            "primary",
                            Some(100.0 - q.hourly_percentage as f64),
                            Some(q.hourly_percentage as f64),
                            q.hourly_reset_time,
                        ),
                        window(
                            "weekly",
                            Some(100.0 - q.weekly_percentage as f64),
                            Some(q.weekly_percentage as f64),
                            q.weekly_reset_time,
                        ),
                    ]
                })
                .unwrap_or_default();
            let quota_error = account.quota_error.as_ref().map(|e| safe_text(&e.message, 160));
            AccountSummary {
                platform: "codex",
                label: label_for(&account.email, reveal),
                plan: account.plan_type.clone(),
                auth_mode: Some(enum_label(&account.auth_mode)),
                status: if account.requires_reauth {
                    "needs_reauth".into()
                } else if quota_error.is_some() {
                    "quota_error".into()
                } else {
                    "ok".into()
                },
                current: current.as_deref() == Some(account.id.as_str()),
                requires_reauth: account.requires_reauth,
                quota_error,
                last_used: Some(account.last_used).filter(|v| *v > 0).map(ts_ms_from_seconds_or_ms),
                quota,
                account_id: account.id,
            }
        })
        .collect()
}

fn collect_claude(reveal: bool) -> Vec<AccountSummary> {
    let current_code = crate::modules::provider_current_state::get_current_account_id(
        "claude_code_account",
    )
    .ok()
    .flatten();
    let current_desktop = crate::modules::provider_current_state::get_current_account_id(
        "claude_desktop_account",
    )
    .ok()
    .flatten();
    crate::modules::claude_account::list_accounts()
        .into_iter()
        .map(|account| {
            // Claude stores the USED percentage.
            let quota = account
                .quota
                .as_ref()
                .map(|q| {
                    let mut windows = vec![
                        window(
                            "five_hour",
                            Some(q.five_hour_percentage as f64),
                            Some(100.0 - q.five_hour_percentage as f64),
                            q.five_hour_reset_time,
                        ),
                        window(
                            "seven_day",
                            Some(q.seven_day_percentage as f64),
                            Some(100.0 - q.seven_day_percentage as f64),
                            q.seven_day_reset_time,
                        ),
                    ];
                    if let Some(sonnet) = q.seven_day_sonnet_percentage {
                        windows.push(window(
                            "seven_day_sonnet",
                            Some(sonnet as f64),
                            Some(100.0 - sonnet as f64),
                            q.seven_day_sonnet_reset_time,
                        ));
                    }
                    windows
                })
                .unwrap_or_default();
            let quota_error = account.quota_error.as_ref().map(|e| safe_text(&e.message, 160));
            let status = account
                .status
                .clone()
                .unwrap_or_else(|| if quota_error.is_some() { "quota_error".into() } else { "ok".into() });
            AccountSummary {
                platform: "claude",
                label: label_for(&account.email, reveal),
                plan: account.plan_type.clone(),
                // Distinguishes subscription OAuth logins from API-key (Anthropic billing) accounts.
                auth_mode: Some(format!("{:?}", account.auth_mode)),
                status,
                current: current_code.as_deref() == Some(account.id.as_str())
                    || current_desktop.as_deref() == Some(account.id.as_str()),
                requires_reauth: false,
                quota_error,
                last_used: None,
                quota,
                account_id: account.id,
            }
        })
        .collect()
}

fn collect_antigravity(reveal: bool) -> Vec<AccountSummary> {
    let current = crate::modules::account::get_current_account_id().ok().flatten();
    crate::modules::account::list_accounts()
        .unwrap_or_default()
        .into_iter()
        .map(|account| {
            let quota = account
                .quota
                .as_ref()
                .map(|q| {
                    q.models
                        .iter()
                        .map(|m| {
                            // Antigravity stores the REMAINING percentage per model.
                            let remaining = m.percentage as f64;
                            let reset = chrono::DateTime::parse_from_rfc3339(&m.reset_time)
                                .ok()
                                .map(|d| d.timestamp_millis());
                            QuotaWindow {
                                name: m.display_name.clone().unwrap_or_else(|| m.name.clone()),
                                used_percent: Some(100.0 - remaining),
                                remaining_percent: Some(remaining),
                                reset_at: reset,
                            }
                        })
                        .collect()
                })
                .unwrap_or_default();
            AccountSummary {
                platform: "antigravity",
                label: label_for(&account.email, reveal),
                plan: account
                    .quota
                    .as_ref()
                    .and_then(|q| q.subscription_tier.clone()),
                auth_mode: Some("oauth".to_string()),
                status: if account.disabled {
                    "disabled".into()
                } else if account.pending_oauth {
                    "pending_oauth".into()
                } else {
                    "ok".into()
                },
                current: current.as_deref() == Some(account.id.as_str()),
                requires_reauth: account.pending_oauth,
                quota_error: account
                    .disabled_reason
                    .as_deref()
                    .map(|r| safe_text(r, 160)),
                last_used: None,
                quota,
                account_id: account.id,
            }
        })
        .collect()
}

fn collect_accounts(platform: Option<&str>, reveal: bool) -> Result<Vec<AccountSummary>, String> {
    let wanted = platform.map(str::to_ascii_lowercase);
    if let Some(p) = wanted.as_deref() {
        if !["claude", "codex", "antigravity"].contains(&p) {
            return Err(format!("unsupported platform filter: {p}"));
        }
    }
    let mut accounts = Vec::new();
    for (name, collect) in [
        ("claude", collect_claude as fn(bool) -> Vec<AccountSummary>),
        ("codex", collect_codex),
        ("antigravity", collect_antigravity),
    ] {
        if wanted.as_deref().map(|w| w == name).unwrap_or(true) {
            accounts.extend(collect(reveal));
        }
    }
    Ok(accounts)
}

fn tool_get_accounts(args: &Value, config: &ManagementConfig) -> ToolOutcome {
    match collect_accounts(arg_str(args, "platform"), config.reveal_email) {
        Ok(accounts) => ToolOutcome::Ok(json!({
            "count": accounts.len(),
            "accounts": accounts,
            "note": "Other tracked platforms (Cursor, Windsurf, Kiro, ...) appear in get_quota."
        })),
        Err(error) => ToolOutcome::Error(error),
    }
}

fn tool_get_quota(args: &Value, config: &ManagementConfig) -> ToolOutcome {
    let filter = arg_str(args, "platform").map(str::to_ascii_lowercase);
    // 1) Normalised rows shared with the web report (Antigravity, Codex, Copilot, Windsurf, ...).
    let rows: Vec<Value> = crate::modules::web_report::build_report_rows()
        .into_iter()
        .filter(|row| {
            filter
                .as_deref()
                .map(|f| row.service.to_ascii_lowercase().contains(f))
                .unwrap_or(true)
        })
        .filter(|row| row.account != "-")
        .map(|row| {
            json!({
                "service": row.service,
                "account": label_for(&row.account, config.reveal_email),
                "metric": safe_text(&row.metric, 80),
                "used": row.used,
                "remaining": row.remaining,
                "resetCycle": row.reset_cycle,
                "status": row.status,
                "note": safe_text(&row.note, 160),
            })
        })
        .collect();
    // 2) Claude is not part of the report rows; add it explicitly.
    let claude: Vec<AccountSummary> = if filter.as_deref().map(|f| "claude".contains(f)).unwrap_or(true) {
        collect_claude(config.reveal_email)
    } else {
        Vec::new()
    };
    ToolOutcome::Ok(json!({
        "source": "cached quota from the last refresh inside Cockpit",
        "rows": rows,
        "claude": claude.iter().map(|a| json!({
            "accountId": a.account_id, "account": a.label, "plan": a.plan,
            "authMode": a.auth_mode, "status": a.status, "windows": a.quota
        })).collect::<Vec<_>>()
    }))
}

fn usage_json(usage: &crate::models::codex_local_access::CodexLocalAccessUsageStats) -> Value {
    json!({
        "requests": usage.request_count,
        "success": usage.success_count,
        "failures": usage.failure_count,
        "clientCanceled": usage.client_canceled_count,
        "inputTokens": usage.input_tokens,
        "outputTokens": usage.output_tokens,
        "totalTokens": usage.total_tokens,
        "cachedTokens": usage.cached_tokens,
        "reasoningTokens": usage.reasoning_tokens,
        "estimatedCostUsd": usage.estimated_cost_usd,
        "avgLatencyMs": if usage.request_count > 0 { usage.total_latency_ms / usage.request_count } else { 0 },
    })
}

async fn tool_get_usage_statistics(args: &Value, config: &ManagementConfig) -> ToolOutcome {
    let state = match crate::modules::codex_local_access::get_local_access_state().await {
        Ok(state) => state,
        Err(error) => return ToolOutcome::Error(error),
    };
    let window_name = arg_str(args, "window").unwrap_or("daily");
    let stats = &state.stats;
    let selected = match window_name {
        "daily" => serde_json::to_value(&stats.daily).ok(),
        "weekly" => serde_json::to_value(&stats.weekly).ok(),
        "monthly" => serde_json::to_value(&stats.monthly).ok(),
        "total" => None,
        other => return ToolOutcome::Error(format!("unknown window: {other}")),
    };
    // The windowed structs are plain numeric aggregates; strip event payloads defensively.
    let selected = selected.map(|mut v| {
        if let Some(obj) = v.as_object_mut() {
            obj.remove("events");
        }
        v
    });
    let mut accounts: Vec<Value> = stats
        .accounts
        .iter()
        .map(|a| {
            let mut v = usage_json(&a.usage);
            v["accountId"] = json!(a.account_id);
            v["account"] = json!(label_for(&a.email, config.reveal_email));
            v
        })
        .collect();
    accounts.sort_by(|a, b| b["requests"].as_u64().cmp(&a["requests"].as_u64()));
    accounts.truncate(25);
    let mut models: Vec<Value> = stats
        .models
        .iter()
        .map(|m| {
            let mut v = usage_json(&m.usage);
            v["model"] = json!(m.model_id);
            v
        })
        .collect();
    models.sort_by(|a, b| b["requests"].as_u64().cmp(&a["requests"].as_u64()));
    models.truncate(25);
    ToolOutcome::Ok(json!({
        "since": stats.since,
        "updatedAt": stats.updated_at,
        "window": window_name,
        "windowStats": selected,
        "totals": usage_json(&stats.totals),
        "topAccounts": accounts,
        "topModels": models,
    }))
}

async fn tool_get_gateway_status(config: &ManagementConfig) -> ToolOutcome {
    let state = match crate::modules::codex_local_access::get_local_access_state().await {
        Ok(state) => state,
        Err(error) => return ToolOutcome::Error(error),
    };
    let (enabled, port, strategy, mode, scope_name, paused) = match state.collection.as_ref() {
        Some(c) => (
            c.enabled,
            Some(c.port),
            Some(enum_label(&c.routing_strategy)),
            Some(enum_label(&c.gateway_mode)),
            Some(enum_label(&c.access_scope)),
            c.paused_account_ids.len(),
        ),
        None => (false, None, None, None, None, 0),
    };
    let platform = crate::modules::android_platform::status();
    ToolOutcome::Ok(json!({
        "gateway": {
            "configured": state.collection.is_some(),
            "enabled": enabled,
            "running": state.running,
            "port": port,
            "baseUrl": state.base_url,
            "routingStrategy": strategy,
            "mode": mode,
            "accessScope": scope_name,
            "memberCount": state.member_count,
            "pausedAccounts": paused,
            "recovering": state.recovering,
            "lastError": state.last_error.as_deref().map(|e| safe_text(e, 300)),
            "totals": usage_json(&state.stats.totals),
        },
        "managementApi": {
            "port": config.port,
            "lanExposed": config.bind_lan,
            "controlGranted": config.control_granted_until.map(|u| u > now_ms()).unwrap_or(false),
            "controlGrantedUntil": config.control_granted_until,
        },
        "android": {
            "isAndroid": platform.is_android,
            "foregroundServiceEnabled": platform.service_enabled,
            "notificationPermission": platform.notification_permission,
            "keystoreAvailable": platform.keystore_available,
        },
        "note": "Android may stop background work (battery optimisation, OEM task killers); \
                 uptime is not guaranteed."
    }))
}

fn gateway_event_json(
    event: &crate::models::codex_local_access::CodexLocalAccessUsageEvent,
    reveal: bool,
) -> Value {
    json!({
        "timestamp": event.timestamp,
        "requestId": event.request_id,
        "accountId": event.account_id,
        "account": label_for(&event.email, reveal),
        "model": event.model_id,
        "requestKind": enum_label(&event.request_kind),
        "httpStatus": event.http_status,
        "errorCategory": safe_text(&event.error_category, 80),
        "errorMessage": safe_text(&event.error_message, 300),
        "latencyMs": event.latency_ms,
    })
}

/// Read the tail of the newest app log, keeping WARN/ERROR lines (redacted).
fn tail_app_log_problems(limit: usize) -> Vec<String> {
    let Ok(path) = crate::modules::logger::get_latest_app_log_file() else {
        return Vec::new();
    };
    let Ok(mut file) = std::fs::File::open(&path) else {
        return Vec::new();
    };
    use std::io::{Read, Seek, SeekFrom};
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let start = len.saturating_sub(256 * 1024);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return Vec::new();
    }
    let mut buf = Vec::new();
    let _ = file.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    let mut lines: Vec<String> = text
        .lines()
        .filter(|l| {
            let upper = l.to_ascii_uppercase();
            upper.contains("WARN") || upper.contains("ERROR")
        })
        .map(|l| safe_text(l, 300))
        .collect();
    let drop = lines.len().saturating_sub(limit);
    lines.drain(..drop);
    lines
}

async fn tool_get_error_logs(args: &Value, config: &ManagementConfig) -> ToolOutcome {
    let source = arg_str(args, "source").unwrap_or("both");
    if !["gateway", "app", "both"].contains(&source) {
        return ToolOutcome::Error(format!("unknown source: {source}"));
    }
    let limit = args
        .get("limit")
        .and_then(Value::as_u64)
        .unwrap_or(20)
        .clamp(1, 100) as u32;
    let mut out = json!({});
    if source != "app" {
        match crate::modules::codex_local_access::query_local_access_usage_events(
            1, limit, None, None, None, None, None, None, None, None, None, None, None, None,
            Some(false), None,
        )
        .await
        {
            Ok(page) => {
                out["gatewayFailures"] = json!({
                    "total": page.total,
                    "events": page.events.iter().map(|e| gateway_event_json(e, config.reveal_email)).collect::<Vec<_>>()
                });
            }
            Err(error) => out["gatewayFailures"] = json!({"error": safe_text(&error, 200)}),
        }
    }
    if source != "gateway" {
        out["appLog"] = json!(tail_app_log_problems(limit as usize));
    }
    ToolOutcome::Ok(out)
}

// ---- Recommendation engine (pure) -----------------------------------------------------

#[derive(Debug, Clone)]
pub struct HealthInput {
    pub platform: String,
    pub account_id: String,
    pub label: String,
    pub available: Option<bool>,
    pub consecutive_failures: u32,
    pub cooldown_active: bool,
    pub requires_reauth: bool,
    /// Lowest remaining percentage over the account's quota windows, if known.
    pub min_remaining_percent: Option<f64>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Recommendation {
    pub platform: String,
    pub account_id: String,
    pub label: String,
    pub score: f64,
    pub reasons: Vec<String>,
}

/// Rank usable accounts. Unusable ones (unavailable, needs re-auth, cooling down) are
/// excluded; the rest are scored by quota headroom minus a failure penalty.
pub fn recommend(inputs: &[HealthInput]) -> Vec<Recommendation> {
    let mut ranked: Vec<Recommendation> = inputs
        .iter()
        .filter(|i| i.available != Some(false) && !i.requires_reauth && !i.cooldown_active)
        .map(|i| {
            let mut reasons = Vec::new();
            let headroom = match i.min_remaining_percent {
                Some(p) => {
                    reasons.push(format!("{p:.0}% quota remaining in the tightest window"));
                    p.clamp(0.0, 100.0)
                }
                None => {
                    reasons.push("quota unknown (neutral score)".to_string());
                    50.0
                }
            };
            let penalty = (i.consecutive_failures as f64 * 15.0).min(60.0);
            if i.consecutive_failures > 0 {
                reasons.push(format!("{} consecutive failures", i.consecutive_failures));
            }
            Recommendation {
                platform: i.platform.clone(),
                account_id: i.account_id.clone(),
                label: i.label.clone(),
                score: headroom - penalty,
                reasons,
            }
        })
        .collect();
    ranked.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    ranked
}

async fn tool_get_account_health(config: &ManagementConfig) -> ToolOutcome {
    let reveal = config.reveal_email;
    let state = crate::modules::codex_local_access::get_local_access_state().await.ok();
    let accounts = collect_accounts(None, reveal).unwrap_or_default();
    let now = now_ms();

    let mut health_rows = Vec::new();
    let mut inputs = Vec::new();
    for account in &accounts {
        let gateway = state
            .as_ref()
            .and_then(|s| s.account_health.iter().find(|h| h.account_id == account.account_id));
        let cooldown_active = gateway
            .map(|h| h.cooldowns.iter().any(|c| c.next_retry_at > now))
            .unwrap_or(false);
        let min_remaining = account
            .quota
            .iter()
            .filter_map(|w| w.remaining_percent)
            .fold(None, |acc: Option<f64>, v| Some(acc.map_or(v, |a| a.min(v))));
        let verdict = if account.requires_reauth {
            "needs_reauth"
        } else if gateway.map(|h| !h.available).unwrap_or(false) {
            "unavailable"
        } else if cooldown_active || gateway.map(|h| h.consecutive_failures > 0).unwrap_or(false) {
            "degraded"
        } else if min_remaining.map(|p| p < 10.0).unwrap_or(false) {
            "low_quota"
        } else if account.status != "ok" {
            "attention"
        } else {
            "healthy"
        };
        inputs.push(HealthInput {
            platform: account.platform.to_string(),
            account_id: account.account_id.clone(),
            label: account.label.clone(),
            available: gateway.map(|h| h.available),
            consecutive_failures: gateway.map(|h| h.consecutive_failures).unwrap_or(0),
            cooldown_active,
            requires_reauth: account.requires_reauth,
            min_remaining_percent: min_remaining,
        });
        health_rows.push(json!({
            "platform": account.platform,
            "accountId": account.account_id,
            "account": account.label,
            "verdict": verdict,
            "status": account.status,
            "minRemainingPercent": min_remaining,
            "gateway": gateway.map(|h| json!({
                "available": h.available,
                "consecutiveFailures": h.consecutive_failures,
                "lastFailureAt": h.last_failure_at,
                "lastFailureStatus": h.last_failure_status,
                "lastFailureCategory": h.last_failure_category.as_deref().map(|c| safe_text(c, 80)),
                "lastFailureMessage": h.last_failure_message.as_deref().map(|c| safe_text(c, 200)),
                "cooldowns": h.cooldowns.iter().map(|c| json!({
                    "model": c.model_id, "remainingMs": c.remaining_ms, "reason": safe_text(&c.reason, 80)
                })).collect::<Vec<_>>(),
            })),
        }));
    }
    let recommendations: Vec<Recommendation> = recommend(&inputs).into_iter().take(5).collect();
    ToolOutcome::Ok(json!({
        "accounts": health_rows,
        "recommendations": recommendations,
        "method": "score = lowest remaining quota % − 15 per consecutive failure; accounts that need re-auth, are unavailable or cooling down are excluded",
    }))
}

// ---- Mutating tools --------------------------------------------------------------------

async fn tool_switch_account(args: &Value, scope: Scope, config: &ManagementConfig) -> ToolOutcome {
    if let Some(outcome) = control_gate(scope, config, now_ms()) {
        return outcome;
    }
    let Some(platform) = arg_str(args, "platform") else {
        return ToolOutcome::Error("platform is required".into());
    };
    let Some(account_id) = arg_str(args, "account_id") else {
        return ToolOutcome::Error("account_id is required".into());
    };
    let known = match collect_accounts(Some(platform), config.reveal_email) {
        Ok(list) => list,
        Err(error) => return ToolOutcome::Error(error),
    };
    let Some(target) = known.iter().find(|a| a.account_id == account_id) else {
        return ToolOutcome::Error(format!("no {platform} account with id {account_id}"));
    };
    if target.requires_reauth || target.status == "disabled" {
        return ToolOutcome::Denied(format!(
            "account is not switchable (status: {})",
            target.status
        ));
    }
    if !arg_bool(args, "confirm") {
        return ToolOutcome::NeedsConfirmation(json!({
            "action": "switch_account",
            "platform": platform,
            "to": {"accountId": target.account_id, "account": target.label, "plan": target.plan},
            "from": known.iter().find(|a| a.current).map(|a| json!({"accountId": a.account_id, "account": a.label})),
            "effect": "Makes this account the active one inside Cockpit and rewrites Cockpit's own sandboxed profile. It does not change other apps on the phone."
        }));
    }
    let result: Result<(), String> = match platform {
        "codex" => crate::modules::codex_account::switch_account_managed(account_id)
            .await
            .map(|_| ()),
        "antigravity" => crate::modules::account::switch_account_local_no_restart(account_id)
            .await
            .map(|_| ()),
        "claude" => {
            let id = account_id.to_string();
            tauri::async_runtime::spawn_blocking(move || {
                let account = crate::modules::claude_account::load_account(&id)
                    .ok_or_else(|| "Claude account not found".to_string())?;
                crate::modules::claude_account::inject_to_claude(&id)?;
                use crate::models::claude::ClaudeAuthMode;
                let key = if matches!(
                    account.auth_mode,
                    ClaudeAuthMode::DesktopOAuth | ClaudeAuthMode::DesktopGateway
                ) {
                    "claude_desktop_account"
                } else {
                    "claude_code_account"
                };
                crate::modules::provider_current_state::set_current_account_id(key, Some(id.as_str()))
            })
            .await
            .map_err(|e| e.to_string())
            .and_then(|r| r)
        }
        other => Err(format!("unsupported platform: {other}")),
    };
    match result {
        Ok(()) => ToolOutcome::Ok(json!({"status":"switched","platform":platform,"accountId":account_id})),
        Err(error) => ToolOutcome::Error(error),
    }
}

async fn tool_configure_routing(args: &Value, scope: Scope, config: &ManagementConfig) -> ToolOutcome {
    if let Some(outcome) = control_gate(scope, config, now_ms()) {
        return outcome;
    }
    let Some(strategy) = arg_str(args, "strategy") else {
        return ToolOutcome::Error("strategy is required".into());
    };
    if !ALLOWED_ROUTING_STRATEGIES.contains(&strategy) {
        return ToolOutcome::Denied(format!(
            "strategy '{strategy}' is not allowed; allowed: {}",
            ALLOWED_ROUTING_STRATEGIES.join(", ")
        ));
    }
    let parsed: crate::models::codex_local_access::CodexLocalAccessRoutingStrategy =
        match serde_json::from_value(json!(strategy)) {
            Ok(value) => value,
            Err(error) => return ToolOutcome::Error(error.to_string()),
        };
    let current = crate::modules::codex_local_access::get_local_access_state()
        .await
        .ok()
        .and_then(|s| s.collection.map(|c| enum_label(&c.routing_strategy)));
    if !arg_bool(args, "confirm") {
        return ToolOutcome::NeedsConfirmation(json!({
            "action": "configure_routing",
            "from": current,
            "to": strategy,
            "effect": "Changes how the local gateway picks an account for new requests."
        }));
    }
    match crate::modules::codex_local_access::update_local_access_routing_strategy(parsed).await {
        Ok(_) => ToolOutcome::Ok(json!({"status":"updated","from":current,"to":strategy})),
        Err(error) => ToolOutcome::Error(error),
    }
}

async fn tool_restart_gateway(args: &Value, scope: Scope, config: &ManagementConfig) -> ToolOutcome {
    if let Some(outcome) = control_gate(scope, config, now_ms()) {
        return outcome;
    }
    if !arg_bool(args, "confirm") {
        return ToolOutcome::NeedsConfirmation(json!({
            "action": "restart_gateway",
            "effect": "Briefly interrupts in-flight gateway requests; accounts, keys and settings are kept."
        }));
    }
    match crate::modules::codex_local_access::restart_local_access_sidecar().await {
        Ok(state) => ToolOutcome::Ok(json!({"status":"restarted","running":state.running,"lastError":state.last_error.as_deref().map(|e| safe_text(e, 200))})),
        Err(error) => ToolOutcome::Error(error),
    }
}

/// Execute one tool for an authenticated caller.
pub async fn call_tool(name: &str, args: &Value, scope: Scope) -> ToolOutcome {
    let Some(def) = tool_def(name) else {
        return ToolOutcome::Error(format!("unknown tool: {name}"));
    };
    if !args.is_object() && !args.is_null() {
        return ToolOutcome::Error("arguments must be an object".into());
    }
    let empty = json!({});
    let args = if args.is_null() { &empty } else { args };
    let config = match load_config() {
        Ok(config) => config,
        Err(error) => return ToolOutcome::Error(error),
    };
    if def.scope > scope {
        return ToolOutcome::Denied(format!(
            "tool '{name}' needs the control token (current token is read-only)"
        ));
    }
    match name {
        "get_accounts" => tool_get_accounts(args, &config),
        "get_quota" => tool_get_quota(args, &config),
        "get_usage_statistics" => tool_get_usage_statistics(args, &config).await,
        "get_gateway_status" => tool_get_gateway_status(&config).await,
        "get_error_logs" => tool_get_error_logs(args, &config).await,
        "get_account_health" => tool_get_account_health(&config).await,
        "switch_account" => tool_switch_account(args, scope, &config).await,
        "configure_routing" => tool_configure_routing(args, scope, &config).await,
        "restart_gateway" => tool_restart_gateway(args, scope, &config).await,
        _ => ToolOutcome::Error(format!("unknown tool: {name}")),
    }
}

fn args_summary(args: &Value) -> String {
    match args.as_object() {
        Some(map) => {
            let parts: Vec<String> = map
                .iter()
                .map(|(k, v)| match v {
                    Value::String(s) => format!("{k}={}", clip(s, 40)),
                    other => format!("{k}={other}"),
                })
                .collect();
            parts.join(" ")
        }
        None => String::new(),
    }
}

// ---------------------------------------------------------------------------------------
// HTTP layer
// ---------------------------------------------------------------------------------------

fn json_response(status: StatusCode, body: Value) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json"), (header::CACHE_CONTROL, "no-store")],
        body.to_string(),
    )
        .into_response()
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}

/// Authenticate a request. `Err` is a ready response.
fn authenticate(headers: &HeaderMap) -> Result<(Scope, ManagementConfig), Response> {
    let config = match load_config() {
        Ok(config) => config,
        Err(_) => {
            return Err(json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error":"management configuration unavailable"}),
            ))
        }
    };
    if !config.enabled {
        return Err(json_response(StatusCode::SERVICE_UNAVAILABLE, json!({"error":"management API is disabled"})));
    }
    if !host_and_origin_allowed(headers, config.bind_lan) {
        return Err(json_response(StatusCode::FORBIDDEN, json!({"error":"host or origin not allowed"})));
    }
    if auth_locked_out() {
        return Err(json_response(StatusCode::TOO_MANY_REQUESTS, json!({"error":"too many failed attempts, retry later"})));
    }
    let Some(token) = bearer_token(headers) else {
        record_auth_failure();
        return Err((
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer realm=\"cockpit-management\"")],
            "missing bearer token",
        )
            .into_response());
    };
    match scope_for_token(&config, token) {
        Some(scope) => Ok((scope, config)),
        None => {
            record_auth_failure();
            Err((
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Bearer realm=\"cockpit-management\"")],
                "invalid bearer token",
            )
                .into_response())
        }
    }
}

async fn run_tool_for_http(name: &str, args: &Value, scope: Scope) -> (Value, bool) {
    let outcome = call_tool(name, args, scope).await;
    audit(name, scope, outcome.label(), &args_summary(args));
    outcome.into_value()
}

async fn handle_rpc_message(message: &Value, scope: Scope) -> Option<Value> {
    let id = message.get("id").cloned();
    let method = message.get("method").and_then(Value::as_str).unwrap_or("");
    // Notifications (no id) never get a response.
    let Some(id) = id else { return None };
    if message.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Some(rpc_error(id, -32600, "invalid request: jsonrpc must be \"2.0\""));
    }
    let params = message.get("params").cloned().unwrap_or(Value::Null);
    let result = match method {
        "initialize" => {
            let requested = params.get("protocolVersion").and_then(Value::as_str).unwrap_or("");
            let version = if SUPPORTED_PROTOCOLS.contains(&requested) { requested } else { SUPPORTED_PROTOCOLS[0] };
            json!({
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name":"cockpit-management","version": env!("CARGO_PKG_VERSION")},
                "instructions": "Read tools are always available with a valid token. Mutating tools need the control token, an in-app control grant and confirm=true; call them without confirm first to preview."
            })
        }
        "ping" => json!({}),
        "tools/list" => tools_list_json(),
        "tools/call" => {
            let Some(name) = params.get("name").and_then(Value::as_str) else {
                return Some(rpc_error(id, -32602, "tools/call requires params.name"));
            };
            let args = params.get("arguments").cloned().unwrap_or(Value::Null);
            let (value, is_error) = run_tool_for_http(name, &args, scope).await;
            json!({
                "content": [{"type":"text","text": serde_json::to_string_pretty(&value).unwrap_or_default()}],
                "structuredContent": value,
                "isError": is_error
            })
        }
        _ => return Some(rpc_error(id, -32601, "method not found")),
    };
    Some(json!({"jsonrpc":"2.0","id":id,"result":result}))
}

async fn mcp_post(headers: HeaderMap, body: Bytes) -> Response {
    let (scope, _config) = match authenticate(&headers) {
        Ok(ok) => ok,
        Err(response) => return response,
    };
    let parsed: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return json_response(StatusCode::OK, rpc_error(Value::Null, -32700, "parse error")),
    };
    match parsed {
        Value::Array(batch) => {
            let mut responses = Vec::new();
            for message in &batch {
                if let Some(response) = handle_rpc_message(message, scope).await {
                    responses.push(response);
                }
            }
            if responses.is_empty() {
                StatusCode::ACCEPTED.into_response()
            } else {
                json_response(StatusCode::OK, Value::Array(responses))
            }
        }
        message => match handle_rpc_message(&message, scope).await {
            Some(response) => json_response(StatusCode::OK, response),
            None => StatusCode::ACCEPTED.into_response(),
        },
    }
}

async fn mcp_method_not_allowed() -> Response {
    (StatusCode::METHOD_NOT_ALLOWED, [(header::ALLOW, "POST")], "").into_response()
}

async fn rest_list_tools(headers: HeaderMap) -> Response {
    match authenticate(&headers) {
        Ok(_) => json_response(StatusCode::OK, tools_list_json()),
        Err(response) => response,
    }
}

async fn rest_call_tool(AxPath(name): AxPath<String>, headers: HeaderMap, body: Bytes) -> Response {
    let (scope, _config) = match authenticate(&headers) {
        Ok(ok) => ok,
        Err(response) => return response,
    };
    let args: Value = if body.is_empty() {
        Value::Null
    } else {
        match serde_json::from_slice(&body) {
            Ok(value) => value,
            Err(_) => return json_response(StatusCode::BAD_REQUEST, json!({"error":"body must be JSON"})),
        }
    };
    if tool_def(&name).is_none() {
        return json_response(StatusCode::NOT_FOUND, json!({"error":"unknown tool"}));
    }
    let (value, is_error) = run_tool_for_http(&name, &args, scope).await;
    json_response(if is_error { StatusCode::UNPROCESSABLE_ENTITY } else { StatusCode::OK }, value)
}

async fn rest_audit(headers: HeaderMap) -> Response {
    match authenticate(&headers) {
        Ok(_) => json_response(StatusCode::OK, json!({"entries": audit_entries()})),
        Err(response) => response,
    }
}

async fn healthz() -> Response {
    json_response(StatusCode::OK, json!({"status":"ok","service":"cockpit-management"}))
}

fn build_router() -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/mcp", post(mcp_post).get(mcp_method_not_allowed).delete(mcp_method_not_allowed))
        .route("/api/v1/tools", get(rest_list_tools))
        .route("/api/v1/tools/{name}", post(rest_call_tool))
        .route("/api/v1/audit", get(rest_audit))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(())
}

// ---------------------------------------------------------------------------------------
// Server lifecycle
// ---------------------------------------------------------------------------------------

struct ServerHandle {
    port: u16,
    shutdown: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

fn server_slot() -> &'static tokio::sync::Mutex<Option<ServerHandle>> {
    static SLOT: OnceLock<tokio::sync::Mutex<Option<ServerHandle>>> = OnceLock::new();
    SLOT.get_or_init(|| tokio::sync::Mutex::new(None))
}

/// Bind and serve according to the stored config. Idempotent; restarts if the port or bind
/// scope changed.
pub async fn apply_config() -> Result<(), String> {
    let config = load_config()?;
    let mut slot = server_slot().lock().await;
    if let Some(handle) = slot.take() {
        let _ = handle.shutdown.send(());
        let _ = tokio::time::timeout(Duration::from_secs(3), handle.task).await;
    }
    if !config.enabled {
        return Ok(());
    }
    let addr: std::net::SocketAddr = if config.bind_lan {
        ([0, 0, 0, 0], config.port).into()
    } else {
        ([127, 0, 0, 1], config.port).into()
    };
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("cannot bind management API on {addr}: {e}"))?;
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let router = build_router();
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                let _ = rx.await;
            })
            .await;
    });
    crate::modules::logger::log_info(&format!(
        "[ManagementAPI] listening on {addr} (lan={})",
        config.bind_lan
    ));
    *slot = Some(ServerHandle { port: config.port, shutdown: tx, task });
    Ok(())
}

pub async fn restore_on_startup() {
    if let Err(error) = apply_config().await {
        crate::modules::logger::log_warn(&format!("[ManagementAPI] startup failed: {error}"));
    }
}

pub async fn running_port() -> Option<u16> {
    server_slot().lock().await.as_ref().map(|h| h.port)
}

// ---------------------------------------------------------------------------------------
// Settings API used by Tauri commands (never exposes tokens except `reveal_token`)
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagementStatus {
    pub enabled: bool,
    pub running: bool,
    pub port: u16,
    pub bind_lan: bool,
    pub reveal_email: bool,
    pub control_granted_until: Option<i64>,
    pub control_granted: bool,
    pub mcp_url: String,
    pub read_token_fingerprint: String,
    pub control_token_fingerprint: String,
    pub allowed_routing_strategies: Vec<&'static str>,
}

pub async fn get_status() -> Result<ManagementStatus, String> {
    let config = load_config()?;
    let running = running_port().await.is_some();
    let host = if config.bind_lan { "<device-ip>" } else { "127.0.0.1" };
    Ok(ManagementStatus {
        enabled: config.enabled,
        running,
        port: config.port,
        bind_lan: config.bind_lan,
        reveal_email: config.reveal_email,
        control_granted_until: config.control_granted_until,
        control_granted: config.control_granted_until.map(|u| u > now_ms()).unwrap_or(false),
        mcp_url: format!("http://{host}:{}/mcp", config.port),
        read_token_fingerprint: config.read_token.sha256.chars().take(8).collect(),
        control_token_fingerprint: config.control_token.sha256.chars().take(8).collect(),
        allowed_routing_strategies: ALLOWED_ROUTING_STRATEGIES.to_vec(),
    })
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagementSettingsUpdate {
    pub enabled: Option<bool>,
    pub port: Option<u16>,
    pub bind_lan: Option<bool>,
    pub reveal_email: Option<bool>,
}

pub async fn update_settings(update: ManagementSettingsUpdate) -> Result<ManagementStatus, String> {
    if let Some(port) = update.port {
        if port < 1024 {
            return Err("port must be 1024 or higher".to_string());
        }
    }
    update_config(|config| {
        if let Some(enabled) = update.enabled {
            config.enabled = enabled;
        }
        if let Some(port) = update.port {
            config.port = port;
        }
        if let Some(lan) = update.bind_lan {
            config.bind_lan = lan;
            if lan {
                // Remote exposure never inherits an old control grant.
                config.control_granted_until = None;
            }
        }
        if let Some(reveal) = update.reveal_email {
            config.reveal_email = reveal;
        }
        if !config.enabled {
            config.control_granted_until = None;
        }
        Ok(())
    })?;
    apply_config().await?;
    get_status().await
}

/// Grant (minutes > 0) or revoke (0) permission for mutating tools.
pub async fn set_control_grant(minutes: u32) -> Result<ManagementStatus, String> {
    let minutes = minutes.min(MAX_GRANT_MINUTES);
    update_config(|config| {
        config.control_granted_until = if minutes == 0 {
            None
        } else {
            Some(now_ms() + minutes as i64 * 60_000)
        };
        Ok(())
    })?;
    audit(
        "control_grant",
        Scope::Control,
        if minutes == 0 { "revoked" } else { "granted" },
        &format!("minutes={minutes}"),
    );
    get_status().await
}

pub fn reveal_token(scope: &str) -> Result<String, String> {
    let scope = Scope::parse(scope)?;
    let config = load_config()?;
    let stored = match scope {
        Scope::Read => &config.read_token,
        Scope::Control => &config.control_token,
    };
    unseal(&stored.sealed)
}

pub fn rotate_token(scope: &str) -> Result<String, String> {
    let scope = Scope::parse(scope)?;
    let (token, stored) = generate_token(scope)?;
    update_config(|config| {
        match scope {
            Scope::Read => config.read_token = stored,
            Scope::Control => {
                config.control_token = stored;
                config.control_granted_until = None;
            }
        }
        Ok(())
    })?;
    audit("rotate_token", Scope::Control, "ok", &format!("scope={}", scope.as_str()));
    Ok(token)
}

#[cfg(test)]
#[path = "management_api_tests.rs"]
mod tests;
