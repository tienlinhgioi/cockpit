//! Tauri commands for the Android build: foreground service, platform status and the
//! management API / MCP settings panel. All of them are safe no-ops or clear errors on
//! desktop, so the shared frontend can call them unconditionally.

use crate::modules::android_platform;
use crate::modules::management_api::{self, AuditEntry, ManagementSettingsUpdate, ManagementStatus};

#[tauri::command]
pub fn android_platform_status() -> android_platform::AndroidPlatformStatus {
    android_platform::status()
}

#[tauri::command]
pub async fn android_service_set_enabled(enabled: bool) -> Result<android_platform::AndroidPlatformStatus, String> {
    let status_text = foreground_status_text().await;
    tauri::async_runtime::spawn_blocking(move || {
        android_platform::service_set_enabled(enabled, &status_text)?;
        Ok::<_, String>(android_platform::status())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn android_request_notification_permission() -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(android_platform::request_notification_permission)
        .await
        .map_err(|e| e.to_string())?
}

/// One-line text for the foreground notification. Contains no account identifiers.
pub async fn foreground_status_text() -> String {
    let gateway = match crate::modules::codex_local_access::get_local_access_state().await {
        Ok(state) if state.running => format!(
            "API gateway running ({} account{})",
            state.member_count,
            if state.member_count == 1 { "" } else { "s" }
        ),
        Ok(_) => "API gateway stopped".to_string(),
        Err(_) => "API gateway unavailable".to_string(),
    };
    let management = match management_api::get_status().await {
        Ok(status) if status.running => format!("management API on :{}", status.port),
        _ => "management API off".to_string(),
    };
    format!("{gateway} · {management}")
}

#[tauri::command]
pub async fn management_api_get_status() -> Result<ManagementStatus, String> {
    management_api::get_status().await
}

#[tauri::command]
pub async fn management_api_update_settings(update: ManagementSettingsUpdate) -> Result<ManagementStatus, String> {
    management_api::update_settings(update).await
}

#[tauri::command]
pub async fn management_api_set_control_grant(minutes: u32) -> Result<ManagementStatus, String> {
    management_api::set_control_grant(minutes).await
}

/// Shows a token to the user inside the app (IPC only; never sent over the management API).
#[tauri::command]
pub async fn management_api_reveal_token(scope: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || management_api::reveal_token(&scope))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn management_api_rotate_token(scope: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || management_api::rotate_token(&scope))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
pub fn management_api_audit_log() -> Vec<AuditEntry> {
    management_api::audit_entries()
}
