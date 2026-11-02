//! Keeps the foreground-service notification text current while the user has the service
//! enabled. Android only; sleeps cheaply otherwise.

use std::time::Duration;

pub async fn run() {
    let mut last = String::new();
    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
        let enabled = tauri::async_runtime::spawn_blocking(crate::modules::android_platform::service_enabled)
            .await
            .unwrap_or(false);
        if !enabled {
            continue;
        }
        let text = crate::commands::mobile_commands::foreground_status_text().await;
        if text == last {
            continue;
        }
        let to_send = text.clone();
        let result = tauri::async_runtime::spawn_blocking(move || {
            crate::modules::android_platform::service_update_status(&to_send)
        })
        .await;
        if matches!(result, Ok(Ok(()))) {
            last = text;
        }
    }
}
