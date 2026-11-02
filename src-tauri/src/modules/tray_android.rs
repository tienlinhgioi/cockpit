//! Android replacement for the desktop system-tray module.
//!
//! Android has no tray / menu bar. The public surface used by the rest of the
//! crate (`update_tray_menu`, `apply_tray_icon_style`, `create_tray_skeleton`,
//! `PlatformId`) is preserved as cheap no-ops so shared account/quota code keeps
//! calling it unchanged. Quota visibility on Android is provided by the main UI
//! and the foreground-service notification instead.

use tauri::Runtime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PlatformId {
    Antigravity,
    Codex,
    Claude,
    Zed,
    GitHubCopilot,
    Windsurf,
    Kiro,
    Cursor,

    Grok,
    Codebuddy,
    CodebuddyCn,
    Qoder,
    Zcode,
    Trae,
    TraeSolo,
    TraeCn,
    TraeSoloCn,
    Workbuddy,
}

impl PlatformId {
    pub(crate) fn default_order() -> [Self; 18] {
        [
            Self::Claude,
            Self::Codex,
            Self::Antigravity,
            Self::Zed,
            Self::GitHubCopilot,
            Self::Windsurf,
            Self::Kiro,
            Self::Cursor,
            Self::Grok,
            Self::Codebuddy,
            Self::CodebuddyCn,
            Self::Qoder,
            Self::Zcode,
            Self::Trae,
            Self::TraeSolo,
            Self::TraeCn,
            Self::TraeSoloCn,
            Self::Workbuddy,
        ]
    }

    pub(crate) fn from_str(value: &str) -> Option<Self> {
        match value {
            crate::modules::tray_layout::PLATFORM_ANTIGRAVITY => Some(Self::Antigravity),
            crate::modules::tray_layout::PLATFORM_CODEX => Some(Self::Codex),
            crate::modules::tray_layout::PLATFORM_CLAUDE_MANAGER => Some(Self::Claude),
            crate::modules::tray_layout::PLATFORM_ZED => Some(Self::Zed),
            crate::modules::tray_layout::PLATFORM_GITHUB_COPILOT => Some(Self::GitHubCopilot),
            crate::modules::tray_layout::PLATFORM_WINDSURF => Some(Self::Windsurf),
            crate::modules::tray_layout::PLATFORM_KIRO => Some(Self::Kiro),
            crate::modules::tray_layout::PLATFORM_CURSOR => Some(Self::Cursor),
            crate::modules::tray_layout::PLATFORM_GROK => Some(Self::Grok),
            crate::modules::tray_layout::PLATFORM_CODEBUDDY => Some(Self::Codebuddy),
            crate::modules::tray_layout::PLATFORM_CODEBUDDY_CN => Some(Self::CodebuddyCn),
            crate::modules::tray_layout::PLATFORM_QODER => Some(Self::Qoder),
            crate::modules::tray_layout::PLATFORM_ZCODE => Some(Self::Zcode),
            crate::modules::tray_layout::PLATFORM_TRAE => Some(Self::Trae),
            crate::modules::tray_layout::PLATFORM_TRAE_SOLO => Some(Self::TraeSolo),
            crate::modules::tray_layout::PLATFORM_TRAE_CN => Some(Self::TraeCn),
            crate::modules::tray_layout::PLATFORM_TRAE_SOLO_CN => Some(Self::TraeSoloCn),
            crate::modules::tray_layout::PLATFORM_WORKBUDDY => Some(Self::Workbuddy),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Antigravity => crate::modules::tray_layout::PLATFORM_ANTIGRAVITY,
            Self::Codex => crate::modules::tray_layout::PLATFORM_CODEX,
            Self::Claude => crate::modules::tray_layout::PLATFORM_CLAUDE_MANAGER,
            Self::Zed => crate::modules::tray_layout::PLATFORM_ZED,
            Self::GitHubCopilot => crate::modules::tray_layout::PLATFORM_GITHUB_COPILOT,
            Self::Windsurf => crate::modules::tray_layout::PLATFORM_WINDSURF,
            Self::Kiro => crate::modules::tray_layout::PLATFORM_KIRO,
            Self::Cursor => crate::modules::tray_layout::PLATFORM_CURSOR,
            Self::Grok => crate::modules::tray_layout::PLATFORM_GROK,
            Self::Codebuddy => crate::modules::tray_layout::PLATFORM_CODEBUDDY,
            Self::CodebuddyCn => crate::modules::tray_layout::PLATFORM_CODEBUDDY_CN,
            Self::Qoder => crate::modules::tray_layout::PLATFORM_QODER,
            Self::Zcode => crate::modules::tray_layout::PLATFORM_ZCODE,
            Self::Trae => crate::modules::tray_layout::PLATFORM_TRAE,
            Self::TraeSolo => crate::modules::tray_layout::PLATFORM_TRAE_SOLO,
            Self::TraeCn => crate::modules::tray_layout::PLATFORM_TRAE_CN,
            Self::TraeSoloCn => crate::modules::tray_layout::PLATFORM_TRAE_SOLO_CN,
            Self::Workbuddy => crate::modules::tray_layout::PLATFORM_WORKBUDDY,
        }
    }

    pub(crate) fn title(self) -> &'static str {
        match self {
            Self::Antigravity => "Antigravity IDE",
            Self::Codex => "Codex",
            Self::Claude => "Claude",
            Self::Zed => "Zed",
            Self::GitHubCopilot => "GitHub Copilot",
            Self::Windsurf => "Windsurf",
            Self::Kiro => "Kiro",
            Self::Cursor => "Cursor",
            Self::Grok => "Grok CLI",
            Self::Codebuddy => "CodeBuddy",
            Self::CodebuddyCn => "CodeBuddy CN",
            Self::Qoder => "Qoder",
            Self::Zcode => "ZCode",
            Self::Trae => "Trae",
            Self::TraeSolo => "TRAE SOLO",
            Self::TraeCn => "Trae CN",
            Self::TraeSoloCn => "TRAE SOLO CN",
            Self::Workbuddy => "WorkBuddy",
        }
    }

    pub(crate) fn nav_target(self) -> &'static str {
        match self {
            Self::Antigravity => "overview",
            Self::Codex => "codex",
            Self::Claude => "claude",
            Self::Zed => "zed",
            Self::GitHubCopilot => "github-copilot",
            Self::Windsurf => "windsurf",
            Self::Kiro => "kiro",
            Self::Cursor => "cursor",
            Self::Grok => "grok",
            Self::Codebuddy => "codebuddy",
            Self::CodebuddyCn => "codebuddy-cn",
            Self::Qoder => "qoder",
            Self::Zcode => "zcode",
            Self::Trae => "trae",
            Self::TraeSolo => "trae-solo",
            Self::TraeCn => "trae-cn",
            Self::TraeSoloCn => "trae-solo-cn",
            Self::Workbuddy => "workbuddy",
        }
    }
}

/// Menu item ids (kept for API parity with the desktop module).
pub mod menu_ids {
    pub const SHOW_WINDOW: &str = "show_window";
    pub const SHOW_FLOATING_CARD: &str = "show_floating_card";
    pub const REFRESH_QUOTA: &str = "refresh_quota";
    pub const SETTINGS: &str = "settings";
    pub const QUIT: &str = "quit";
}

pub fn apply_tray_icon_style<R: Runtime>(_app: &tauri::AppHandle<R>) -> Result<(), String> {
    Ok(())
}

pub fn create_tray_skeleton<R: Runtime>(_app: &tauri::AppHandle<R>) -> Result<(), String> {
    Ok(())
}

pub fn update_tray_menu<R: Runtime>(_app: &tauri::AppHandle<R>) -> Result<(), String> {
    Ok(())
}
