//! Android compatibility shims for desktop-only `tauri::Window` APIs.
//!
//! Tauri compiles `hide`, `minimize`, `set_size`, `destroy`, ... only for
//! desktop targets. On Android there is a single, OS-managed activity window,
//! so these operations are intentionally no-ops that report success. Shared
//! code that persists window geometry or "closes to tray" therefore keeps
//! compiling unchanged and simply does nothing on Android.
//!
//! Import with `use crate::utils::android_window_compat::*;` (gated on
//! `target_os = "android"` at the call site).

use tauri::{Runtime, Window, WebviewWindow, WebviewWindowBuilder};

pub trait DesktopWindowCompat {
    fn hide(&self) -> tauri::Result<()> {
        Ok(())
    }
    fn minimize(&self) -> tauri::Result<()> {
        Ok(())
    }
    fn maximize(&self) -> tauri::Result<()> {
        Ok(())
    }
    fn show(&self) -> tauri::Result<()> {
        Ok(())
    }
    fn unminimize(&self) -> tauri::Result<()> {
        Ok(())
    }
    fn set_focus(&self) -> tauri::Result<()> {
        Ok(())
    }
    fn center(&self) -> tauri::Result<()> {
        Ok(())
    }
    fn close(&self) -> tauri::Result<()> {
        Ok(())
    }
    fn destroy(&self) -> tauri::Result<()> {
        Ok(())
    }
    fn set_always_on_top(&self, _always_on_top: bool) -> tauri::Result<()> {
        Ok(())
    }
    fn set_size<S: Into<tauri::Size>>(&self, _size: S) -> tauri::Result<()> {
        Ok(())
    }
    fn set_min_size<S: Into<tauri::Size>>(&self, _size: Option<S>) -> tauri::Result<()> {
        Ok(())
    }
    fn set_position<P: Into<tauri::Position>>(&self, _position: P) -> tauri::Result<()> {
        Ok(())
    }
}

impl<R: Runtime> DesktopWindowCompat for Window<R> {}
impl<R: Runtime> DesktopWindowCompat for WebviewWindow<R> {}

pub trait DesktopWindowBuilderCompat: Sized {
    fn title<S: Into<String>>(self, _title: S) -> Self {
        self
    }
    fn focused(self, _focused: bool) -> Self {
        self
    }
    fn center(self) -> Self {
        self
    }
    fn min_inner_size(self, _width: f64, _height: f64) -> Self {
        self
    }
    fn inner_size(self, _width: f64, _height: f64) -> Self {
        self
    }
}

impl<'a, R: Runtime, M: tauri::Manager<R>> DesktopWindowBuilderCompat
    for WebviewWindowBuilder<'a, R, M>
{
}
