/**
 * Android detection + root class so mobile-only CSS (src/styles/mobile.css) can be scoped
 * with `html.platform-android` without touching the desktop layout.
 */
export function isAndroidWebView(): boolean {
  return typeof navigator !== 'undefined' && /android/i.test(navigator.userAgent || '');
}

export function applyPlatformClasses(): void {
  if (typeof document === 'undefined') return;
  if (isAndroidWebView()) {
    document.documentElement.classList.add('platform-android');
  }
}
