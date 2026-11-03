import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { writeText } from '@tauri-apps/plugin-clipboard-manager';
import {
  getAndroidPlatformStatus,
  getManagementAuditLog,
  getManagementStatus,
  requestAndroidNotificationPermission,
  revealManagementToken,
  rotateManagementToken,
  setAndroidServiceEnabled,
  setManagementControlGrant,
  updateManagementSettings,
  type AndroidPlatformStatus,
  type ManagementAuditEntry,
  type ManagementScope,
  type ManagementStatus,
} from '../../services/mobileManagementService';
import { registerMobileResources } from '../../i18n/mobileResources';


function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Android foreground service + Management API / MCP settings.
 * The panel only talks to Rust commands; tokens are shown on demand and never persisted
 * in the webview.
 */
export function MobileManagementPanel() {
  const { t } = useTranslation();
  const [platform, setPlatform] = useState<AndroidPlatformStatus | null>(null);
  const [status, setStatus] = useState<ManagementStatus | null>(null);
  const [audit, setAudit] = useState<ManagementAuditEntry[]>([]);
  const [shownToken, setShownToken] = useState<{ scope: ManagementScope; value: string } | null>(null);
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [p, s, a] = await Promise.all([
        getAndroidPlatformStatus(),
        getManagementStatus(),
        getManagementAuditLog(),
      ]);
      setPlatform(p);
      setStatus(s);
      setAudit(a.slice(0, 20));
    } catch (error) {
      setMessage(errorText(error));
    }
  }, []);

  useEffect(() => {
    registerMobileResources();
    void refresh();
  }, [refresh]);

  const run = async (action: () => Promise<unknown>, okMessage?: string) => {
    setBusy(true);
    setMessage('');
    try {
      await action();
      if (okMessage) setMessage(okMessage);
    } catch (error) {
      setMessage(errorText(error));
    } finally {
      setBusy(false);
      await refresh();
    }
  };

  const copy = (text: string) => run(() => writeText(text), t('mobile.copied', 'Copied'));

  const mcpCommand = status
    ? `claude mcp add --transport http cockpit ${status.mcpUrl} --header "Authorization: Bearer <TOKEN>"`
    : '';
  const grantRemaining =
    status?.controlGranted && status.controlGrantedUntil
      ? Math.max(0, Math.ceil((status.controlGrantedUntil - Date.now()) / 60000))
      : 0;

  const tokenRow = (scope: ManagementScope, label: string, fingerprint: string) => (
    <div className="mobile-panel-row">
      <span>
        {label} (…{fingerprint})
      </span>
      <span>
        <button
          type="button"
          className="btn btn-secondary"
          disabled={busy}
          onClick={() =>
            run(async () => setShownToken({ scope, value: await revealManagementToken(scope) }))
          }
        >
          {t('mobile.mgmt.show', 'Show')}
        </button>{' '}
        <button
          type="button"
          className="btn btn-secondary"
          disabled={busy}
          onClick={() =>
            run(async () => setShownToken({ scope, value: await rotateManagementToken(scope) }))
          }
        >
          {t('mobile.mgmt.rotate', 'Rotate')}
        </button>
      </span>
    </div>
  );

  return (
    <section className="mobile-panel settings-section" aria-label="Android and management API">
      {platform?.isAndroid && (
        <div className="mobile-panel">
          <h3>{t('mobile.service.title', 'Android background service')}</h3>
          <p>
            {t(
              'mobile.service.desc',
              'Keeps the local gateway and management API running with a visible notification. Android may still stop it (battery saver, OEM task killers), so 24/7 uptime is not guaranteed.',
            )}
          </p>
          <div className="mobile-panel-row">
            <span>
              {platform.serviceEnabled
                ? t('mobile.service.on', 'Foreground service: ON')
                : t('mobile.service.off', 'Foreground service: OFF')}
            </span>
            <button
              type="button"
              className="btn btn-secondary"
              disabled={busy}
              onClick={() => run(() => setAndroidServiceEnabled(!platform.serviceEnabled))}
            >
              {platform.serviceEnabled
                ? t('mobile.service.turnOff', 'Turn off')
                : t('mobile.service.turnOn', 'Turn on')}
            </button>
          </div>
          {!platform.notificationPermission && (
            <div className="mobile-panel-row">
              <span>{t('mobile.service.notifPermission', 'Notification permission not granted')}</span>
              <button
                type="button"
                className="btn btn-secondary"
                disabled={busy}
                onClick={() => run(requestAndroidNotificationPermission)}
              >
                {t('mobile.service.grant', 'Allow')}
              </button>
            </div>
          )}
          <div className="mobile-panel-row">
            <span>
              {t('mobile.keystore', 'Android Keystore')}:{' '}
              {platform.keystoreAvailable
                ? t('mobile.keystoreOk', 'protecting stored credentials')
                : t('mobile.keystoreMissing', 'unavailable')}
            </span>
          </div>
        </div>
      )}

      <div className="mobile-panel">
        <h3>{t('mobile.mgmt.title', 'Management API / MCP (for Claude Code)')}</h3>
        <p>
          {t(
            'mobile.mgmt.desc',
            'A token-protected API on localhost that lets Claude Code inspect accounts, quota and gateway health. It is OFF by default and never returns OAuth tokens or API keys. Claude.ai web/mobile cannot reach a local MCP server; use Claude Code (for example in Termux, or on a PC via adb forward).',
          )}
        </p>
        {status && (
          <>
            <div className="mobile-panel-row">
              <span>
                {status.running
                  ? t('mobile.mgmt.running', 'Running on {{url}}', { url: status.mcpUrl })
                  : t('mobile.mgmt.stopped', 'Stopped')}
              </span>
              <button
                type="button"
                className="btn btn-secondary"
                disabled={busy}
                onClick={() => run(() => updateManagementSettings({ enabled: !status.enabled }))}
              >
                {status.enabled ? t('mobile.mgmt.disable', 'Disable') : t('mobile.mgmt.enable', 'Enable')}
              </button>
            </div>

            {tokenRow('read', t('mobile.mgmt.readToken', 'Read token'), status.readTokenFingerprint)}
            {tokenRow('control', t('mobile.mgmt.controlToken', 'Control token'), status.controlTokenFingerprint)}
            {shownToken && (
              <div>
                <div className="mobile-panel-token" data-testid="management-token">
                  {shownToken.value}
                </div>
                <div className="mobile-panel-row">
                  <button type="button" className="btn btn-secondary" onClick={() => void copy(shownToken.value)}>
                    {t('mobile.copy', 'Copy')}
                  </button>
                  <button type="button" className="btn btn-secondary" onClick={() => setShownToken(null)}>
                    {t('mobile.hide', 'Hide')}
                  </button>
                </div>
              </div>
            )}

            <div className="mobile-panel-row">
              <span>{t('mobile.mgmt.control', 'Allow Claude to change settings')}</span>
              <span>
                {status.controlGranted
                  ? t('mobile.mgmt.grantedFor', 'granted ({{m}} min left)', { m: grantRemaining })
                  : t('mobile.mgmt.notGranted', 'not granted')}
              </span>
            </div>
            <div className="mobile-panel-row">
              {[15, 60].map((minutes) => (
                <button
                  key={minutes}
                  type="button"
                  className="btn btn-secondary"
                  disabled={busy || !status.enabled}
                  onClick={() => run(() => setManagementControlGrant(minutes))}
                >
                  {t('mobile.mgmt.grantMinutes', 'Grant {{m}} min', { m: minutes })}
                </button>
              ))}
              <button
                type="button"
                className="btn btn-secondary"
                disabled={busy || !status.controlGranted}
                onClick={() => run(() => setManagementControlGrant(0))}
              >
                {t('mobile.mgmt.revoke', 'Revoke')}
              </button>
            </div>
            <p>
              {t(
                'mobile.mgmt.controlHint',
                'Even with a grant, every change needs the control token and an explicit confirm. Allowed routing strategies: {{list}}.',
                { list: status.allowedRoutingStrategies.join(', ') },
              )}
            </p>

            <label className="mobile-panel-row">
              <span>{t('mobile.mgmt.revealEmail', 'Show full e-mail addresses to the API')}</span>
              <input
                type="checkbox"
                checked={status.revealEmail}
                disabled={busy}
                onChange={(e) => run(() => updateManagementSettings({ revealEmail: e.target.checked }))}
              />
            </label>
            <label className="mobile-panel-row">
              <span>{t('mobile.mgmt.lan', 'Expose on the local network (not recommended)')}</span>
              <input
                type="checkbox"
                checked={status.bindLan}
                disabled={busy}
                onChange={(e) => {
                  const next = e.target.checked;
                  if (
                    next &&
                    !window.confirm(
                      t(
                        'mobile.mgmt.lanConfirm',
                        'Anyone on your network holding the token could query this device. HTTP is not encrypted. Continue?',
                      ),
                    )
                  ) {
                    return;
                  }
                  void run(() => updateManagementSettings({ bindLan: next }));
                }}
              />
            </label>

            <div>
              <div>{t('mobile.mgmt.connect', 'Connect Claude Code')}:</div>
              <div className="mobile-panel-token">{mcpCommand}</div>
              <button type="button" className="btn btn-secondary" onClick={() => void copy(mcpCommand)}>
                {t('mobile.copy', 'Copy')}
              </button>
            </div>

            <details>
              <summary>
                {t('mobile.mgmt.audit', 'Recent API activity')} ({audit.length})
              </summary>
              <ul>
                {audit.map((entry, index) => (
                  <li key={`${entry.timestamp}-${index}`}>
                    {new Date(entry.timestamp).toLocaleTimeString()} · {entry.tool} · {entry.scope} ·{' '}
                    {entry.outcome} {entry.detail}
                  </li>
                ))}
              </ul>
            </details>
          </>
        )}
        {message && <p role="status">{message}</p>}
      </div>
    </section>
  );
}
