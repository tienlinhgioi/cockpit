import { invoke } from '@tauri-apps/api/core';

export interface AndroidPlatformStatus {
  isAndroid: boolean;
  serviceEnabled: boolean;
  notificationPermission: boolean;
  keystoreAvailable: boolean;
  filesDir?: string | null;
}

export interface ManagementStatus {
  enabled: boolean;
  running: boolean;
  port: number;
  bindLan: boolean;
  revealEmail: boolean;
  controlGrantedUntil?: number | null;
  controlGranted: boolean;
  mcpUrl: string;
  readTokenFingerprint: string;
  controlTokenFingerprint: string;
  allowedRoutingStrategies: string[];
}

export interface ManagementSettingsUpdate {
  enabled?: boolean;
  port?: number;
  bindLan?: boolean;
  revealEmail?: boolean;
}

export interface ManagementAuditEntry {
  timestamp: number;
  tool: string;
  scope: string;
  outcome: string;
  detail: string;
}

export type ManagementScope = 'read' | 'control';

export const getAndroidPlatformStatus = () =>
  invoke<AndroidPlatformStatus>('android_platform_status');
export const setAndroidServiceEnabled = (enabled: boolean) =>
  invoke<AndroidPlatformStatus>('android_service_set_enabled', { enabled });
export const requestAndroidNotificationPermission = () =>
  invoke<void>('android_request_notification_permission');

export const getManagementStatus = () => invoke<ManagementStatus>('management_api_get_status');
export const updateManagementSettings = (update: ManagementSettingsUpdate) =>
  invoke<ManagementStatus>('management_api_update_settings', { update });
export const setManagementControlGrant = (minutes: number) =>
  invoke<ManagementStatus>('management_api_set_control_grant', { minutes });
export const revealManagementToken = (scope: ManagementScope) =>
  invoke<string>('management_api_reveal_token', { scope });
export const rotateManagementToken = (scope: ManagementScope) =>
  invoke<string>('management_api_rotate_token', { scope });
export const getManagementAuditLog = () =>
  invoke<ManagementAuditEntry[]>('management_api_audit_log');
