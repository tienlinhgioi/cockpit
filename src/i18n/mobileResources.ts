import i18n from 'i18next';

/**
 * Strings for the Android / Management API panel. Kept out of src/locales/*.json so the
 * upstream locale-parity tooling is not affected; English is also the in-code default of
 * every `t('mobile.…', 'English')` call, so a missing language simply falls back to English.
 */
const vi = {
  copied: 'Đã sao chép',
  copy: 'Sao chép',
  hide: 'Ẩn',
  keystoreOk: 'đang bảo vệ thông tin xác thực đã lưu',
  keystoreMissing: 'không khả dụng',
  service: {
    title: 'Dịch vụ nền Android',
    desc: 'Giữ gateway cục bộ và API quản trị chạy với thông báo hiển thị. Android vẫn có thể dừng dịch vụ (tiết kiệm pin, trình dọn dẹp của hãng), nên không đảm bảo chạy 24/7.',
    on: 'Dịch vụ foreground: BẬT',
    off: 'Dịch vụ foreground: TẮT',
    turnOn: 'Bật',
    turnOff: 'Tắt',
    notifPermission: 'Chưa cấp quyền thông báo',
    grant: 'Cho phép',
  },
  mgmt: {
    title: 'API quản trị / MCP (cho Claude Code)',
    desc: 'API trên localhost có bảo vệ bằng token, cho phép Claude Code xem tài khoản, quota và tình trạng gateway. Mặc định TẮT và không bao giờ trả về OAuth token hay API key. Claude.ai web/mobile không gọi được MCP cục bộ; hãy dùng Claude Code (ví dụ trong Termux, hoặc trên PC qua adb forward).',
    running: 'Đang chạy tại {{url}}',
    stopped: 'Đã dừng',
    enable: 'Bật',
    disable: 'Tắt',
    readToken: 'Token chỉ đọc',
    controlToken: 'Token điều khiển',
    show: 'Hiện',
    rotate: 'Đổi mới',
    control: 'Cho phép Claude thay đổi cài đặt',
    grantedFor: 'đã cấp (còn {{m}} phút)',
    notGranted: 'chưa cấp',
    grantMinutes: 'Cấp {{m}} phút',
    revoke: 'Thu hồi',
    controlHint:
      'Ngay cả khi đã cấp quyền, mọi thay đổi vẫn cần token điều khiển và xác nhận rõ ràng. Chiến lược định tuyến cho phép: {{list}}.',
    revealEmail: 'Hiện email đầy đủ cho API',
    lan: 'Mở ra mạng nội bộ (không khuyến nghị)',
    lanConfirm:
      'Bất kỳ ai trong mạng có token đều có thể truy vấn thiết bị này. HTTP không được mã hóa. Tiếp tục?',
    connect: 'Kết nối Claude Code',
    audit: 'Hoạt động API gần đây',
  },
};

export function registerMobileResources(): void {
  i18n.addResourceBundle('vi', 'translation', { mobile: vi }, true, false);
}
