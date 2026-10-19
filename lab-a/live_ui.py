"""Presentation only: no collector, model, or Wazuh configuration changes."""
import os
import shutil
import sys

TITLE = 'AI Dashboard'
AUTHORS = 'By Hải Đăng - Hồng Thái - Quang Duy'


def enable_color(stream):
    if os.environ.get('NO_COLOR') is not None or not stream.isatty():
        return False
    if os.name != 'nt':
        return True
    try:
        import ctypes
        import msvcrt
        from ctypes import wintypes
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        handle = wintypes.HANDLE(msvcrt.get_osfhandle(stream.fileno()))
        mode = wintypes.DWORD()
        return bool(kernel.GetConsoleMode(handle, ctypes.byref(mode)) and
                    kernel.SetConsoleMode(handle, mode.value | 4))
    except (OSError, AttributeError, ValueError):
        return False


def line(text='', color=None):
    # Fall back to escaped characters if a redirected stream uses a legacy codec.
    encoding = getattr(sys.stdout, 'encoding', None) or 'utf-8'
    text = text.encode(encoding, errors='backslashreplace').decode(encoding)
    if color and enable_color(sys.stdout):
        text = '\033['+color+'m'+text+'\033[0m'
    print(text, flush=True)


def rule():
    line('─' * min(76, max(24, shutil.get_terminal_size((80, 24)).columns - 2)), '90')


def show_header():
    line()
    rule()
    line('  '+TITLE, '1;96')
    line('  '+AUTHORS, '97')
    line('  SOC Lab · Live monitoring · Event correlation', '90')
    rule()
    line('  KHỞI ĐỘNG', '1;94')
    line('  Đang kiểm tra mô hình, sensor và kết nối Wazuh…')


def show_runtime(args):
    line()
    line('  PHẠM VI & NGUỒN DỮ LIỆU', '1;94')
    if args.endpoints and not args.all_flows:
        line('  Bộ lọc IP do bạn chọn: '+str(args.endpoints), '33')
    else:
        line('  Mọi flow tại sensor đã cấu hình · Không lọc IP', '32')
    names = {'auth':'SSH / xác thực', 'eve':'Suricata EVE', 'wazuh':'Wazuh alerts',
             'web':'HTTP requests', 'raw':'Apache access'}
    for source in args.runtime['sources']:
        line('  '+names.get(source['kind'], source['kind'])+'  |  '+source['container'])
        line('    '+source['path'], '90')
    line('  Model: '+str(args.model), '90')
    line('  Wazuh: '+('bật gửi cảnh báo' if args.publish_wazuh else 'chỉ quan sát local'), '36')
    line()
    line('  QUY TRÌNH', '1;94')
    line('  Thu log → Chuẩn hóa → MLP & bằng chứng → Correlation → Wazuh')
    line()
    line('  LƯU Ý', '1;33')
    line('  • Chỉ quan sát nguồn đã cấu hình; chỉ thu log mới từ lúc bật AI.')
    line('  • MLP đang thử nghiệm; vẫn còn báo nhầm SSH bình thường.')
    line('  • SQLi được đối chiếu bằng HTTP/rule; MLP chưa có lớp SQLi.')
    line('  • Dự đoán không phải nhãn train hoặc bằng chứng đã chiếm quyền.')
    line('  • Flow có thể đến muộn sau timeout; HTTP/auth thường đến sớm hơn.')
    line('  • Ctrl+C tại đây để dừng; đợi LIVE_DONE trước khi đóng cửa sổ.')
    if args.heartbeat_seconds:
        line('  Bộ đếm định kỳ: mỗi '+str(args.heartbeat_seconds)+' giây.', '90')
    else:
        line('  Chỉ in khi có hoạt động hoặc thay đổi trạng thái.', '90')


def show_session(folder):
    line()
    line('  THƯ MỤC PHIÊN', '1;94')
    line('  '+str(folder))
    rule()
    line('  NHẬT KÝ TRỰC TIẾP', '1;96')
    line('  [HTTP] request  [SENSOR] rule  [AI] dự đoán  [CORRELATION] case', '90')
    line()


def show_footer():
    rule()
    line('LIVE_DONE: Đã đóng file đầu ra. Có thể đóng cửa sổ này.', '1;32')


if __name__ == '__main__':
    from types import SimpleNamespace
    line('BẢN XEM TRƯỚC — chưa kết nối sensor hoặc Wazuh.', '33')
    show_header()
    show_runtime(SimpleNamespace(endpoints=None, all_flows=True, publish_wazuh=True,
        heartbeat_seconds=0, model='…/mlp-lab-20261014-212857', runtime={'sources':[
        {'kind':'eve','container':'ubuntu-endpoint','path':'/var/log/suricata/eve.json'},
        {'kind':'web','container':'ubuntu-endpoint','path':'/var/log/apache2/soc-lab-requests.tsv'}]}))
    show_session('E:/SOC-Lab/AI/live/raw/<phiên mới>')
