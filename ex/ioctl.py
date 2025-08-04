import ctypes
from ctypes import wintypes

# Constants for CreateFile
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080

# Constants for CTL_CODE
FILE_DEVICE_UNKNOWN = 0x00000022
METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0
FILE_READ_ACCESS = 0x0001
FILE_WRITE_ACCESS = 0x0002

def CTL_CODE(device_type, function, method, access):
    return (device_type << 16) | (access << 14) | (function << 2) | method

CreateFileW = ctypes.windll.kernel32.CreateFileW
DeviceIoControl = ctypes.windll.kernel32.DeviceIoControl
CloseHandle = ctypes.windll.kernel32.CloseHandle

CreateFileW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
    wintypes.HANDLE
]
CreateFileW.restype = wintypes.HANDLE

DeviceIoControl.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPVOID
]
DeviceIoControl.restype = wintypes.BOOL

CloseHandle.argtypes = [wintypes.HANDLE]
CloseHandle.restype = wintypes.BOOL

INVALID_HANDLE_VALUE = 2 ** 64 - 1

class KernelDevice:
    def __init__(self, device_name):
        self.device_name = device_name
        self.handle = INVALID_HANDLE_VALUE

    def open(self):
        self.handle = CreateFileW(
            self.device_name,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None
        )
        if self.handle == INVALID_HANDLE_VALUE:
            raise ctypes.WinError()
        return self.handle != INVALID_HANDLE_VALUE

    def close(self):
        if self.handle != INVALID_HANDLE_VALUE:
            CloseHandle(self.handle)
            self.handle = INVALID_HANDLE_VALUE

    def ioctl(self, control_code, in_buffer=None, out_buffer_size=0):
        if self.handle == INVALID_HANDLE_VALUE:
            raise ValueError("Device not opened.")

        in_buffer_ptr = None
        in_buffer_len = 0
        if in_buffer:
            in_buffer_len = len(in_buffer)
            in_buffer_ptr = ctypes.create_string_buffer(in_buffer, in_buffer_len)

        out_buffer = ctypes.create_string_buffer(out_buffer_size)
        bytes_returned = wintypes.DWORD(0)

        success = DeviceIoControl(
            self.handle,
            control_code,
            in_buffer_ptr,
            in_buffer_len,
            out_buffer,
            out_buffer_size,
            ctypes.byref(bytes_returned),
            None
        )

        if not success:
            raise ctypes.WinError()

        return out_buffer.raw[:bytes_returned.value]

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()