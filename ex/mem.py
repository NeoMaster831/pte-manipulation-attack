
import ctypes
from ctypes import wintypes

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40
MEM_RELEASE = 0x8000

VirtualAlloc = ctypes.windll.kernel32.VirtualAlloc
VirtualFree = ctypes.windll.kernel32.VirtualFree

VirtualAlloc.argtypes = [
    wintypes.LPVOID,  # lpAddress
    ctypes.c_size_t,  # dwSize
    wintypes.DWORD,   # flAllocationType
    wintypes.DWORD    # flProtect
]
VirtualAlloc.restype = wintypes.LPVOID

VirtualFree.argtypes = [
    wintypes.LPVOID,  # lpAddress
    ctypes.c_size_t,  # dwSize
    wintypes.DWORD    # dwFreeType
]
VirtualFree.restype = wintypes.BOOL

def allocate_lowlevel_buffer(size) -> int:
    if size <= 0:
        raise ValueError("Size must be greater than 0")
    
    address = VirtualAlloc(
        None,                          # lpAddress - 시스템이 주소 결정
        size,                          # dwSize - 할당할 크기
        MEM_COMMIT | MEM_RESERVE,      # flAllocationType - 커밋하고 예약
        PAGE_EXECUTE_READWRITE         # flProtect - 읽기/쓰기 권한
    )
    
    if not address:
        raise ctypes.WinError()
    
    return address

def free_lowlevel_buffer(address: int) -> bool:
    if address == 0:
        return False
    
    result = VirtualFree(
        address,     # lpAddress - 해제할 주소
        0,           # dwSize - 0으로 설정 (전체 할당 영역 해제)
        MEM_RELEASE  # dwFreeType - 메모리 해제
    )
    
    return bool(result)

def write_memory(address: int, data: bytes):
    if address == 0 or not data:
        raise ValueError("Invalid address or data")
    ctypes.memmove(address, data, len(data))

def read_memory(address: int, size: int) -> bytes:
    if address == 0 or size <= 0:
        raise ValueError("Invalid address or size")
    buffer = (ctypes.c_char * size)()
    ctypes.memmove(buffer, address, size)
    return bytes(buffer)