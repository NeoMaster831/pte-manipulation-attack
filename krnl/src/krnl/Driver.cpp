#include <ntddk.h>
#include <intrin.h>

#define LogInfo(fmt, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, fmt, __VA_ARGS__)

// Define the PTE structure
typedef struct _PGT_ENTRY
{
    ULONG64 Valid : 1;            // [0]
    ULONG64 Write : 1;            // [1]
    ULONG64 Owner : 1;            // [2]
    ULONG64 WriteThrough : 1;     // [3]
    ULONG64 CacheDisabled : 1;    // [4]
    ULONG64 Accessed : 1;         // [5]
    ULONG64 Dirty : 1;            // [6]
    ULONG64 LargePage : 1;        // [7]
    ULONG64 Global : 1;           // [8]
    ULONG64 CopyOnWrite : 1;      // [9]
    ULONG64 Prototype : 1;        // [10]
    ULONG64 Reserved0 : 1;        // [11]
    ULONG64 PageFrameNumber : 40; // [12-51]
    ULONG64 SoftwareWsIndex : 11; // [52-62]
    ULONG64 NoExecute : 1;        // [63]
} PGT_ENTRY, *PPGT_ENTRY;

uintptr_t MmPteBase = 0;
uintptr_t MmPdeBase = 0;
uintptr_t MmPpeBase = 0;
uintptr_t MmPxeBase = 0;
uintptr_t KernelBase = 0;

uintptr_t GetKernelBase()
{
    UNICODE_STRING exQueueWorkItemName = RTL_CONSTANT_STRING(L"ExQueueWorkItem");
    auto exQueueWorkItemPtr = MmGetSystemRoutineAddress(&exQueueWorkItemName);
    if (!exQueueWorkItemPtr)
    {
        LogInfo("Failed to get ExQueueWorkItem address.\n");
        return 0;
    }
    uintptr_t kernelBase = (uintptr_t)exQueueWorkItemPtr - 0x361810; // Adjust based on the known offset
    return kernelBase;
}

PPGT_ENTRY MiGetPteAddress(IN PVOID VirtualAddress)
{
    return (PPGT_ENTRY)(MmPteBase + (((ULONG_PTR)VirtualAddress >> 9) & 0x7FFFFFFFF8));
}
PPGT_ENTRY MiGetPdeAddress(IN PVOID VirtualAddress)
{
    return (PPGT_ENTRY)(MmPdeBase + (((ULONG_PTR)VirtualAddress >> 18) & 0x3FFFFFF8));
}
PPGT_ENTRY MiGetPpeAddress(IN PVOID VirtualAddress)
{
    return (PPGT_ENTRY)(MmPpeBase + (((ULONG_PTR)VirtualAddress >> 27) & 0x1FFFF8));
}
PPGT_ENTRY MiGetPxeAddress(IN PVOID VirtualAddress)
{
    return ((PPGT_ENTRY)MmPxeBase + (((ULONG_PTR)VirtualAddress >> 39) & 0x1FF));
}

PPGT_ENTRY GetLastPageTable(PVOID address)
{
    PPGT_ENTRY pxe = MiGetPxeAddress(address);
    if (!MmIsAddressValid(pxe) || !pxe->Valid)
        return nullptr;
    
    PPGT_ENTRY ppe = MiGetPpeAddress(address);
    if (!MmIsAddressValid(ppe) || !ppe->Valid)
        return nullptr;
    
    if (ppe->LargePage)
        return ppe;
    
    PPGT_ENTRY pde = MiGetPdeAddress(address);
    if (!MmIsAddressValid(pde) || !pde->Valid)
        return nullptr;
    
    if (pde->LargePage)
        return pde;
    
    PPGT_ENTRY pte = MiGetPteAddress(address);
    if (!MmIsAddressValid(pte) || !pte->Valid)
        return nullptr;
    
    return pte;
}

bool IsKernelAddress(PVOID address)
{
    return ((uintptr_t)address >= 0xFFFF'8000'0000'0000 && (uintptr_t)address < 0xFFFF'FFFF'FFFF'FFFF);
}

bool HasWriteAccess(PVOID address)
{
    if (!MmIsAddressValid(address))
        return false;
    
    PPGT_ENTRY pte = GetLastPageTable(address);
    if (!pte)
        return false;
    
    return (pte->Valid && pte->Write && (!pte->CopyOnWrite || pte->Dirty));
}

// IOCTL definitions
#define IOCTL_ORACLE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VERIFY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _ORACLE_INPUT
{
    ULONG64 Where;
    ULONG64 What;
} ORACLE_INPUT, *PORACLE_INPUT;

NTSTATUS VulnOracle(_In_ ORACLE_INPUT *input)
{
    // Check if the address is a kernel address and has write access
    if (IsKernelAddress((PVOID)input->Where) && !HasWriteAccess((PVOID)input->Where))
        return STATUS_ACCESS_VIOLATION;

    *(volatile ULONG64 *)input->Where ^= input->What;
    return STATUS_SUCCESS;
}

typedef ULONG64 VERIFY_INPUT, *PVERIFY_INPUT;

NTSTATUS Verify(_In_ PVERIFY_INPUT input)
{
    if (*input != KernelBase) {
        return STATUS_INVALID_PARAMETER;
    }

    // Pwn
    auto process = (uintptr_t)PsGetCurrentProcess();
    auto system = (uintptr_t)PsInitialSystemProcess;
    *(ULONG64*)(process + 0x248) = *(ULONG64*)(system + 0x248); // Change Process' Token to System Token
    
    return STATUS_SUCCESS;
}

static void DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symbolicLinkName = RTL_CONSTANT_STRING(L"\\DosDevices\\krnl");
    IoDeleteSymbolicLink(&symbolicLinkName);
    if (DriverObject->DeviceObject)
    {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
    LogInfo("Driver unloaded successfully.\n");
}

static NTSTATUS DriverDefaultHandler(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_NOT_IMPLEMENTED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS DriverCreateCloseHandler(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DriverDeviceControlHandler(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inputBufferLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputBufferLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    switch (controlCode)
    {
    case IOCTL_ORACLE:
        if (inputBufferLength == sizeof(ORACLE_INPUT) && outputBufferLength == 0)
        {
            status = VulnOracle((PORACLE_INPUT)buffer);
        }
        else
        {
            status = STATUS_INVALID_PARAMETER;
        }
        break;
    case IOCTL_VERIFY:
        if (inputBufferLength == sizeof(VERIFY_INPUT) && outputBufferLength == 0)
        {
            status = Verify((PVERIFY_INPUT)buffer);
        }
        else
        {
            status = STATUS_INVALID_PARAMETER;
        }
        break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DriverUnload;

    KernelBase = GetKernelBase();
    LogInfo("Kernel Base: %llX", KernelBase);
    MmPteBase = *(uintptr_t *)(KernelBase + 0xFC4478); // Adjust based on the known offset
    size_t selfRefIndex = ((MmPteBase & 0x0000'FFFF'FFFF'FFFF) >> 39);
    MmPdeBase = MmPteBase + (selfRefIndex << 30);
    MmPpeBase = MmPdeBase + (selfRefIndex << 21);
    MmPxeBase = MmPpeBase + (selfRefIndex << 12);

    for (unsigned int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i)
    {
        DriverObject->MajorFunction[i] = DriverDefaultHandler;
    }
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDeviceControlHandler;

    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\krnl");
    UNICODE_STRING symbolicLinkName = RTL_CONSTANT_STRING(L"\\DosDevices\\krnl");
    PDEVICE_OBJECT deviceObject = nullptr;
    auto status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject);

    if (!NT_SUCCESS(status))
    {
        LogInfo("Failed to create device: %08X\n", status);
        return status;
    }

    status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);

    if (!NT_SUCCESS(status))
    {
        LogInfo("Failed to create symbolic link: %08X\n", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    LogInfo("Driver loaded successfully.\n");

    return STATUS_SUCCESS;
}