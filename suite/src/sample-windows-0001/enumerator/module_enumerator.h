#pragma once

#include "../platform/windows_def.h"

namespace psj
{
    typedef bool (NTAPI * PPSJ_ENUM_PROCESS_MODULES_CALLBACK)(_In_ PLDR_DATA_TABLE_ENTRY module, _In_opt_ PVOID context);

    class ModuleEnumerator
    {
    private:
        PFN_NtQueryInformationProcess m_NtQueryInformationProcess;
        PFN_NtQueryVirtualMemory m_NtQueryVirtualMemory;
        PFN_NtReadVirtualMemory m_NtReadVirtualMemory;
        PFN_RtlNtPathNameToDosPathName m_RtlNtPathNameToDosPathName;

    private:
        HANDLE m_processHandle;
        PPSJ_ENUM_PROCESS_MODULES_CALLBACK m_callback;
        PVOID m_context;

    private:
        NTSTATUS PsjNtQueryInformationProcess(
            _In_ HANDLE processHandle,
            _In_ PROCESSINFOCLASS processInformationClass,
            _Out_writes_bytes_(processInformationLength) PVOID processInformation,
            _In_ ULONG processInformationLength,
            _Out_opt_ PULONG returnLength);

        NTSTATUS PsjNtQueryVirtualMemory(
            _In_ HANDLE processHandle,
            _In_ PVOID baseAddress,
            _In_ MEMORY_INFORMATION_CLASS memoryInformationClass,
            _Out_writes_bytes_(memoryInformationLength) PVOID memoryInformation,
            _In_ SIZE_T memoryInformationLength,
            _Out_opt_ PSIZE_T returnLength);

        NTSTATUS PsjNtReadVirtualMemory(
            _In_ HANDLE processHandle,
            _In_opt_ PVOID baseAddress,
            _Out_writes_bytes_to_(numberOfBytesToRead, *numberOfBytesRead) PVOID buffer,
            _In_ SIZE_T numberOfBytesToRead,
            _Out_opt_ PSIZE_T numberOfBytesRead);

        NTSTATUS PsjRtlNtPathNameToDosPathName(
            __in ULONG flags,
            __inout PRTL_UNICODE_STRING_BUFFER path,
            __out_opt PULONG disposition,
            __inout_opt PWSTR* filePart);

    private:
        bool EnumProcessModules32();
        bool EnumProcessModules64();

    public:
        ModuleEnumerator(
            _In_ HANDLE processHandle, 
            _In_ PPSJ_ENUM_PROCESS_MODULES_CALLBACK callback,
            _In_opt_ PVOID context);
        virtual ~ModuleEnumerator();

        bool EnumProcessModules();

        static bool GetProcedureAddressRemoteCallback(_In_ PLDR_DATA_TABLE_ENTRY module, _In_opt_ PVOID context);
    };
}