#include "module_enumerator.h"

namespace psj
{
    ModuleEnumerator::ModuleEnumerator(
        _In_ HANDLE processHandle,
        _In_ PPSJ_ENUM_PROCESS_MODULES_CALLBACK callback,
        _In_opt_ PVOID context)
        : m_NtQueryInformationProcess(nullptr)
        , m_NtQueryVirtualMemory(nullptr)
        , m_NtReadVirtualMemory(nullptr)
        , m_RtlNtPathNameToDosPathName(nullptr)
        , m_processHandle(processHandle)
        , m_callback(callback)
        , m_context(context)
    {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

        if (ntdll == nullptr)
            return;

        m_NtQueryInformationProcess = (PFN_NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
        m_NtQueryVirtualMemory = (PFN_NtQueryVirtualMemory)GetProcAddress(ntdll, "NtQueryVirtualMemory");
        m_NtReadVirtualMemory = (PFN_NtReadVirtualMemory)GetProcAddress(ntdll, "NtReadVirtualMemory");
        m_RtlNtPathNameToDosPathName = (PFN_RtlNtPathNameToDosPathName)GetProcAddress(ntdll, "RtlNtPathNameToDosPathName");
    }

    ModuleEnumerator::~ModuleEnumerator()
    {
    }

    NTSTATUS ModuleEnumerator::PsjNtQueryInformationProcess(
        _In_ HANDLE processHandle,
        _In_ PROCESSINFOCLASS processInformationClass,
        _Out_writes_bytes_(processInformationLength) PVOID processInformation,
        _In_ ULONG processInformationLength,
        _Out_opt_ PULONG returnLength)
    {
        if (m_NtQueryInformationProcess == nullptr)
            return STATUS_PROCEDURE_NOT_FOUND;

        return m_NtQueryInformationProcess(
            processHandle,
            processInformationClass,
            processInformation,
            processInformationLength,
            returnLength);
    }

    NTSTATUS ModuleEnumerator::PsjNtQueryVirtualMemory(
        _In_ HANDLE processHandle,
        _In_ PVOID baseAddress,
        _In_ MEMORY_INFORMATION_CLASS memoryInformationClass,
        _Out_writes_bytes_(memoryInformationLength) PVOID memoryInformation,
        _In_ SIZE_T memoryInformationLength,
        _Out_opt_ PSIZE_T returnLength)
    {
        if (m_NtQueryVirtualMemory == nullptr)
            return STATUS_PROCEDURE_NOT_FOUND;

        return m_NtQueryVirtualMemory(
            processHandle,
            baseAddress,
            memoryInformationClass,
            memoryInformation,
            memoryInformationLength,
            returnLength);
    }

    NTSTATUS ModuleEnumerator::PsjNtReadVirtualMemory(
        _In_ HANDLE processHandle,
        _In_opt_ PVOID baseAddress,
        _Out_writes_bytes_to_(numberOfBytesToRead, *numberOfBytesRead) PVOID buffer,
        _In_ SIZE_T numberOfBytesToRead,
        _Out_opt_ PSIZE_T numberOfBytesRead)
    {
        if (m_NtReadVirtualMemory == nullptr)
            return STATUS_PROCEDURE_NOT_FOUND;

        return m_NtReadVirtualMemory(
            processHandle,
            baseAddress,
            buffer,
            numberOfBytesToRead,
            numberOfBytesRead);
    }

    NTSTATUS ModuleEnumerator::PsjRtlNtPathNameToDosPathName(
        __in ULONG flags,
        __inout PRTL_UNICODE_STRING_BUFFER path,
        __out_opt PULONG disposition,
        __inout_opt PWSTR* filePart)
    {
        if (m_RtlNtPathNameToDosPathName == nullptr)
            return STATUS_PROCEDURE_NOT_FOUND;

        return m_RtlNtPathNameToDosPathName(
            flags,
            path,
            disposition,
            filePart);
    }

    bool ModuleEnumerator::EnumProcessModules()
    {
        if (m_processHandle == nullptr)
            return false;

        bool status = EnumProcessModules64();

        BOOL wow64Process = FALSE;
        IsWow64Process(m_processHandle, &wow64Process);

        if (wow64Process)
            status = EnumProcessModules32();

        return status;
    }

    bool ModuleEnumerator::EnumProcessModules32()
    {
        return false;
    }

    bool ModuleEnumerator::EnumProcessModules64()
    {
        return false;
    }

    bool ModuleEnumerator::GetProcedureAddressRemoteCallback(
        _In_ PLDR_DATA_TABLE_ENTRY module,
        _In_opt_ PVOID context)
    {
        return false;
    }
}