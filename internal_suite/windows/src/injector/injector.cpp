#include "injector.h"

namespace psj
{
    Injector::Injector()
        : m_NtCreateSection(nullptr)
        , m_NtMapViewOfSection(nullptr)
        , m_NtUnmapViewOfSection(nullptr)
        , m_NtAllocateVirtualMemory(nullptr)
        , m_NtReadVirtualMemory(nullptr)
        , m_NtWriteVirtualMemory(nullptr)
        , m_RtlCreateUserThread(nullptr)
    {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");

        if (ntdll == nullptr)
            return;

        m_NtCreateSection = (PFN_NtCreateSection)GetProcAddress(ntdll, "NtCreateSection");
        m_NtMapViewOfSection = (PFN_NtMapViewOfSection)GetProcAddress(ntdll, "NtMapViewOfSection");
        m_NtUnmapViewOfSection = (PFN_NtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");
        m_NtAllocateVirtualMemory = (PFN_NtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
        m_NtReadVirtualMemory = (PFN_NtReadVirtualMemory)GetProcAddress(ntdll, "NtReadVirtualMemory");
        m_NtWriteVirtualMemory = (PFN_NtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");
        m_RtlCreateUserThread = (PFN_RtlCreateUserThread)GetProcAddress(ntdll, "RtlCreateUserThread");
    }

    Injector::~Injector()
    {
    }

    NTSTATUS Injector::PsjNtCreateSection(
        _Out_ PHANDLE sectionHandle,
        _In_ ACCESS_MASK desiredAccess,
        _In_opt_ POBJECT_ATTRIBUTES objectAttributes,
        _In_opt_ PLARGE_INTEGER maximumSize,
        _In_ ULONG sectionPageProtection,
        _In_ ULONG allocationAttributes,
        _In_opt_ HANDLE fileHandle)
    {
        if (m_NtCreateSection == nullptr)
            return STATUS_PROCEDURE_NOT_FOUND;

        return m_NtCreateSection(
            sectionHandle,
            desiredAccess,
            objectAttributes,
            maximumSize,
            sectionPageProtection,
            allocationAttributes,
            fileHandle);
    }

    NTSTATUS Injector::PsjNtMapViewOfSection(
        _In_ HANDLE sectionHandle,
        _In_ HANDLE processHandle,
        _Inout_ _At_(*baseAddress, _Readable_bytes_(*viewSize) _Writable_bytes_(*viewSize) _Post_readable_byte_size_(*viewSize)) PVOID* baseAddress,
        _In_ ULONG_PTR zeroBits,
        _In_ SIZE_T commitSize,
        _Inout_opt_ PLARGE_INTEGER sectionOffset,
        _Inout_ PSIZE_T viewSize,
        _In_ SECTION_INHERIT inheritDisposition,
        _In_ ULONG allocationType,
        _In_ ULONG pageProtection)
    {
        if (m_NtMapViewOfSection == nullptr)
            return STATUS_PROCEDURE_NOT_FOUND;

        return m_NtMapViewOfSection(
            sectionHandle,
            processHandle,
            baseAddress,
            zeroBits,
            commitSize,
            sectionOffset,
            viewSize,
            inheritDisposition,
            allocationType,
            pageProtection);
    }

    NTSTATUS Injector::PsjNtUnmapViewOfSection(
        _In_ HANDLE processHandle,
        _In_opt_ PVOID baseAddress)
    {
        if (m_NtUnmapViewOfSection == nullptr)
            return STATUS_PROCEDURE_NOT_FOUND;

        return m_NtUnmapViewOfSection(
            processHandle,
            baseAddress);
    }

    NTSTATUS Injector::PsjNtAllocateVirtualMemory(
        _In_ HANDLE processHandle,
        _Inout_ _At_(*baseAddress, _Readable_bytes_(*regionSize) _Writable_bytes_(*regionSize) _Post_readable_byte_size_(*regionSize)) PVOID* baseAddress,
        _In_ ULONG_PTR zeroBits,
        _Inout_ PSIZE_T regionSize,
        _In_ ULONG allocationType,
        _In_ ULONG pageProtection)
    {
        if (m_NtAllocateVirtualMemory == nullptr)
            return STATUS_PROCEDURE_NOT_FOUND;

        return m_NtAllocateVirtualMemory(
            processHandle,
            baseAddress,
            zeroBits,
            regionSize,
            allocationType,
            pageProtection);
    }

    NTSTATUS Injector::PsjNtReadVirtualMemory(
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

    NTSTATUS Injector::PsjNtWriteVirtualMemory(
        _In_ HANDLE processHandle,
        _In_opt_ PVOID baseAddress,
        _In_reads_bytes_(numberOfBytesToWrite) PVOID buffer,
        _In_ SIZE_T numberOfBytesToWrite,
        _Out_opt_ PSIZE_T numberOfBytesWritten)
    {
        if (m_NtWriteVirtualMemory == nullptr)
            return STATUS_PROCEDURE_NOT_FOUND;

        return m_NtWriteVirtualMemory(
            processHandle,
            baseAddress,
            buffer,
            numberOfBytesToWrite,
            numberOfBytesWritten);
    }

    NTSTATUS Injector::PsjRtlCreateUserThread(
        _In_ HANDLE processHandle,
        _In_opt_ PSECURITY_DESCRIPTOR securityDescriptor,
        _In_ BOOLEAN createSuspended,
        _In_ ULONG stackZeroBits,
        _In_ SIZE_T stackReserve,
        _In_ SIZE_T stackCommit,
        _In_ PUSER_THREAD_START_ROUTINE startAddress,
        _In_opt_ PVOID parameter,
        _Out_ PHANDLE threadHandle,
        _Out_opt_ PPSJ_CLIENT_ID clientId)
    {
        if (m_RtlCreateUserThread == nullptr)
            return STATUS_PROCEDURE_NOT_FOUND;

        return m_RtlCreateUserThread(
            processHandle,
            securityDescriptor,
            createSuspended,
            stackZeroBits,
            stackReserve,
            stackCommit,
            startAddress,
            parameter,
            threadHandle,
            clientId);
    }

    bool Injector::InjectDllIntoProcess(HANDLE processHandle, const std::string& dllName)
    {
        return false;
    }

    bool Injector::Injection(DWORD processId, const std::string& dllName)
    {
        HANDLE processHandle = OpenProcess(
            PROCESS_CREATE_THREAD
            | PROCESS_QUERY_INFORMATION
            | PROCESS_VM_OPERATION
            | PROCESS_VM_WRITE
            | PROCESS_VM_READ,
            FALSE,
            (DWORD)(ULONG_PTR)processId);

        if (processHandle == nullptr)
            return false;

        bool ret = InjectDllIntoProcess(processHandle, dllName);

        if (processHandle != nullptr)
            CloseHandle(processHandle);

        return ret;
    }
}