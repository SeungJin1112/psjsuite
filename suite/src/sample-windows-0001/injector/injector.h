#pragma once

#include "../platform/windows_def.h"

#include <algorithm>
#include <string>

#include "../enumerator/module_enumerator.h"

namespace psj
{
    class Injector
    {
    private:
        PFN_NtCreateSection m_NtCreateSection;
        PFN_NtMapViewOfSection m_NtMapViewOfSection;
        PFN_NtUnmapViewOfSection m_NtUnmapViewOfSection;
        PFN_NtAllocateVirtualMemory m_NtAllocateVirtualMemory;
        PFN_NtReadVirtualMemory m_NtReadVirtualMemory;
        PFN_NtWriteVirtualMemory m_NtWriteVirtualMemory;
        PFN_RtlCreateUserThread m_RtlCreateUserThread;

    private:
        NTSTATUS PsjNtCreateSection(
            _Out_ PHANDLE sectionHandle,
            _In_ ACCESS_MASK desiredAccess,
            _In_opt_ POBJECT_ATTRIBUTES objectAttributes,
            _In_opt_ PLARGE_INTEGER maximumSize,
            _In_ ULONG sectionPageProtection,
            _In_ ULONG allocationAttributes,
            _In_opt_ HANDLE fileHandle);

        NTSTATUS PsjNtMapViewOfSection(
            _In_ HANDLE sectionHandle,
            _In_ HANDLE processHandle,
            _Inout_ _At_(*baseAddress, _Readable_bytes_(*viewSize) _Writable_bytes_(*viewSize) _Post_readable_byte_size_(*viewSize)) PVOID *baseAddress,
            _In_ ULONG_PTR zeroBits,
            _In_ SIZE_T commitSize,
            _Inout_opt_ PLARGE_INTEGER sectionOffset,
            _Inout_ PSIZE_T viewSize,
            _In_ SECTION_INHERIT inheritDisposition,
            _In_ ULONG allocationType,
            _In_ ULONG pageProtection);

        NTSTATUS PsjNtUnmapViewOfSection(
            _In_ HANDLE processHandle,
            _In_opt_ PVOID baseAddress);

        NTSTATUS PsjNtAllocateVirtualMemory(
            _In_ HANDLE processHandle,
            _Inout_ _At_(*baseAddress, _Readable_bytes_(*regionSize) _Writable_bytes_(*regionSize) _Post_readable_byte_size_(*regionSize)) PVOID *baseAddress,
            _In_ ULONG_PTR zeroBits,
            _Inout_ PSIZE_T regionSize,
            _In_ ULONG allocationType,
            _In_ ULONG pageProtection);

        NTSTATUS PsjNtReadVirtualMemory(
            _In_ HANDLE processHandle,
            _In_opt_ PVOID baseAddress,
            _Out_writes_bytes_to_(numberOfBytesToRead, *numberOfBytesRead) PVOID buffer,
            _In_ SIZE_T numberOfBytesToRead,
            _Out_opt_ PSIZE_T numberOfBytesRead);

        NTSTATUS PsjNtWriteVirtualMemory(
            _In_ HANDLE processHandle,
            _In_opt_ PVOID baseAddress,
            _In_reads_bytes_(numberOfBytesToWrite) PVOID buffer,
            _In_ SIZE_T numberOfBytesToWrite,
            _Out_opt_ PSIZE_T numberOfBytesWritten);

        NTSTATUS PsjRtlCreateUserThread(
            _In_ HANDLE processHandle,
            _In_opt_ PSECURITY_DESCRIPTOR threadSecurityDescriptor,
            _In_ BOOLEAN createSuspended,
            _In_opt_ ULONG zeroBits,
            _In_opt_ SIZE_T maximumStackSize,
            _In_opt_ SIZE_T committedStackSize,
            _In_ PUSER_THREAD_START_ROUTINE startAddress,
            _In_opt_ PVOID parameter,
            _Out_opt_ PHANDLE threadHandle,
            _Out_opt_ PPSJ_CLIENT_ID clientId);

    private:
        bool LoadMappedImage(
            _In_opt_ PWSTR fileName,
            _In_opt_ HANDLE fileHandle,
            _In_ BOOLEAN readOnly,
            _Out_ PPSJ_MAPPED_IMAGE mappedImage);

        bool MapViewOfEntireFile(
            _In_opt_ PWSTR fileName,
            _In_opt_ HANDLE fileHandle,
            _In_ BOOLEAN readOnly,
            _Out_ PVOID *viewBase,
            _Out_ PSIZE_T size);

        bool InitializeMappedImage(
            _Out_ PPSJ_MAPPED_IMAGE mappedImage,
            _In_ PVOID viewBase,
            _In_ SIZE_T size);

        bool MappedImageProbe(
            _In_ PPSJ_MAPPED_IMAGE mappedImage,
            _In_ PVOID address,
            _In_ SIZE_T length);

        bool ProbeAddress(
            _In_ PVOID userAddress,
            _In_ SIZE_T userLength,
            _In_ PVOID bufferAddress,
            _In_ SIZE_T bufferLength,
            _In_ ULONG alignment);

        bool GetProcedureAddressRemote(
            _In_ HANDLE processHandle,
            _In_ PWSTR fileName,
            _In_opt_ PSTR procedureName,
            _In_opt_ ULONG procedureNumber,
            _Out_ PVOID *procedureAddress,
            _Out_opt_ PVOID *dllBase);

        bool GetMappedImageExports(
            _Out_ PPSJ_MAPPED_IMAGE_EXPORTS exports,
            _In_ PPSJ_MAPPED_IMAGE mappedImage);

        bool GetMappedImageDataEntry(
            _In_ PPSJ_MAPPED_IMAGE mappedImage,
            _In_ ULONG index,
            _Out_ PPSJ_IMAGE_DATA_DIRECTORY *entry);

        PVOID MappedImageRvaToVa(
            _In_ PPSJ_MAPPED_IMAGE mappedImage,
            _In_ ULONG rva,
            _Out_opt_ PPSJ_IMAGE_SECTION_HEADER *section);

        PPSJ_IMAGE_SECTION_HEADER MappedImageRvaToSection(
            _In_ PPSJ_MAPPED_IMAGE mappedImage,
            _In_ ULONG rva);

        bool GetMappedImageExportFunctionRemote(
            _In_ PPSJ_MAPPED_IMAGE_EXPORTS exports,
            _In_opt_ PSTR name,
            _In_opt_ USHORT ordinal,
            _In_ PVOID remoteBase,
            _Out_ PVOID *function);

        ULONG LookupMappedImageExportName(
            _In_ PPSJ_MAPPED_IMAGE_EXPORTS exports,
            _In_ PSTR name);

    private:
        bool InjectDllIntoProcess(HANDLE processHandle, const std::wstring &dllName);

    public:
        Injector();
        virtual ~Injector();

        bool Injection(DWORD processId, const std::wstring &dllName);
    };
}