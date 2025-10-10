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
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

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

    bool Injector::LoadMappedImage(
        _In_opt_ PWSTR fileName,
        _In_opt_ HANDLE fileHandle,
        _In_ BOOLEAN readOnly,
        _Out_ PPSJ_MAPPED_IMAGE mappedImage)
    {
        if (MapViewOfEntireFile(
            fileName,
            fileHandle,
            readOnly,
            &mappedImage->view_base,
            (size_t*)&mappedImage->size) == false)
            return false;

        if (InitializeMappedImage(
            mappedImage,
            mappedImage->view_base,
            mappedImage->size) == false)
        {
            PsjNtUnmapViewOfSection(NtCurrentProcess(), mappedImage->view_base);
            return false;
        }

        return true;
    }

    bool Injector::MapViewOfEntireFile(
        _In_opt_ PWSTR fileName,
        _In_opt_ HANDLE fileHandle,
        _In_ BOOLEAN readOnly,
        _Out_ PVOID *viewBase,
        _Out_ PSIZE_T size)
    {
        bool ret = false;
        NTSTATUS status = STATUS_SUCCESS;
        BOOLEAN openedFile = FALSE;
        LARGE_INTEGER fileSize = {};
        HANDLE sectionHandle = nullptr;
        SIZE_T tmpViewSize = 0x00;
        PVOID tmpViewBase = nullptr;

        if (fileName == L"" && fileHandle == nullptr)
            return false;

        if (size == nullptr || viewBase == nullptr)
            return false;

        if (fileHandle == nullptr)
        {
            fileHandle = CreateFileW(
                fileName,
                ((FILE_EXECUTE | FILE_READ_ATTRIBUTES | FILE_READ_DATA) | (!readOnly ? (FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA) : 0x00)) | SYNCHRONIZE,
                FILE_SHARE_READ,
                nullptr,
                OPEN_EXISTING,
                0x00,
                nullptr);

            if (fileHandle == INVALID_HANDLE_VALUE)
                return false;

            openedFile = TRUE;
        }

        fileSize.LowPart = GetFileSize(fileHandle, (LPDWORD)&fileSize.HighPart);

        status = PsjNtCreateSection(
            &sectionHandle,
            SECTION_ALL_ACCESS,
            nullptr,
            &fileSize,
            readOnly ? PAGE_EXECUTE_READ : PAGE_EXECUTE_READWRITE,
            SEC_COMMIT,
            fileHandle);

        if (!NT_SUCCESS(status))
            goto CLEANUP;

        tmpViewSize = (SIZE_T)fileSize.QuadPart;

        status = PsjNtMapViewOfSection(
            sectionHandle,
            NtCurrentProcess(),
            &tmpViewBase,
            0x00,
            0x00,
            nullptr,
            &tmpViewSize,
            SECTION_INHERIT::VIEW_SHARE,
            0x00,
            readOnly ? PAGE_EXECUTE_READ : PAGE_EXECUTE_READWRITE);

        if (!NT_SUCCESS(status))
            goto CLEANUP;

        *viewBase = tmpViewBase;
        *size = (SIZE_T)fileSize.QuadPart;

        ret = true;

    CLEANUP:
        if (sectionHandle != nullptr)
            CloseHandle(sectionHandle);

        if (openedFile && fileHandle != nullptr)
            CloseHandle(fileHandle);

        return ret;
    }

    bool Injector::InitializeMappedImage(
        _Out_ PPSJ_MAPPED_IMAGE mappedImage,
        _In_ PVOID viewBase,
        _In_ SIZE_T size)
    {
        mappedImage->view_base = viewBase;
        mappedImage->size = size;

        PPSJ_IMAGE_DOS_HEADER dosHeader = (PPSJ_IMAGE_DOS_HEADER)viewBase;

        if (MappedImageProbe(mappedImage, dosHeader, sizeof(PSJ_IMAGE_DOS_HEADER)) == false)
            return false;

        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return false;

        ULONG ntHeadersOffset = (ULONG)dosHeader->e_lfanew;

        if (ntHeadersOffset == 0x00 || ntHeadersOffset >= 0x10000000 || ntHeadersOffset >= size)
            return false;

        mappedImage->nt_headers = (PPSJ_IMAGE_NT_HEADERS)PTR_ADD_OFFSET(viewBase, ntHeadersOffset);

        if (MappedImageProbe(mappedImage, dosHeader, sizeof(PSJ_IMAGE_DOS_HEADER)) == false)
            return false;
            
        if (MappedImageProbe(mappedImage, mappedImage->nt_headers, FIELD_OFFSET(PSJ_IMAGE_NT_HEADERS, optional_header)) == false)
            return false;

        if (MappedImageProbe(
            mappedImage, mappedImage->nt_headers,
            FIELD_OFFSET(PSJ_IMAGE_NT_HEADERS, optional_header)
            + mappedImage->nt_headers->file_header.size_of_optional_header
            + mappedImage->nt_headers->file_header.number_of_sections * sizeof(PSJ_IMAGE_SECTION_HEADER)) == false)
            return false;

        if (mappedImage->nt_headers->signature != IMAGE_NT_SIGNATURE)
            return false;

        mappedImage->magic = mappedImage->nt_headers->optional_header.magic;

        if (mappedImage->magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC
            && mappedImage->magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            return false;

        mappedImage->number_of_sections = mappedImage->nt_headers->file_header.number_of_sections;

        mappedImage->sections = (PPSJ_IMAGE_SECTION_HEADER)(
            ((PCHAR)&mappedImage->nt_headers->optional_header)
            + mappedImage->nt_headers->file_header.size_of_optional_header);

        return true;
    }

    bool Injector::MappedImageProbe(
        _In_ PPSJ_MAPPED_IMAGE mappedImage,
        _In_ PVOID address,
        _In_ SIZE_T length)
    {
        return ProbeAddress(address, length, mappedImage->view_base, mappedImage->size, 0x01);
    }

    bool Injector::ProbeAddress(
        _In_ PVOID userAddress,
        _In_ SIZE_T userLength,
        _In_ PVOID bufferAddress,
        _In_ SIZE_T bufferLength,
        _In_ ULONG alignment)
    {
        if (userLength == 0x00 || ((ULONG_PTR)userAddress & (alignment - 0x01)) != 0x00)
            return false;

        if (((ULONG_PTR)userAddress + userLength < (ULONG_PTR)userAddress)
            || ((ULONG_PTR)userAddress < (ULONG_PTR)bufferAddress)
            || ((ULONG_PTR)userAddress + userLength > (ULONG_PTR)bufferAddress + bufferLength))
            return false;

        return true;
    }

    bool Injector::GetProcedureAddressRemote(
        _In_ HANDLE processHandle,
        _In_ PWSTR fileName,
        _In_opt_ PSTR procedureName,
        _In_opt_ ULONG procedureNumber,
        _Out_ PVOID *procedureAddress,
        _Out_opt_ PVOID *dllBase)
    {
        PSJ_MAPPED_IMAGE mappedImage = {};

        if (LoadMappedImage(fileName, nullptr, TRUE, &mappedImage) == false)
            return false;

        std::wstring tmpFileName(fileName);
        std::transform(tmpFileName.begin(), tmpFileName.end(), tmpFileName.begin(), [](wchar_t c){return static_cast<wchar_t>(towlower(static_cast<wint_t>(c)));});

        PSJ_PROCEDURE_ADDRESS_REMOTE_CONTEXT context = {};
        wcscpy_s(context.file_name, tmpFileName.c_str());

        ModuleEnumerator moduleEnumerator(processHandle, ModuleEnumerator::GetProcedureAddressRemoteCallback, &context);

        if (mappedImage.magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
#if !defined(_AMD64_) && !defined(_ARM64_)
            PsjNtUnmapViewOfSection(NtCurrentProcess(), mappedImage.view_base);
            return false;
#endif
        }

        moduleEnumerator.EnumProcessModules();

        if (context.dll_base == nullptr)
        {
            PsjNtUnmapViewOfSection(NtCurrentProcess(), mappedImage.view_base);
            return false;
        }

        PSJ_MAPPED_IMAGE_EXPORTS exports;

        if (GetMappedImageExports(&exports, &mappedImage) == false)
        {
            PsjNtUnmapViewOfSection(NtCurrentProcess(), mappedImage.view_base);
            return false;
        }

        if (GetMappedImageExportFunctionRemote(&exports, procedureName, (USHORT)procedureNumber, context.dll_base, procedureAddress) == false)
        {
            PsjNtUnmapViewOfSection(NtCurrentProcess(), mappedImage.view_base);
            return false;
        }

        if (dllBase != nullptr)
            *dllBase = context.dll_base;

        PsjNtUnmapViewOfSection(NtCurrentProcess(), mappedImage.view_base);
        return true;
    }

    bool Injector::GetMappedImageExports(
        _Out_ PPSJ_MAPPED_IMAGE_EXPORTS exports,
        _In_ PPSJ_MAPPED_IMAGE mappedImage)
    {
        exports->mapped_image = mappedImage;

        if (GetMappedImageDataEntry(mappedImage, IMAGE_DIRECTORY_ENTRY_EXPORT, &exports->data_directory) == false)
            return false;

        PPSJ_IMAGE_EXPORT_DIRECTORY exportDirectory = (PPSJ_IMAGE_EXPORT_DIRECTORY)MappedImageRvaToVa(
            mappedImage,
            exports->data_directory->virtual_address,
            nullptr);

        if (exportDirectory == nullptr)
            return false;

        if (MappedImageProbe(mappedImage, exportDirectory, sizeof(PSJ_IMAGE_EXPORT_DIRECTORY)) == false)
            return false;

        exports->export_directory = exportDirectory;
        exports->number_of_entries = exportDirectory->number_of_functions;
        exports->address_table = (uint32_t *)MappedImageRvaToVa(mappedImage, exportDirectory->address_of_functions, nullptr);
        exports->name_pointer_table = (uint32_t *)MappedImageRvaToVa(mappedImage, exportDirectory->address_of_names, nullptr);
        exports->ordinal_table = (uint16_t *)MappedImageRvaToVa(mappedImage, exportDirectory->address_of_name_ordinals, nullptr);

        if (exports->address_table == nullptr || exports->name_pointer_table == nullptr || exports->ordinal_table == nullptr)
            return false;

        if (MappedImageProbe(mappedImage, exports->address_table, exportDirectory->number_of_functions * sizeof(uint32_t)) == false)
            return false;

        if (MappedImageProbe(mappedImage, exports->name_pointer_table, exportDirectory->number_of_names * sizeof(uint32_t)) == false)
            return false;

        if (MappedImageProbe(mappedImage, exports->ordinal_table, exportDirectory->number_of_functions * sizeof(uint16_t)) == false)
            return false;

        return true;
    }

    bool Injector::GetMappedImageDataEntry(
        _In_ PPSJ_MAPPED_IMAGE mappedImage,
        _In_ ULONG index,
        _Out_ PPSJ_IMAGE_DATA_DIRECTORY *entry)
    {
        if (mappedImage->magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            PPSJ_IMAGE_OPTIONAL_HEADER32 optionalHeader = (PPSJ_IMAGE_OPTIONAL_HEADER32)&mappedImage->nt_headers->optional_header;

            if (index >= optionalHeader->number_of_rva_and_sizes)
                return false;

            *entry = &optionalHeader->data_directory[index];
        }
        else if (mappedImage->magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            PPSJ_IMAGE_OPTIONAL_HEADER64 optionalHeader = (PPSJ_IMAGE_OPTIONAL_HEADER64)&mappedImage->nt_headers->optional_header;

            if (index >= optionalHeader->number_of_rva_and_sizes)
                return false;

            *entry = &optionalHeader->data_directory[index];
        }
        else
        {
            return false;
        }

        return true;
    }

    PVOID Injector::MappedImageRvaToVa(
        _In_ PPSJ_MAPPED_IMAGE mappedImage,
        _In_ ULONG rva,
        _Out_opt_ PPSJ_IMAGE_SECTION_HEADER *section)
    {
        PPSJ_IMAGE_SECTION_HEADER sectionHeader = MappedImageRvaToSection(mappedImage, rva);

        if (section != nullptr)
            *section = sectionHeader;

        return (PVOID)((ULONG_PTR)mappedImage->view_base
            + (rva - sectionHeader->virtual_address)
            + sectionHeader->pointer_to_raw_data);
    }

    PPSJ_IMAGE_SECTION_HEADER Injector::MappedImageRvaToSection(
        _In_ PPSJ_MAPPED_IMAGE mappedImage,
        _In_ ULONG rva)
    {
        for (uint32_t i = 0x00; i < mappedImage->number_of_sections; i++)
        {
            if ((rva >= mappedImage->sections[i].virtual_address)
                && (rva < mappedImage->sections[i].virtual_address + mappedImage->sections[i].size_of_raw_data))
                return &mappedImage->sections[i];
        }

        return nullptr;
    }

    bool Injector::GetMappedImageExportFunctionRemote(
        _In_ PPSJ_MAPPED_IMAGE_EXPORTS exports,
        _In_opt_ PSTR name,
        _In_opt_ USHORT ordinal,
        _In_ PVOID remoteBase,
        _Out_ PVOID *function)
    {
        if (name != "")
        {
            ULONG index = LookupMappedImageExportName(exports, name);

            if (index == -0x01)
                return false;

            ordinal = exports->ordinal_table[index] + (USHORT)exports->export_directory->base;
        }

        ordinal -= (USHORT)exports->export_directory->base;

        if (ordinal >= exports->export_directory->number_of_functions)
            return false;

        uint32_t rva = exports->address_table[ordinal];

        if ((rva >= exports->data_directory->virtual_address)
            && (rva < exports->data_directory->virtual_address + exports->data_directory->size))
            return false;

        *function = PTR_ADD_OFFSET(remoteBase, rva);

        return true;
    }

    ULONG Injector::LookupMappedImageExportName(
        _In_ PPSJ_MAPPED_IMAGE_EXPORTS exports,
        _In_ PSTR name)
    {
        if (exports->export_directory->number_of_names == 0x00)
            return -0x01;

        int32_t low = 0x00;
        int32_t high = exports->export_directory->number_of_names - 0x01;

        do
        {
            int32_t i = (low + high) / 0x02;

            LPSTR tmpName = (LPSTR)MappedImageRvaToVa(
                exports->mapped_image,
                exports->name_pointer_table[i],
                nullptr);

            if (tmpName == nullptr)
                return -0x01;

            INT comparison = strcmp(name, tmpName);

            if (comparison == 0x00)
                return i;
            else if (comparison < 0x00)
                high = i - 0x01;
            else
                low = i + 0x01;
        } while (low <= high);

        return -0x01;
    }

    bool Injector::InjectDllIntoProcess(HANDLE processHandle, const std::wstring& dllName)
    {
        return false;
    }

    bool Injector::Injection(DWORD processId, const std::wstring& dllName)
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