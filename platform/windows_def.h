#pragma once

#include "platform.h"
#include "pe_image.h"

#if defined(_WIN32) || defined(_WIN64)
//----------------------------------------------------------------------
// windows
//----------------------------------------------------------------------
#define NtCurrentProcess()          ((HANDLE)(LONG_PTR)-0x01)
#define NtCurrentThread()           ((HANDLE)(LONG_PTR)-0x02)
#define NtCurrentSession()          ((HANDLE)(LONG_PTR)-0x03)

#define ZwCurrentProcess()          NtCurrentProcess()
#define ZwCurrentThread()           NtCurrentThread()
#define ZwCurrentSession()          NtCurrentSession()

#define NtCurrentPeb()              (NtCurrentTeb()->ProcessEnvironmentBlock)
#define NtCurrentProcessId()        (NtCurrentTeb()->ClientId.UniqueProcess)
#define NtCurrentThreadId()         (NtCurrentTeb()->ClientId.UniqueThread)
//----------------------------------------------------------------------
#define FILE_SUPERSEDE              0x00000000
#define FILE_OPEN                   0x00000001
#define FILE_CREATE                 0x00000002
#define FILE_OPEN_IF                0x00000003
#define FILE_OVERWRITE              0x00000004
#define FILE_OVERWRITE_IF           0x00000005
#define FILE_MAXIMUM_DISPOSITION    0x00000005
//----------------------------------------------------------------------
#define PTR_ADD_OFFSET(pointer, offset) ((void *)((size_t)(pointer) + (size_t)(offset)))
#define PTR_SUB_OFFSET(pointer, offset) ((void *)((size_t)(pointer) - (size_t)(offset)))
//----------------------------------------------------------------------
#define PSJ_MAPPED_IMAGE_DELAY_IMPORTS 0x01
//----------------------------------------------------------------------
typedef enum _SECTION_INHERIT
{
    VIEW_SHARE = 0x01,
    VIEW_UNMAP = 0x02
} SECTION_INHERIT, *PSECTION_INHERIT;
//----------------------------------------------------------------------
typedef NTSTATUS(NTAPI *PFN_NtCreateSection)
(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle
);
//----------------------------------------------------------------------
typedef NTSTATUS(NTAPI *PFN_NtMapViewOfSection)
(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ SECTION_INHERIT InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection
);
//----------------------------------------------------------------------
typedef NTSTATUS(NTAPI *PFN_NtUnmapViewOfSection)
(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress
);
//----------------------------------------------------------------------
typedef NTSTATUS(NTAPI *PFN_NtAllocateVirtualMemory)
(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection
);
//----------------------------------------------------------------------
typedef NTSTATUS(NTAPI *PFN_NtReadVirtualMemory)
(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _Out_writes_bytes_to_(NumberOfBytesToRead, *NumberOfBytesRead) PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToRead,
    _Out_opt_ PSIZE_T NumberOfBytesRead
);
//----------------------------------------------------------------------
typedef NTSTATUS(NTAPI *PFN_NtWriteVirtualMemory)
(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_reads_bytes_(NumberOfBytesToWrite) PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToWrite,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
);
//----------------------------------------------------------------------
typedef _Function_class_(USER_THREAD_START_ROUTINE)
NTSTATUS NTAPI USER_THREAD_START_ROUTINE
(
    _In_ PVOID ThreadParameter
);
typedef USER_THREAD_START_ROUTINE* PUSER_THREAD_START_ROUTINE;
//----------------------------------------------------------------------
typedef struct _PSJ_CLIENT_ID
{
    void *unique_process;
    void *unique_thread;
} PSJ_CLIENT_ID, *PPSJ_CLIENT_ID;
//----------------------------------------------------------------------
typedef NTSTATUS(NTAPI *PFN_RtlCreateUserThread)
(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
    _In_ BOOLEAN CreateSuspended,
    _In_opt_ ULONG ZeroBits,
    _In_opt_ SIZE_T MaximumStackSize,
    _In_opt_ SIZE_T CommittedStackSize,
    _In_ PUSER_THREAD_START_ROUTINE StartAddress,
    _In_opt_ PVOID Parameter,
    _Out_opt_ PHANDLE ThreadHandle,
    _Out_opt_ PPSJ_CLIENT_ID ClientId
);
//----------------------------------------------------------------------
#endif