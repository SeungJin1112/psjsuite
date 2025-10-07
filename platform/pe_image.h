#pragma once

#include "platform.h"

//----------------------------------------------------------------------
typedef struct _PSJ_IMAGE_FILE_HEADER
{
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
} PSJ_IMAGE_FILE_HEADER, *PPSJ_IMAGE_FILE_HEADER;
//----------------------------------------------------------------------
typedef struct _PSJ_IMAGE_DATA_DIRECTORY
{
    uint32_t virtual_address;
    uint32_t size;
} PSJ_IMAGE_DATA_DIRECTORY, *PPSJ_IMAGE_DATA_DIRECTORY;
//----------------------------------------------------------------------
typedef struct _PSJ_IMAGE_OPTIONAL_HEADER
{
    uint16_t magic;
    uint8_t major_linker_version;
    uint8_t minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
    uint32_t base_of_data;
    uint32_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_operating_system_version;
    uint16_t minor_operating_system_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t check_sum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint32_t size_of_stack_reserve;
    uint32_t size_of_stack_commit;
    uint32_t size_of_heap_reserve;
    uint32_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
    PSJ_IMAGE_DATA_DIRECTORY data_directory[0x10];
} PSJ_IMAGE_OPTIONAL_HEADER32, *PPSJ_IMAGE_OPTIONAL_HEADER32;
//----------------------------------------------------------------------
typedef struct _PSJ_IMAGE_OPTIONAL_HEADER64
{
    uint16_t magic;
    uint8_t major_linker_version;
    uint8_t minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
    uint64_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_operating_system_version;
    uint16_t minor_operating_system_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t check_sum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint64_t size_of_stack_reserve;
    uint64_t size_of_stack_commit;
    uint64_t size_of_heap_reserve;
    uint64_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
    PSJ_IMAGE_DATA_DIRECTORY data_directory[0x10];
} PSJ_IMAGE_OPTIONAL_HEADER64, *PPSJ_IMAGE_OPTIONAL_HEADER64;
//----------------------------------------------------------------------
typedef struct _PSJ_IMAGE_ROM_OPTIONAL_HEADER
{
    uint16_t magic;
    uint8_t major_linker_version;
    uint8_t minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
    uint32_t base_of_data;
    uint32_t base_of_bss;
    uint32_t gpr_mask;
    uint32_t cpr_mask[0x04];
    uint32_t gp_value;
} PSJ_IMAGE_ROM_OPTIONAL_HEADER, *PPSJ_IMAGE_ROM_OPTIONAL_HEADER;
//----------------------------------------------------------------------
typedef struct _PSJ_IMAGE_NT_HEADERS32
{
    uint32_t signature;
    PSJ_IMAGE_FILE_HEADER file_header;
    PSJ_IMAGE_OPTIONAL_HEADER32 optional_header;
} PSJ_IMAGE_NT_HEADERS32, *PPSJ_IMAGE_NT_HEADERS32;
//----------------------------------------------------------------------
typedef struct _PSJ_IMAGE_NT_HEADERS64
{
    uint32_t signature;
    PSJ_IMAGE_FILE_HEADER file_header;
    PSJ_IMAGE_OPTIONAL_HEADER64 optional_header;
} PSJ_IMAGE_NT_HEADERS64, *PPSJ_IMAGE_NT_HEADERS64;
//----------------------------------------------------------------------
typedef struct _PSJ_IMAGE_ROM_HEADERS
{
    PSJ_IMAGE_FILE_HEADER file_header;
    PSJ_IMAGE_ROM_OPTIONAL_HEADER optional_header;
} PSJ_IMAGE_ROM_HEADERS, *PPSJ_IMAGE_ROM_HEADERS;
//----------------------------------------------------------------------
#pragma pack(push, 1)
typedef struct _PSJ_IMAGE_SECTION_HEADER
{
    uint8_t name[0x08];
    union
    {
        uint32_t physical_address;
        uint32_t virtual_size;
    } misc;
    uint32_t virtual_address;
    uint32_t size_of_raw_data;
    uint32_t pointer_to_raw_data;
    uint32_t pointer_to_relocations;
    uint32_t pointer_to_linenumbers;
    uint16_t number_of_relocations;
    uint16_t number_of_linenumbers;
    uint32_t characteristics;
} PSJ_IMAGE_SECTION_HEADER, *PPSJ_IMAGE_SECTION_HEADER;
#pragma pack(pop)
//----------------------------------------------------------------------
typedef struct _PSJ_MAPPED_IMAGE32
{
    void *view_base;
    size_t size;
    PPSJ_IMAGE_NT_HEADERS32 nt_headers;
    uint32_t number_of_sections;
    PPSJ_IMAGE_SECTION_HEADER sections;
    uint16_t magic;
} PSJ_MAPPED_IMAGE32, *PPSJ_MAPPED_IMAGE32;
//----------------------------------------------------------------------
typedef struct _PSJ_MAPPED_IMAGE64
{
    void *view_base;
    size_t size;
    PPSJ_IMAGE_NT_HEADERS64 nt_headers;
    uint32_t number_of_sections;
    PPSJ_IMAGE_SECTION_HEADER sections;
    uint16_t magic;
} PSJ_MAPPED_IMAGE64, *PPSJ_MAPPED_IMAGE64;
//----------------------------------------------------------------------
typedef struct _PSJ_IMAGE_EXPORT_DIRECTORY
{
    uint32_t characteristics;
    uint32_t time_data_stamp;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t name;
    uint32_t base;
    uint32_t number_of_functions;
    uint32_t number_of_names;
    uint32_t address_of_functions;
    uint32_t address_of_names;
    uint32_t address_of_name_ordinals;
} PSJ_IMAGE_EXPORT_DIRECTORY, *PPSJ_IMAGE_EXPORT_DIRECTORY;
//----------------------------------------------------------------------
typedef struct _PSJ_MAPPED_IMAGE_EXPORTS32
{
    PPSJ_MAPPED_IMAGE32 mapped_image;
    uint32_t number_of_entries;
    PPSJ_IMAGE_DATA_DIRECTORY data_directory;
    PPSJ_IMAGE_EXPORT_DIRECTORY export_directory;
    uint32_t *address_table;
    uint32_t *name_pointer_table;
    uint16_t *ordinal_table;
} PSJ_MAPPED_IMAGE_EXPORTS32, *PPSJ_MAPPED_IMAGE_EXPORTS32;
//----------------------------------------------------------------------
typedef struct _PSJ_MAPPED_IMAGE_EXPORTS64
{
    PPSJ_MAPPED_IMAGE64 mapped_image;
    uint32_t number_of_entries;
    PPSJ_IMAGE_DATA_DIRECTORY data_directory;
    PPSJ_IMAGE_EXPORT_DIRECTORY export_directory;
    uint32_t *address_table;
    uint32_t *name_pointer_table;
    uint16_t *ordinal_table;
} PSJ_MAPPED_IMAGE_EXPORTS64, *PPSJ_MAPPED_IMAGE_EXPORTS64;
//----------------------------------------------------------------------
typedef struct _PSJ_REMOTE_MAPPED_IMAGE32
{
    void *view_base;
    PPSJ_IMAGE_NT_HEADERS32 nt_headers;
    uint32_t number_of_sections;
    PPSJ_IMAGE_SECTION_HEADER sections;
    uint16_t magic;
} PSJ_REMOTE_MAPPED_IMAGE32, *PPSJ_REMOTE_MAPPED_IMAGE32;
//----------------------------------------------------------------------
typedef struct _PSJ_REMOTE_MAPPED_IMAGE64
{
    void *view_base;
    PPSJ_IMAGE_NT_HEADERS64 nt_headers;
    uint32_t number_of_sections;
    PPSJ_IMAGE_SECTION_HEADER sections;
    uint16_t magic;
} PSJ_REMOTE_MAPPED_IMAGE64, *PPSJ_REMOTE_MAPPED_IMAGE64;
//----------------------------------------------------------------------
typedef struct _PSJ_MAPPED_IMAGE_EXPORT_ENTRY
{
    uint16_t ordinal;
    char *name;
} PSJ_MAPPED_IMAGE_EXPORT_ENTRY, *PPSJ_MAPPED_IMAGE_EXPORT_ENTRY;
//----------------------------------------------------------------------
typedef struct _PSJ_MAPPED_IMAGE_EXPORT_FUNCTION
{
    void *function;
    char *forwarded_name;
} PSJ_MAPPED_IMAGE_EXPORT_FUNCTION, *PPSJ_MAPPED_IMAGE_EXPORT_FUNCTION;
//----------------------------------------------------------------------
typedef struct _PSJ_IMAGE_IMPORT_DESCRIPTOR
{
    union
    {
        uint32_t characteristics;
        uint32_t original_first_thunk;
    } dummy_union_name;
    uint32_t time_date_stamp;
    uint32_t forwarder_chain;
    uint32_t name;
    uint32_t first_thunk;
} PSJ_IMAGE_IMPORT_DESCRIPTOR, *PPSJ_IMAGE_IMPORT_DESCRIPTOR;
//----------------------------------------------------------------------
typedef struct _PSJ_MAPPED_IMAGE_IMPORTS32
{
    PPSJ_MAPPED_IMAGE32 mapped_image;
    uint32_t flags;
    uint32_t number_of_dlls;
    union
    {
        PPSJ_IMAGE_IMPORT_DESCRIPTOR descriptor_table;
        void *delay_descriptor_table;
    };
} PSJ_MAPPED_IMAGE_IMPORTS32, *PPSJ_MAPPED_IMAGE_IMPORTS32;
//----------------------------------------------------------------------
typedef struct _PSJ_MAPPED_IMAGE_IMPORTS64
{
    PPSJ_MAPPED_IMAGE64 mapped_image;
    uint32_t flags;
    uint32_t number_of_dlls;
    union
    {
        PPSJ_IMAGE_IMPORT_DESCRIPTOR descriptor_table;
        void *delay_descriptor_table;
    };
} PSJ_MAPPED_IMAGE_IMPORTS64, *PPSJ_MAPPED_IMAGE_IMPORTS64;
//----------------------------------------------------------------------
typedef struct _PSJ_MAPPED_IMAGE_IMPORT_DLL32
{
    PPSJ_MAPPED_IMAGE32 mapped_image;
    uint32_t flags;
    char *name;
    uint32_t number_of_entries;
    union
    {
        PPSJ_IMAGE_IMPORT_DESCRIPTOR descriptor;
        void *delay_descriptor;
    };
    void **lookup_table;
} PSJ_MAPPED_IMAGE_IMPORT_DLL32, *PPSJ_MAPPED_IMAGE_IMPORT_DLL32;
//----------------------------------------------------------------------
typedef struct _PSJ_MAPPED_IMAGE_IMPORT_DLL64
{
    PPSJ_MAPPED_IMAGE64 mapped_image;
    uint32_t flags;
    char *name;
    uint32_t number_of_entries;
    union
    {
        PPSJ_IMAGE_IMPORT_DESCRIPTOR descriptor;
        void *delay_descriptor;
    };
    void **lookup_table;
} PSJ_MAPPED_IMAGE_IMPORT_DLL64, *PPSJ_MAPPED_IMAGE_IMPORT_DLL64;
//----------------------------------------------------------------------
typedef struct _PSJ_MAPPED_IMAGE_IMPORT_ENTRY
{
    char *name;
    union
    {
        uint16_t ordinal;
        uint16_t name_hint;
    };
} PSJ_MAPPED_IMAGE_IMPORT_ENTRY, *PPSJ_MAPPED_IMAGE_IMPORT_ENTRY;
//--------------------------------------------------------------------------------