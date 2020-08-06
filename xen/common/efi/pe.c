#include "efi.h"

struct DosFileHeader {
        UINT8   Magic[2];
        UINT16  LastSize;
        UINT16  nBlocks;
        UINT16  nReloc;
        UINT16  HdrSize;
        UINT16  MinAlloc;
        UINT16  MaxAlloc;
        UINT16  ss;
        UINT16  sp;
        UINT16  Checksum;
        UINT16  ip;
        UINT16  cs;
        UINT16  RelocPos;
        UINT16  nOverlay;
        UINT16  reserved[4];
        UINT16  OEMId;
        UINT16  OEMInfo;
        UINT16  reserved2[10];
        UINT32  ExeHeader;
} __attribute__((packed));

#define PE_HEADER_MACHINE_ARM64         0xaa64
#define PE_HEADER_MACHINE_X64           0x8664
#define PE_HEADER_MACHINE_I386          0x014c

struct PeFileHeader {
        UINT16  Machine;
        UINT16  NumberOfSections;
        UINT32  TimeDateStamp;
        UINT32  PointerToSymbolTable;
        UINT32  NumberOfSymbols;
        UINT16  SizeOfOptionalHeader;
        UINT16  Characteristics;
} __attribute__((packed));

struct PeHeader {
        UINT8   Magic[4];
        struct PeFileHeader FileHeader;
} __attribute__((packed));

struct PeSectionHeader {
        UINT8   Name[8];
        UINT32  VirtualSize;
        UINT32  VirtualAddress;
        UINT32  SizeOfRawData;
        UINT32  PointerToRawData;
        UINT32  PointerToRelocations;
        UINT32  PointerToLinenumbers;
        UINT16  NumberOfRelocations;
        UINT16  NumberOfLinenumbers;
        UINT32  Characteristics;
} __attribute__((packed));

void * __init pe_find_section(const void * const image_base,
        const char * section_name, UINTN * size_out)
{
    const CHAR8 * const base = image_base;
    const struct DosFileHeader * dos = (const void*) base;
    const struct PeHeader * pe;
    const UINTN name_len = strlen(section_name);
    UINTN offset;

    if ( base == NULL )
        return NULL;

    if ( memcmp(dos->Magic, "MZ", 2) != 0 )
        return NULL;

    pe = (const void *) &base[dos->ExeHeader];
    if ( memcmp(pe->Magic, "PE\0\0", 4) != 0 )
        return NULL;

    /* PE32+ Subsystem type */
#if defined(__ARM__)
    if (pe->FileHeader.Machine != PE_HEADER_MACHINE_ARM64)
        return NULL;
#elif defined(__x86_64__)
    if (pe->FileHeader.Machine != PE_HEADER_MACHINE_X64)
        return NULL;
#else
    // unknown architecture
    return NULL;
#endif

    if ( pe->FileHeader.NumberOfSections > 96 )
        return NULL;

    offset = dos->ExeHeader + sizeof(*pe) + pe->FileHeader.SizeOfOptionalHeader;

    for (UINTN i = 0; i < pe->FileHeader.NumberOfSections; i++)
    {
        const struct PeSectionHeader *const sect = (const struct PeSectionHeader *)&base[offset];
        if ( memcmp(sect->Name, section_name, name_len) == 0 )
        {
            if ( size_out )
                *size_out = sect->VirtualSize;
            return (void*)(sect->VirtualAddress + (uintptr_t) image_base);
        }

        offset += sizeof(*sect);
    }

    return NULL;
}
