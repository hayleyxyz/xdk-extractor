#ifndef XDK_EXTRACTOR_COFF_H
#define XDK_EXTRACTOR_COFF_H

#include <cstdint>

namespace coff {

    static const uint16_t DosMagic = 0x5a4d;

    static const char PEMagic[] = { 'P', 'E', '\0', '\0' };

    static const uint16_t MachineI386 = 0x14C;

    static const uint32_t NumberOfDataDirectories = 16;

    static const uint32_t NameSize = 8;

    /**
     * Bunch of PE structures (stolen from llvm src)
     */
    struct DOSHeader {
        uint16_t Magic;
        uint16_t UsedBytesInTheLastPage;
        uint16_t FileSizeInPages;
        uint16_t NumberOfRelocationItems;
        uint16_t HeaderSizeInParagraphs;
        uint16_t MinimumExtraParagraphs;
        uint16_t MaximumExtraParagraphs;
        uint16_t InitialRelativeSS;
        uint16_t InitialSP;
        uint16_t Checksum;
        uint16_t InitialIP;
        uint16_t InitialRelativeCS;
        uint16_t AddressOfRelocationTable;
        uint16_t OverlayNumber;
        uint16_t Reserved[4];
        uint16_t OEMid;
        uint16_t OEMinfo;
        uint16_t Reserved2[10];
        uint32_t AddressOfNewExeHeader;
    };

    struct FileHeader {
        uint16_t Machine;
        uint16_t NumberOfSections;
        uint32_t TimeDateStamp;
        uint32_t PointerToSymbolTable;
        uint32_t NumberOfSymbols;
        uint16_t SizeOfOptionalHeader;
        uint16_t Characteristics;
    };

    struct DataDirectory {
        uint32_t RelativeVirtualAddress;
        uint32_t Size;
    };

    struct PE32Header {
        enum {
            PE32 = 0x10b,
            PE32_PLUS = 0x20b
        };

        uint16_t Magic;
        uint8_t  MajorLinkerVersion;
        uint8_t  MinorLinkerVersion;
        uint32_t SizeOfCode;
        uint32_t SizeOfInitializedData;
        uint32_t SizeOfUninitializedData;
        uint32_t AddressOfEntryPoint; // RVA
        uint32_t BaseOfCode; // RVA
        uint32_t BaseOfData; // RVA
        uint32_t ImageBase;
        uint32_t SectionAlignment;
        uint32_t FileAlignment;
        uint16_t MajorOperatingSystemVersion;
        uint16_t MinorOperatingSystemVersion;
        uint16_t MajorImageVersion;
        uint16_t MinorImageVersion;
        uint16_t MajorSubsystemVersion;
        uint16_t MinorSubsystemVersion;
        uint32_t Win32VersionValue;
        uint32_t SizeOfImage;
        uint32_t SizeOfHeaders;
        uint32_t CheckSum;
        uint16_t Subsystem;
        // FIXME: This should be DllCharacteristics to match the COFF spec.
        uint16_t DLLCharacteristics;
        uint32_t SizeOfStackReserve;
        uint32_t SizeOfStackCommit;
        uint32_t SizeOfHeapReserve;
        uint32_t SizeOfHeapCommit;
        uint32_t LoaderFlags;
        // FIXME: This should be NumberOfRvaAndSizes to match the COFF spec.
        uint32_t NumberOfRvaAndSize;
        DataDirectory DataDirectories[NumberOfDataDirectories];
    };

    struct SectionHeader {
        char     Name[NameSize];
        uint32_t VirtualSize;
        uint32_t VirtualAddress;
        uint32_t SizeOfRawData;
        uint32_t PointerToRawData;
        uint32_t PointerToRelocations;
        uint32_t PointerToLineNumbers;
        uint16_t NumberOfRelocations;
        uint16_t NumberOfLineNumbers;
        uint32_t Characteristics;
    };

    uint32_t getSizeOfImage(std::fstream& file);

};


#endif //XDK_EXTRACTOR_COFF_H
