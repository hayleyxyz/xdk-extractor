#include <fstream>
#include <stdexcept>
#include "coff.h"

namespace coff {
    uint32_t getSizeOfImage(std::fstream& file) {
        coff::DOSHeader dosHeader;
        file.read(reinterpret_cast<char *>(&dosHeader), sizeof(coff::DOSHeader));

        if(dosHeader.Magic != coff::DosMagic) {
            throw new std::runtime_error("Input file missing DOS header");
        }

        char magic[4];

        file.seekg(dosHeader.AddressOfNewExeHeader, std::ios::beg);
        file.read(magic, sizeof(magic));

        if(std::memcmp(coff::PEMagic, magic, sizeof(coff::PEMagic)) != 0) {
            throw new std::runtime_error("Input file invalid/corrupt EXE");
        }

        coff::FileHeader fileHeader;
        file.read(reinterpret_cast<char *>(&fileHeader), sizeof(coff::FileHeader));

        if(fileHeader.Machine != coff::MachineI386) {
            throw new std::runtime_error("Input file is not a i386 EXE");
        }

        coff::PE32Header pe32Header;
        file.read(reinterpret_cast<char *>(&pe32Header), sizeof(coff::PE32Header));

        uint32_t topOffset = 0;

        for(int i = 0; i < fileHeader.NumberOfSections; i++) {
            coff::SectionHeader sectionHeader;
            file.read(reinterpret_cast<char *>(&sectionHeader), sizeof(coff::SectionHeader));

            topOffset = std::max(topOffset, sectionHeader.PointerToRawData + sectionHeader.SizeOfRawData);
        }

        return topOffset;
    }
}