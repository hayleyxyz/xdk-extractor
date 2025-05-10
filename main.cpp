#include <iostream>
#include <fstream>
#include <vector>
#include <cstring>
#include "coff.h"
#include <cmath>

static const char CabMagic[] = { 'M', 'S', 'C', 'F' };

struct CabHeader {
    char Magic[4];
    uint32_t Reserved;
    uint32_t PackedSize;

};

void help(const char * name) {
    std::cout << "Usage: " << name << " <XDKSetupXenonXXXX.exe>" << std::endl;
}

int main(int argc, const char * argv[]) {

    if(argc < 2) {
        help(argv[0]);
        return 1;
    }

    std::fstream file;
    file.open(argv[1], std::ios::in | std::ios::binary);

    if(!file.is_open()) {
        std::cout << "Failed to open file: " << argv[1] << std::endl;
        return 2;
    }

    uint32_t peSize = coff::getSizeOfImage(file);

    std::cout << std::hex << "Start of data: 0x" << peSize << std::endl;

    char * buffer = nullptr;
    uint32_t bufferSize = 0;
    uint32_t index = 0;

    while(true) {
        file.seekg(peSize, std::ios::beg);

        CabHeader header;
        file.read(reinterpret_cast<char *>(&header), sizeof(CabHeader));

        if(std::memcmp(CabMagic, header.Magic, sizeof(CabMagic)) != 0) {
            break;
        }

        file.seekg(peSize, std::ios::beg);

        if(buffer == nullptr) {
            buffer = reinterpret_cast<char *>(malloc(header.PackedSize));
            bufferSize = header.PackedSize;
        }
        else if(bufferSize < header.PackedSize) {
            buffer = reinterpret_cast<char *>(realloc(buffer, header.PackedSize));
            bufferSize = header.PackedSize;
        }

        file.read(buffer, header.PackedSize);

        char fileNameBuffer[225];
        snprintf(fileNameBuffer, sizeof(fileNameBuffer), "data_%d.cab", index++);

        std::cout << "Extracting: " << fileNameBuffer << std::endl;

        std::fstream output;
        output.open(fileNameBuffer, std::ios::out | std::ios::binary);
        output.write(buffer, header.PackedSize);
        output.close();

        peSize += header.PackedSize;
    }

    return 0;
}
