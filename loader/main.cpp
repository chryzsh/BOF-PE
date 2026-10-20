
#include <string>
#include <fstream>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <algorithm>
#include <windows.h>
#include <format>
#include "mappedmodule.h"

typedef void(WINAPI* dllmain_ptr)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

extern "C" PVOID NTAPI RtlEncodeSystemPointer(IN PVOID Pointer);

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

extern "C" NTSTATUS NTAPI NtQueryVirtualMemory(
     HANDLE                   ProcessHandle,
     PVOID                    BaseAddress,
     MEMORY_INFORMATION_CLASS MemoryInformationClass,
     PVOID                    MemoryInformation,
     SIZE_T                   MemoryInformationLength,
     PSIZE_T                  ReturnLength
);

typedef struct _INVERTED_FUNCTION_TABLE_ENTRY
{
    struct _IMAGE_RUNTIME_FUNCTION_ENTRY* FunctionTable;                    
    VOID* ImageBase;                                                       
    ULONG SizeOfImage;  
    ULONG SizeOfTable; 
}INVERTED_FUNCTION_TABLE_ENTRY;


typedef struct _RTL_INVERTED_FUNCTION_TABLE{
    ULONG Count;
    ULONG MaxCount;
    ULONG Pad[2];
    INVERTED_FUNCTION_TABLE_ENTRY Entries[0x200];

}RTL_INVERTED_FUNCTION_TABLE;

typedef void(*bof_entry_ptr)(const char* args, int len);

//https://github.com/HoShiMin/formatPE - modified to be compatible with GCC compiler
#include "Pe.hpp"

//https://stackoverflow.com/questions/51352863/what-is-the-idiomatic-c17-standard-approach-to-reading-binary-files
std::vector<std::byte> LoadFile(std::string const& filepath)
{
    std::ifstream ifs(filepath, std::ios::binary|std::ios::ate);

    if(!ifs)
        throw std::runtime_error(filepath + ": " + std::strerror(errno));

    auto end = ifs.tellg();
    ifs.seekg(0, std::ios::beg);

    auto size = std::size_t(end - ifs.tellg());

    if(size == 0) // avoid undefined behavior
        return {};

    std::vector<std::byte> buffer(size);

    if(!ifs.read((char*)buffer.data(), buffer.size()))
        throw std::runtime_error(filepath + ": " + std::strerror(errno));

    return buffer;
}


int GetPackedArguments(int argc, const char* argv[], const char* bof_args_def, std::string& result);

int main(int argc, char** argv){

    if(argc < 2){
        puts("Not enough arguments to load BOF PE file.\nloader pefile [fmt [arg1] [arg2] ...]");
        return -1;
    }

    try {
        const auto pe = MappedModule(printf, LoadFile(argv[1]));

        if (pe.GetModule().exports().count() > 0) {

            //Prefer the conventional 'go' export, otherwise fall back
            //to the first exported function
            auto entry = bof_entry_ptr(pe.GetProcAddress("go"));
            if (entry == nullptr) {
                entry = bof_entry_ptr(pe.GetModule().exports().begin()->address());
                printf("No 'go' export found, using first export\n");
            }

            if (argc - 2 <= 0) {
                //If we have less than 2 arguments, then no BOF arguments were provided
                printf("Calling BOF PE entry @ %p with no arguments\n", entry);
                entry(nullptr, 0);
            }
            else {
                //BOF arguments were provided, so pack them to the specification given
                std::string args;
                if (GetPackedArguments(argc - 2, (const char**)&argv[2], argv[2], args) >= 0) {
                    printf("Calling BOF PE entry @ %p with arguments @ %p and size %d\n", entry, args.data(), (int)args.size());

                    entry(args.data(), args.length());
                }
                else
                    puts("Failed to pack BOF arguments");
            }

        }
        else {
            puts("No exported function from BOF-PE, don't know what to call");
        }

        puts("Press enter to exit...\n");
        getchar();
    }
    catch (const std::string& message) {
        printf("%s\n", message.c_str());
    }
    catch (const std::exception& ex) {
        printf("%s\n", ex.what());
    }

    return 0;
}
