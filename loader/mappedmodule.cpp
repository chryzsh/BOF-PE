
#include <windows.h>
#include <vector>
#include <string>
#include <fstream>
#include <format>

#include "mappedmodule.h"

typedef void(WINAPI* dllmain_ptr)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

extern "C" PVOID NTAPI RtlEncodeSystemPointer(IN PVOID Pointer);

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


typedef struct _RTL_INVERTED_FUNCTION_TABLE {
    ULONG Count;
    ULONG MaxCount;
    ULONG Epoch;
    ULONG Overflow;
    INVERTED_FUNCTION_TABLE_ENTRY Entries[0x200];

}RTL_INVERTED_FUNCTION_TABLE;

//https://github.com/HoShiMin/formatPE - modified to be compatible with GCC compiler
#include "Pe.hpp"

//Typically each C2 provider will impement their own resolution
//method of beacon APIs.  Beacuse our loader is a POC, we simply
//use the comatibility layer beacon.dll directly
static FARPROC ResolveBeaconFunction(const char* beaconFunction){

    static auto beaconMod = LoadLibrary("beacon.dll");

    if(beaconMod == nullptr){
        throw std::string("Failed to find beacon.dll compatibility DLL");
    }

    //We dont need to resolve BeaconInvokeStandalone because
    //the method is only ever called when running standalone
    if (strcmp(beaconFunction, "BeaconInvokeStandalone") == 0)
        return nullptr;
    else
        return GetProcAddress(beaconMod, beaconFunction);
}

static void ProcessImports(const Pe::PeNative& pe) {

    //For POC purposes, import resolution does not currently support
    //forwarders or API sets.  This is left for the C2 implementation

    for (const auto& mod : pe.imports()) {

        auto modName = mod.libName();
        HMODULE currentModule = nullptr;

        if(strcmp(modName, "beacon.dll") != 0){
            currentModule = LoadLibraryA(modName);
            if (currentModule == nullptr) {
                throw std::format("Failed to load dependent libary {}", modName);
            }
        }

        for (const auto& imp : mod) {

             auto ptr = (FARPROC*)imp.importAddressTableEntry();

            if(currentModule != nullptr){
                //If the current import DLL is not beacon.dll, resolve functions as normal
                if (imp.type() == Pe::ImportType::name) {                   
                    *ptr = GetProcAddress(currentModule, imp.name()->Name);
                }else {
                    *ptr = GetProcAddress(currentModule, MAKEINTRESOURCE(imp.ordinal()));
                }

                if (*ptr == nullptr) {
                    throw std::format("Unresolved import {}!{}", modName, imp.type() == Pe::ImportType::name ? imp.name()->Name : MAKEINTRESOURCE(imp.ordinal()));
                }

            }else{
                //Current DLL is beacon.dll, resolve via internal C2 mechanism
                *ptr = ResolveBeaconFunction(imp.name()->Name);
            }
        }
    }
}

static void ProcessRelocations(const Pe::PeNative& pe, uintptr_t delta) {

    for (const auto& reloc : pe.relocs()) {
        for (const auto& entry : reloc) {
            switch (entry.reloc()->type()) {
                case Pe::RelocType::dir64: 
                    *((uintptr_t*)(entry.addr())) += delta;
                    break;
                case Pe::RelocType::highlow:
                    *(uint32_t*)(entry.addr()) += uint32_t(delta);
                    break;
                case Pe::RelocType::high:
                    *(int16_t*)(entry.addr()) += HIWORD(delta);
                    break;
                case Pe::RelocType::low:
                    *(int16_t*)(entry.addr()) += LOWORD(delta);
                    break;  
                case Pe::RelocType::absolute:
                    break;
                default:
                    throw std::format("Unhandled reloc type {}", entry.reloc()->rawType);
                    break;
            }
        }
    }
}

static void UpdateSectionPermissions(const Pe::PeNative& pe) {

    for (const auto& section : pe.sections()) {

        auto pagePermissions = PAGE_READONLY;
        auto oldPermissions = 1ul;
        
        if (section.Characteristics & IMAGE_SCN_CNT_CODE || section.Characteristics & IMAGE_SCN_MEM_EXECUTE) {            
            if (section.Characteristics & IMAGE_SCN_MEM_WRITE) {
                pagePermissions = PAGE_EXECUTE_WRITECOPY;
            }
            else {
                pagePermissions = PAGE_EXECUTE_READ;
            }
        }
        else if (section.Characteristics & IMAGE_SCN_MEM_WRITE) {
            pagePermissions = PAGE_READWRITE;
        }

        if(pagePermissions != PAGE_READWRITE)
            VirtualProtect(LPVOID(pe.byRva<void>(section.VirtualAddress)), section.SizeOfRawData, pagePermissions, &oldPermissions);
    }
}

static const Pe::GenericTypes::SecHeader* FindSection(const std::string& name, const Pe::PeNative& mappedPe) {

    for (auto& sec : mappedPe.sections()) {
        if (strncmp((const char*)sec.Name, name.c_str(), 8) == 0) {
            return &sec;
        }
    }
    return nullptr;
}

static const PVOID GetExceptionTables(const Pe::PeNative& mappedPe, ULONG& size) {

    size = (ULONG)(-1);
    auto result = PVOID(-1);

#if defined(_X86_)

    if (mappedPe.headers().opt()->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH)
        return result;
       
    auto loadConfigDir = mappedPe.directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
    auto loadConfig = mappedPe.byRva<IMAGE_LOAD_CONFIG_DIRECTORY32>(loadConfigDir->VirtualAddress);

    if (loadConfigDir->VirtualAddress && loadConfigDir->Size && loadConfig->SEHandlerCount && loadConfig->SEHandlerTable) {
        result = PVOID(loadConfig->SEHandlerTable);
        size = sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY) * loadConfig->SEHandlerCount;
    }
    else {
        result = nullptr;
        size = 0;
    }
         
#else

    result = (PVOID)mappedPe.exceptions().descriptor().ptr;
    size = mappedPe.exceptions().descriptor().size;

#endif

    return result;
}

static RTL_INVERTED_FUNCTION_TABLE* FindLdrpInvertedFunctionTable(uintptr_t& mrDataPtr, DWORD& mrDataSize) {

    auto ntPe = Pe::PeNative::fromModule(GetModuleHandle("ntdll.dll"));
    auto mrData = FindSection(".mrdata", ntPe);
    RTL_INVERTED_FUNCTION_TABLE* table = nullptr;

    if (mrData == nullptr) {
        return nullptr;
    }

    mrDataPtr = uintptr_t(ntPe.base()) + mrData->VirtualAddress;
    uintptr_t mrDataPtrEnd = mrDataPtr + mrData->SizeOfRawData;
    mrDataSize = mrData->SizeOfRawData;

    //Iterate through the .mrdata section of ntdll a byte at a time searching for the LdrpInvertedFunctionTable
    while (mrDataPtr++ < mrDataPtrEnd) {

        table = reinterpret_cast<RTL_INVERTED_FUNCTION_TABLE*>(mrDataPtr);

        // Basic checks for a candidate table, if these are out of range, 
        // it's not the table we are looking for
        if (table->MaxCount > 512 || table->MaxCount == 0 || table->Count == 0 || table->Count > table->MaxCount)
            continue;

        MEMORY_BASIC_INFORMATION mbi = {};

        // We only need to check the first entry in the table which is always ntdll.dll.  
        // If the entry has the following attributes, we have a candidate for further checks
        //  * Exception table is within the range of the image memory address space
        //  * The ImageBase is indeed allocated, valid and commited to memory  
        //  * The initial allocation of the memory range was allocated with WRX, which is typical of loaded modules
        if (table->Entries[0].FunctionTable < table->Entries[0].ImageBase ||
                uintptr_t(table->Entries[0].FunctionTable) >= uintptr_t(table->Entries[0].ImageBase) + table->Entries[0].SizeOfImage ||
                NtQueryVirtualMemory(GetCurrentProcess(), table->Entries[0].ImageBase, MemoryBasicInformation, &mbi, sizeof(mbi), nullptr) != 0 ||
                (mbi.State & MEM_COMMIT) == 0 ||
                (mbi.AllocationProtect != PAGE_EXECUTE_WRITECOPY))
            continue;

        //Now that we are fairy certain the ImageBase is ntdll, lets double check
        //by parsing the PE from memory and checking that it looks like a PE
        auto tablePe = Pe::PeNative::fromModule(table->Entries[0].ImageBase);
        auto exceptionTableSize = 0ul;
        auto exceptionTable = GetExceptionTables(tablePe, exceptionTableSize);

        // The final checks for the inverted function table:
        //  * Does the ImageBase memory contents looks like a PE
        //  * Does the imageSize of the parse PE match the entry within the table
        //  * Does the size of the execption information in the PE match that of the table
        //  * Does the address of the exception table from the PE match the entry in the table   
        if (!tablePe.valid() || 
                tablePe.imageSize() != table->Entries[0].SizeOfImage ||
                exceptionTableSize != table->Entries[0].SizeOfTable ||
                exceptionTable != table->Entries[0].FunctionTable)
            continue;

        break;
    }

    return table;
}


//http://uninformed.org/index.cgi?v=8&a=2&p=20
// Currently this only works for Windows 8+.  
// The RTL_INVERTED_FUNCTION_TABLE memory layout is different for x86 on older platforms
void RtlpInsertInvertedFunctionTableEntry(PVOID ImageBase, ULONG ImageSize, PVOID ExceptionDirectory, ULONG ExceptionDirectorySize) {

    uintptr_t mrData = 0;
    DWORD mrDataSize = 0;
    auto table = FindLdrpInvertedFunctionTable(mrData, mrDataSize);
    DWORD oldProtect = 0;

    if (table == nullptr) {
        throw std::runtime_error("[!] Failed to find LdrpInvertedFunctionTable\n");
    }
    
    VirtualProtect(PVOID(mrData), mrDataSize, PAGE_READWRITE, &oldProtect);

    auto entryIndex = 1;

    if (table->Count == table->MaxCount) {
        table->Overflow = 1;
    }
    else {

        InterlockedIncrement(&table->Epoch);
        entryIndex = 1;

        if (table->Count != 1) {
            while (entryIndex < table->Count) {
                if (ImageBase < table->Entries[entryIndex].ImageBase) {
                    break;
                }
                entryIndex++;
            }
        }

        if (entryIndex != table->Count) {
            memmove(&table->Entries[entryIndex + 1],
                &table->Entries[entryIndex],
                (table->Count - entryIndex) * sizeof(INVERTED_FUNCTION_TABLE_ENTRY));
        }
    }

    table->Entries[entryIndex].ImageBase = ImageBase;
    table->Entries[entryIndex].SizeOfImage = ImageSize;
#if defined(__x86_64__) || defined(_M_X64)
    table->Entries[entryIndex].FunctionTable = (IMAGE_RUNTIME_FUNCTION_ENTRY*)ExceptionDirectory;
#else
    //x86 function table addresses are masked for additional protection
    table->Entries[entryIndex].FunctionTable = (IMAGE_RUNTIME_FUNCTION_ENTRY*)RtlEncodeSystemPointer(ExceptionDirectory);
#endif
    table->Entries[entryIndex].SizeOfTable = ExceptionDirectorySize;
    table->Count++;
    InterlockedIncrement(&table->Epoch);

    VirtualProtect(PVOID(mrData), mrDataSize, oldProtect, &oldProtect);
}

void RtlpDeleteInvertedFunctionTableEntry(PVOID ImageBase) {

    uintptr_t mrData = 0;
    DWORD mrDataSize = 0;
    auto table = FindLdrpInvertedFunctionTable(mrData, mrDataSize);
    DWORD oldProtect = 0;

    if (table == nullptr) {
        throw std::runtime_error("[!] Failed to find LdrpInvertedFunctionTable\n");
    }

    VirtualProtect(PVOID(mrData), mrDataSize, PAGE_READWRITE, &oldProtect);

    auto entryIndex = 1;

    while (entryIndex < table->Count) {
        if (ImageBase == table->Entries[entryIndex].ImageBase) {
            break;
        }
        entryIndex++;
    }

    if (entryIndex <= table->Count) {
        if (entryIndex != table->Count) {

            InterlockedDecrement(&table->Epoch);
            auto moved_entries = table->Count - entryIndex;

            memmove(&table->Entries[entryIndex],
                &table->Entries[entryIndex + 1],
                moved_entries * sizeof(INVERTED_FUNCTION_TABLE_ENTRY));
        }
    }

    InterlockedDecrement(&table->Epoch);
    table->Overflow = 0;
    table->Count--;
}

static void AddExceptionSupport(const Pe::PeNative& mappedPe){

    auto exceptionTableSize = 0ul;
    auto exceptionTable = GetExceptionTables(mappedPe, exceptionTableSize);

#if defined(__x86_64__) || defined(_M_X64)
    //Add the runtime function table so that SEH/C++ exceptions work for x64 PE's
    RtlAddFunctionTable((PRUNTIME_FUNCTION)mappedPe.exceptions().descriptor().ptr, mappedPe.exceptions().descriptor().size / sizeof(RUNTIME_FUNCTION), DWORD64(mappedPe.base()));
#endif

    RtlpInsertInvertedFunctionTableEntry(PVOID(mappedPe.base()), mappedPe.imageSize(), exceptionTable, exceptionTableSize);      
}



void RemoveExceptionSupport(const Pe::PeNative& mappedPe) {

    auto exceptionTableSize = 0ul;
    auto exceptionTable = GetExceptionTables(mappedPe, exceptionTableSize);

#if defined(__x86_64__) || defined(_M_X64)
    //Add the runtime function table so that SEH/C++ exceptions work for x64 PE's
    RtlDeleteFunctionTable((PRUNTIME_FUNCTION)mappedPe.exceptions().descriptor().ptr);
#endif

    RtlpDeleteInvertedFunctionTableEntry(PVOID(mappedPe.base()));
}

static void TlsCallbacks(Logger logger, const Pe::PeNative& mappedPe){
        
    //Call each TLS callback to perform any initalization
    for(auto tls : mappedPe.tls()){
        logger("Calling TLS callback 0x%p\n", tls.callback_mapped());
        tls.callback_mapped()(PVOID(mappedPe.base()), DLL_PROCESS_ATTACH, nullptr);
    }
}

MappedModule::MappedModule(Logger logger, const std::vector<std::byte>& peBytes) : _mappedPe(Pe::ImgType::module, nullptr), _logger(logger) {

    auto pe = Pe::PeNative::fromFile(peBytes.data());

    if (!pe.valid()) {
        throw std::runtime_error("PE file is not valid");
    }

    //We try to allocate at the preferred base, this will save relocation later
    _mappedImage = VirtualAlloc((LPVOID)(pe.headers().opt()->ImageBase), pe.imageSize(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    //Preferred base was not available, so just allocate at any available address
    if (_mappedImage == nullptr) {
        _mappedImage = VirtualAlloc(nullptr, pe.imageSize(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    }

    _logger("Allocated image @ 0x%p\n", _mappedImage);

    if (_mappedImage == nullptr) {       
        throw std::bad_alloc();
    }

    try {

        //Wipe the mapped image space and copy the Pe headers across
        memset(_mappedImage, 0, pe.imageSize());
        memcpy(_mappedImage, pe.base(), pe.headers().nt()->OptionalHeader.SizeOfHeaders);

        //Now map each section into it's correct RVA location, ignoring the .discard section
        for (auto section : pe.sections()) {
            if (section.PointerToRawData && strncmp((const char*)section.Name, ".discard", 8) != 0) {
                memcpy(reinterpret_cast<void*>(uintptr_t(_mappedImage) + section.VirtualAddress), pe.byOffset<void*>(section.PointerToRawData), section.SizeOfRawData);
                _logger("Copied section %.8s @ 0x%p\n", section.Name, PVOID(uintptr_t(_mappedImage) + section.VirtualAddress));
            }
            else {
                _logger("Skipped .discard section @ 0x%p\n", PVOID(uintptr_t(_mappedImage) + section.VirtualAddress));
            }
        }

        //Now that we have laid out the PE in mapped form,
        //Parse the PE from memory
        _mappedPe = std::move(Pe::PeNative::fromModule(_mappedImage));

        //If our mapped base address doesn't match the preferred base
        //then process the reloc section
        if (uintptr_t(_mappedImage) != pe.headers().opt()->ImageBase) {
            ProcessRelocations(_mappedPe, uintptr_t(_mappedImage) - uintptr_t(pe.headers().opt()->ImageBase));
            _logger("Processed relocations\n");
        }
        else {
            _logger("Skipped relocations\n");
        }

        //Now process our import table, paying special attention to imports
        //from beacon.dll
        ProcessImports(_mappedPe);
        _logger("Processed imports\n");

        //Update the section permissions to expected values,
        //for example RX for the .text section
        UpdateSectionPermissions(_mappedPe);
        _logger("Set section permissions\n");

        AddExceptionSupport(_mappedPe);
        _logger("Added exception function tables\n");

        //Not a true TLS callback implementation as we should be adding entries
        //to ntdll's real TLS callback table, but good enough for our POC
        TlsCallbacks(logger, _mappedPe);

        if (_mappedPe.headers().nt()->FileHeader.Characteristics & IMAGE_FILE_DLL) {
            auto dllmain = dllmain_ptr(uintptr_t(_mappedPe.base()) + _mappedPe.headers().opt()->AddressOfEntryPoint);
            dllmain(HINSTANCE(_mappedPe.base()), DLL_PROCESS_ATTACH, 0);
        }
    }
    catch (...) {
        VirtualFree(_mappedImage, 0, MEM_RELEASE);
        throw;
    }
}

MappedModule::MappedModule(MappedModule&& other) noexcept : _mappedPe(Pe::ImgType::module, nullptr),
    _mappedImage(other._mappedImage), _loaded(other._loaded), _logger(other._logger) {

    //Take ownership of the mapped image, the moved from object
    //no longer releases it when destroyed
    _mappedPe = std::move(other._mappedPe);
    other._mappedImage = nullptr;
}

MappedModule& MappedModule::operator=(MappedModule&& other) noexcept {

    if (this != &other) {
        Release();
        _mappedPe = std::move(other._mappedPe);
        _mappedImage = other._mappedImage;
        _loaded = other._loaded;
        _logger = other._logger;
        other._mappedImage = nullptr;
    }

    return *this;
}

void MappedModule::Release() {

    //Moved from objects no longer own an image
    if (_mappedImage == nullptr)
        return;

    if (_mappedPe.headers().nt()->FileHeader.Characteristics & IMAGE_FILE_DLL) {
        auto dllmain = dllmain_ptr(uintptr_t(_mappedPe.base()) + _mappedPe.headers().opt()->AddressOfEntryPoint);
        dllmain(HINSTANCE(_mappedPe.base()), DLL_PROCESS_DETACH, 0);
    }

    RemoveExceptionSupport(_mappedPe);
    VirtualFree(_mappedImage, 0, MEM_RELEASE);
    _mappedImage = nullptr;
}

MappedModule::~MappedModule() {
    Release();
}

FARPROC MappedModule::GetProcAddress(const char* name) const {

    auto exp = _mappedPe.exports().find(name);

    if (exp.type() == Pe::ExportType::unknown)
        return nullptr;

    return (FARPROC)exp.address();   
}

const Pe::PeNative& MappedModule::GetModule() const {
    return _mappedPe;
}