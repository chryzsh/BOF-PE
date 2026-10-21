# Async BOF-PEs are built as DLLs that export go. OC2 runs a BOF-PE (.dll),
# and loader.exe runs the same DLL for standalone tests.
add_library(procwatch SHARED main.cpp)
set_target_properties(procwatch PROPERTIES PREFIX "")

target_compile_definitions(procwatch PRIVATE BOF_PE_DLL)
target_include_directories(procwatch PRIVATE ${CMAKE_SOURCE_DIR}/beacon)
target_link_libraries(procwatch beacon)

if (CMAKE_C_COMPILER_ID MATCHES "MSVC|Clang")
    target_compile_options(procwatch PRIVATE /GS- /MT /EHa)
    target_link_options(procwatch PRIVATE /MERGE:.gfids=. /MERGE:_RDATA=. /MERGE:.data=. /MERGE:.rdata=. /MERGE:.pdata=. /SECTION:.,RW /MERGE:.discard_data=.discard)

    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        target_link_options(procwatch PRIVATE /SAFESEH)
    endif()

else()
    # -static links libgcc and libstdc++ into the DLL, so its only runtime
    # dependency is msvcrt.dll. The default MinGW DLL linker script is used,
    # link.ld is for the EXE model.
    target_compile_options(procwatch PRIVATE -fexceptions)
    target_link_options(procwatch PRIVATE -fexceptions -static -static-libgcc -static-libstdc++ -s -Wl,--subsystem,windows)
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        target_link_options(procwatch PRIVATE -Wl,--image-base=0x180000000)
    endif()
endif()
