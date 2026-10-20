add_executable(procwatch main.cpp)

target_include_directories(procwatch PRIVATE ${CMAKE_SOURCE_DIR}/beacon)
target_link_libraries(procwatch beacon)

if (CMAKE_C_COMPILER_ID MATCHES "MSVC|Clang")
    target_compile_options(procwatch PRIVATE /GS- /MT /EHa)
    target_link_options(procwatch PRIVATE /MERGE:.gfids=. /MERGE:_RDATA=. /MERGE:.data=. /MERGE:.rdata=. /MERGE:.pdata=. /SECTION:.,RW /MERGE:.discard_data=.discard)

    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        target_link_options(procwatch PRIVATE /SAFESEH)
    endif()

else()
    target_link_options(procwatch PRIVATE -fexceptions -static -T${LINK_SCRIPT} -Wl,--strip-debug)
endif()
