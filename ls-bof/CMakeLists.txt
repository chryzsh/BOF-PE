
add_executable(ls-bof main.cpp)

target_include_directories(ls-bof PRIVATE ${CMAKE_SOURCE_DIR}/beacon)
target_link_libraries(ls-bof beacon)

if (CMAKE_C_COMPILER_ID MATCHES "MSVC|Clang")
    target_compile_options(ls-bof PRIVATE /GS- /MT)
    target_link_options(ls-bof PRIVATE /MERGE:.gfids=. /MERGE:_RDATA=. /MERGE:.data=. /MERGE:.rdata=. /MERGE:.pdata=. /SECTION:.,RW /MERGE:.discard_data=.discard)

    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        target_link_options(ls-bof PRIVATE /SAFESEH)
    endif()

else()
    target_link_options(ls-bof PRIVATE -static)
    target_link_options(ls-bof PRIVATE -fno-unwind-tables -fno-asynchronous-unwind-tables -falign-functions=1 -fno-exceptions -fno-rtti -T${LINK_SCRIPT} -Wl,--strip-all)
endif()
