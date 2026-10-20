cmake_minimum_required(VERSION 3.18)
project(bof-pe )

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

message("-- Building for ${CMAKE_CXX_COMPILER_ID} compiler")

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(LINK_SCRIPT ${CMAKE_SOURCE_DIR}/link.ld)
    set(ARCH x64)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(LINK_SCRIPT ${CMAKE_SOURCE_DIR}/link32.ld)
    set(ARCH x86)
endif()

include_directories(${CMAKE_SOURCE_DIR}/beacon/)

add_subdirectory(beacon)
add_subdirectory(loader)
add_subdirectory(tiny-pe)
add_subdirectory(c-pe)
add_subdirectory(cpp-pe)

# Install a BOF-PE twice: <arch>/<name>.exe for standalone runs next to
# beacon.dll, and pe/<name>.<arch>.o, the name OC2 uses to look up a BOF
function(install_bof_pe target)
    install(TARGETS ${target} RUNTIME DESTINATION ${ARCH})
    install(FILES $<TARGET_FILE:${target}> DESTINATION pe RENAME ${target}.${ARCH}.o)
endfunction()

install(TARGETS beacon loader RUNTIME DESTINATION ${ARCH} LIBRARY DESTINATION ${ARCH} ARCHIVE EXCLUDE_FROM_ALL)
install_bof_pe(tiny-pe)
install_bof_pe(c-pe)
install_bof_pe(cpp-pe)
