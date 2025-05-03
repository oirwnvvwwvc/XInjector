cmake_minimum_required(VERSION 3.31)
project(XInjector)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)

set(CUSTOM_OUTPUT_DIR ${CMAKE_BINARY_DIR}/../build/${CMAKE_BUILD_TYPE})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CUSTOM_OUTPUT_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CUSTOM_OUTPUT_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CUSTOM_OUTPUT_DIR}/lib)

function(codesign target_name entitlements_file)
    add_custom_command(
            TARGET ${target_name}
            POST_BUILD
            COMMAND /usr/bin/codesign -s - -f --entitlements ${entitlements_file} $<TARGET_FILE:${target_name}>
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            VERBATIM
    )
endfunction()


add_library(xinjector-payload SHARED xinjector_payload.c)
set_target_properties(xinjector-payload PROPERTIES OSX_ARCHITECTURES "arm64;arm64e;x86_64")
target_compile_options(xinjector-payload PRIVATE "-fno-exceptions" "-fno-unwind-tables")

add_executable(xinjector xinjector.c)
codesign(xinjector ${CMAKE_SOURCE_DIR}/devtool.plist)
target_compile_definitions(xinjector PRIVATE "__DARWIN_OPAQUE_ARM_THREAD_STATE64")
set_target_properties(xinjector PROPERTIES OSX_ARCHITECTURES "arm64;arm64e;x86_64")
target_link_libraries(xinjector PRIVATE xinjector-payload)

