# This file was automatically generated for projects
# without default 'CMakeLists.txt' file.

FILE(GLOB_RECURSE app_sources ${CMAKE_SOURCE_DIR}/src/*.*)

idf_component_register(SRCS ${app_sources})
target_compile_options(${COMPONENT_LIB} PRIVATE
    -Wall -Wextra
    -Wcast-align -Wcast-qual -Wdisabled-optimization -Wendif-labels -Wformat=2
    -Wformat-extra-args -Wformat-overflow=2 -Wformat-signedness
    -Wformat-truncation=2 -Winit-self -Winline -Winvalid-pch -Wjump-misses-init
    -Wlogical-op -Wmissing-declarations -Wmissing-include-dirs -Wpacked
    -Wpointer-arith -Wstrict-aliasing=3 -Wswitch-enum -Wswitch-default
    -Wwrite-strings -Wc++-compat -Wfloat-equal -Wconversion -Wredundant-decls
    -Wmissing-prototypes

    -Wno-sign-conversion

    -Werror=implicit-function-declaration -Werror=old-style-definition
    -Werror=nested-externs -Werror=strict-prototypes
)
