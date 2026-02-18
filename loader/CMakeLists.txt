enable_language(ASM)

add_library(dwmapi SHARED
    dwmapi.cpp
    trampolines.S
    dwmapi.def
)

target_link_options(dwmapi PRIVATE
    -Wl,--enable-stdcall-fixup
    -nostdlib
    -Wl,-e,DllMain
    -lkernel32
    -luser32
)

set_target_properties(dwmapi PROPERTIES
    PREFIX ""
    OUTPUT_NAME "dwmapi"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
)
