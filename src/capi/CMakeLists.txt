# The C API as a shared library: what FFI callers (Dart, Python, Rust, C#)
# load. Every other layer links in statically, so this one file -- plus, on
# MinGW, the runtime DLL bundled beside it -- is all an application ships.
add_library(uconnect_c SHARED uconnect_c.cpp)
target_include_directories(uconnect_c PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(uconnect_c PRIVATE uconnect)
target_compile_definitions(uconnect_c PRIVATE UCONNECT_C_BUILD)

# Export only what uconnect_c.h marks UCONNECT_API.
set_target_properties(uconnect_c PROPERTIES
    C_VISIBILITY_PRESET      hidden
    CXX_VISIBILITY_PRESET    hidden
    VISIBILITY_INLINES_HIDDEN ON)

# The static libraries were not built with hidden visibility, so on ELF their
# symbols would be re-exported; this keeps them out of the dynamic table. (PE
# exports only what is marked dllexport, and Mach-O is handled by the preset.)
if (UNIX AND NOT APPLE)
    target_link_options(uconnect_c PRIVATE "LINKER:--exclude-libs,ALL")
endif()

# MinGW would call it libuconnect_c.dll. uconnect_c.dll is the name MSVC
# gives it, and the one a Windows caller will try to load.
if (WIN32)
    set_target_properties(uconnect_c PROPERTIES PREFIX "")
endif()

uconnect_bundle_runtime(uconnect_c)
