# The C API as a shared library: what FFI callers (Dart, Python, Rust, C#)
# load. Every other layer links in statically, so this one file -- plus, on
# MinGW, the runtime DLL bundled beside it -- is all an application ships.
add_library(uconnect_c SHARED uconnect_c.cpp)
target_include_directories(uconnect_c PUBLIC ${PROJECT_SOURCE_DIR}/include)
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

# --- packaging ---------------------------------------------------------------
# What an application ships is this one library and its header. On Apple
# platforms it can be built as a framework, which is the only form iOS accepts
# an app's own dynamic code in (a bare .dylib is refused by the App Store and
# cannot be embedded); it is the default there. scripts/build-xcframework.sh
# folds a device and a simulator build of it into one XCFramework.
if (CMAKE_SYSTEM_NAME MATCHES "^(iOS|tvOS|watchOS|visionOS)$")
    set(_uconnect_framework ON)
else()
    set(_uconnect_framework OFF)
endif()
option(UCONNECT_CAPI_FRAMEWORK "Build uconnect_c as a framework (Apple platforms)" ${_uconnect_framework})
set(UCONNECT_FRAMEWORK_IDENTIFIER "dev.uconnect.uconnect-c" CACHE STRING
    "Bundle identifier of the uconnect_c framework")

# The header is listed as a source as well: only then do the Ninja and Makefile
# generators copy it into a framework's Headers folder.
target_sources(uconnect_c PRIVATE ${PROJECT_SOURCE_DIR}/include/uconnect/uconnect_c.h)
set_target_properties(uconnect_c PROPERTIES
    PUBLIC_HEADER ${PROJECT_SOURCE_DIR}/include/uconnect/uconnect_c.h)
if (APPLE AND UCONNECT_CAPI_FRAMEWORK)
    set_target_properties(uconnect_c PROPERTIES
        FRAMEWORK TRUE
        MACOSX_FRAMEWORK_IDENTIFIER ${UCONNECT_FRAMEWORK_IDENTIFIER}
        MACOSX_FRAMEWORK_SHORT_VERSION_STRING ${PROJECT_VERSION}
        MACOSX_FRAMEWORK_BUNDLE_VERSION ${PROJECT_VERSION}
        MACOSX_FRAMEWORK_INFO_PLIST ${CMAKE_CURRENT_SOURCE_DIR}/framework-Info.plist.in)
endif()

# `cmake --install` lays out the library (or framework) and the C header. The
# C++ layers are static libraries linked into it and are not installed: an
# application that wants the C++ API builds the library as part of itself.
include(GNUInstallDirs)
install(TARGETS uconnect_c
    RUNTIME       DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY       DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE       DESTINATION ${CMAKE_INSTALL_LIBDIR}
    FRAMEWORK     DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/uconnect)
