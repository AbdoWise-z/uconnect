# Source this to get a usable toolchain on PATH.
#
# On Windows the CLion-bundled toolchain is not on PATH in a normal shell, so
# add it. On Linux/macOS the system compiler is already there and this is a
# no-op -- the script must stay sourceable on every platform, because
# scripts/smoke.sh relies on it.
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
        CLION="${UCONNECT_TOOLCHAIN:-/c/Program Files/JetBrains/CLion 2026.2.2}"
        if [ -d "$CLION" ]; then
            export PATH="$CLION/bin/cmake/win/x64/bin:$CLION/bin/mingw/bin:$CLION/bin/ninja/win/x64:$PATH"
        fi
        ;;
esac

# Executables carry .exe on Windows and nothing elsewhere.
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) export EXE=".exe" ;;
    *)                    export EXE="" ;;
esac
