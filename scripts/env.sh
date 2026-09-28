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

# wait_listening <server-log> <pid> [seconds]: block until the server has
# opened its port. It runs a STUN probe before that, which takes seconds when
# nothing answers, so a fixed sleep races it -- and a node started too early
# spends its first seconds backing off between refused connections.
wait_listening() {
    local log="$1" pid="$2" secs="${3:-20}" i
    for ((i = 0; i < secs * 10; ++i)); do
        grep -q "listening on" "$log" 2>/dev/null && return 0
        kill -0 "$pid" 2>/dev/null || return 1
        sleep 0.1
    done
    return 1
}
