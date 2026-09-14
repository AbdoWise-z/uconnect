# Configure, build and test from PowerShell.
#
# The CLion-bundled toolchain is not on PATH in a normal shell, so this puts it
# there for the duration of the script. Adjust $Clion if your CLion lives
# elsewhere, or set UCONNECT_TOOLCHAIN to a directory containing bin/cmake,
# bin/mingw and bin/ninja.
#
#   .\scripts\build.ps1              configure + build + unit tests
#   .\scripts\build.ps1 -All         also run the end-to-end smoke test
#   .\scripts\build.ps1 -Clean       wipe build/ first

param(
    [switch]$All,
    [switch]$Clean,
    [string]$BuildType = "Debug"
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

$clion = $env:UCONNECT_TOOLCHAIN
if (-not $clion) {
    $candidates = @(
        "C:\Program Files\JetBrains\CLion 2026.2.2",
        "C:\Program Files\JetBrains\CLion 2024.3.2"
    )
    # Also accept any other CLion install, newest first.
    $candidates += (Get-ChildItem "C:\Program Files\JetBrains" -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -like "CLion*" } |
                    Sort-Object Name -Descending |
                    ForEach-Object { $_.FullName })
    foreach ($c in $candidates) {
        if (Test-Path (Join-Path $c "bin\cmake\win\x64\bin\cmake.exe")) { $clion = $c; break }
    }
}

if (-not $clion) {
    Write-Error "Could not find a CLion toolchain. Set UCONNECT_TOOLCHAIN to your CLion install directory, or install CMake, a C++20 compiler and Ninja and put them on PATH."
}

$env:PATH = "$clion\bin\cmake\win\x64\bin;$clion\bin\mingw\bin;$clion\bin\ninja\win\x64;$env:PATH"

Write-Host "toolchain: $clion"
& cmake --version | Select-Object -First 1
& g++ --version | Select-Object -First 1

if ($Clean -and (Test-Path build)) {
    Write-Host "removing build/"
    Remove-Item -Recurse -Force build
}

& cmake -S . -B build -G Ninja "-DCMAKE_BUILD_TYPE=$BuildType" -DUCONNECT_BUILD_TESTS=ON
if ($LASTEXITCODE -ne 0) { Write-Error "configure failed" }

& cmake --build build
if ($LASTEXITCODE -ne 0) { Write-Error "build failed" }

if ($All) {
    # The smoke test is a bash script: it starts a server and two peers and
    # asserts they punch, handshake and exchange data.
    & ctest --test-dir build --output-on-failure
} else {
    & ctest --test-dir build --output-on-failure -E uconnect_smoke
}
if ($LASTEXITCODE -ne 0) { Write-Error "tests failed" }

Write-Host ""
Write-Host "built:"
Write-Host "  build\server\uconnect-rendezvous.exe"
Write-Host "  build\examples\uconn-demo.exe"
