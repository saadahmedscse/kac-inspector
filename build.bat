@echo off
:: Builds a release binary of KAC Inspector and copies it next to this script.
setlocal
cd /d "%~dp0"

where cargo >nul 2>&1 || (
    echo  cargo not found. Install Rust from https://rustup.rs and try again.
    pause
    exit /b 1
)

echo  Building KAC Inspector (release)...
cargo build --release || (
    echo.
    echo  Build FAILED.
    pause
    exit /b 1
)

copy /y "target\release\kac-inspector.exe" "KAC Inspector.exe" >nul
echo.
echo  Done: %~dp0KAC Inspector.exe
pause
