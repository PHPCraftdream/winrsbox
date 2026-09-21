@echo off
setlocal
:: Anchored to the repository root: this script addresses bin/ and workdir/
:: relative to the repo, not to wherever it was invoked from. It used to sit
:: in the root, so cwd and script location were the same thing; after the move
:: into scripts/ they are not, and without this it would only work when called
:: from exactly one directory.
pushd "%~dp0.." || exit /b 1
if not exist bin mkdir bin
if not exist workdir\bin mkdir workdir\bin
pushd workdir\target-app && go build -o ..\bin\target-app.exe . && popd || exit /b 1
pushd workdir\go-chain    && go build -o ..\bin\chain.exe              . && popd || exit /b 1
pushd workdir\go-cwd-child && go build -o ..\bin\cwd-child.exe         . && popd || exit /b 1
pushd winrsbox            && cargo build --release 2>&1                && popd || exit /b 1
copy /Y winrsbox\target\release\hook.dll                    bin\ >nul
copy /Y winrsbox\target\release\winrsbox.exe                bin\ >nul
copy /Y winrsbox\target\release\integration-tests.exe workdir\bin\ >nul
echo.
echo === built ok ===
