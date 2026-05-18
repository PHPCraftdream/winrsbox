@echo off
setlocal
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
