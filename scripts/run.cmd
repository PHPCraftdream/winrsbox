@echo off
:: Anchored to the repository root: this script addresses bin/ and workdir/
:: relative to the repo, not to wherever it was invoked from. It used to sit
:: in the root, so cwd and script location were the same thing; after the move
:: into scripts/ they are not, and without this it would only work when called
:: from exactly one directory.
pushd "%~dp0.." || exit /b 1
pushd bin || (echo run scriptsuild.cmd first & exit /b 1)
if exist sandbox-root rmdir /S /Q sandbox-root
if exist inside.txt del inside.txt
if exist inside-from-child.txt del inside-from-child.txt
winrsbox.exe -d -- ..\workdir\bin\target-app.exe
echo.
echo === sandbox-root contents ===
dir /S /B sandbox-root 2>nul || echo (empty)
echo.
echo === escape check ===
if exist ..\escape.txt (echo FAIL: escape.txt LEAKED outside) else (echo OK: escape.txt not outside)
if exist ..\child-escape.txt (echo FAIL: child-escape.txt LEAKED outside) else (echo OK: child-escape.txt not outside)
echo.
echo === project_root passthrough check ===
if exist inside.txt (echo OK: inside.txt in project_root) else (echo FAIL: inside.txt missing from project_root)
popd
