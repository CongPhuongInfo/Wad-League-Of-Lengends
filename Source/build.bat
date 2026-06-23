@echo off
setlocal

echo +------------------------------------------+
echo ^|  RiotWadTool - Build Script (.NET 4.5)   ^|
echo +------------------------------------------+

:: ── Tìm csc.exe từ .NET Framework ──
set CSC=
for %%v in (4.0.30319) do (
    if exist "%WINDIR%\Microsoft.NET\Framework64\v%%v\csc.exe" (
        set CSC=%WINDIR%\Microsoft.NET\Framework64\v%%v\csc.exe
    ) else if exist "%WINDIR%\Microsoft.NET\Framework\v%%v\csc.exe" (
        set CSC=%WINDIR%\Microsoft.NET\Framework\v%%v\csc.exe
    )
)

if "%CSC%"=="" (
    echo [!] Khong tim thay csc.exe
    echo     Dam bao may da cai .NET Framework 4.x
    echo     Thuong nam o: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
    pause & exit /b 1
)

echo [*] Dung compiler: %CSC%

:: ── Tham chiếu ZstdNet nếu có ──
set REFS=-r:System.dll -r:System.Core.dll
if exist "ZstdNet.dll" (
    echo [*] Tim thay ZstdNet.dll - bat ho tro Zstd
    set REFS=%REFS% -r:ZstdNet.dll
) else (
    echo [~] Khong co ZstdNet.dll - Zstd se bao loi khi dung
)

:: ── Build ──
if not exist "bin" mkdir bin

"%CSC%" ^
    -out:bin\RiotWadTool.exe ^
    -target:exe ^
    -optimize+ ^
    -platform:anycpu ^
    %REFS% ^
    Program.cs

if errorlevel 1 (
    echo.
    echo [!] Build THAT BAI
    pause & exit /b 1
)

:: ── Copy ZstdNet DLLs nếu có ──
if exist "ZstdNet.dll"   copy /Y "ZstdNet.dll"   "bin\" >nul
if exist "x64\libzstd.dll" (
    if not exist "bin\x64" mkdir "bin\x64"
    copy /Y "x64\libzstd.dll" "bin\x64\" >nul
)
if exist "x86\libzstd.dll" (
    if not exist "bin\x86" mkdir "bin\x86"
    copy /Y "x86\libzstd.dll" "bin\x86\" >nul
)

echo.
echo [OK] Build thanh cong: bin\RiotWadTool.exe
echo.
echo  Vi du su dung:
echo    bin\RiotWadTool.exe unpack Scripts.wad.client
echo    bin\RiotWadTool.exe list   Scripts.wad.client
echo    bin\RiotWadTool.exe pack   C:\mods\Scripts output.wad.client
echo.
pause
