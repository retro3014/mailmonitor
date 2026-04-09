cd /d %~dp0

echo Installing the driver build for 64-bit systems

rem Copy the driver to system folder
copy driver\x64\sockfilter.sys %windir%\system32\drivers

rem Register the driver
release\Win32\nfregdrv.exe sockfilter

pause