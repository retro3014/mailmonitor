cd /d %~dp0

echo Installing the driver build for 32-bit systems

rem Copy the driver to system folder
copy driver\Win32\netfilter2.sys %windir%\system32\drivers

rem Register the driver
release\win32\nfregdrv.exe netfilter2

pause