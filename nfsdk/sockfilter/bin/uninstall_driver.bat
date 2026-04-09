cd /d %~dp0

rem Uninstall the network hooking driver

rem Try to unload the driver
sc stop sockfilter

rem Unregister the driver
release\win32\nfregdrv.exe -u sockfilter

rem Delete driver file
del %windir%\system32\drivers\sockfilter.sys


pause