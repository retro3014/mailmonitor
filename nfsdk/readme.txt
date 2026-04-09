NetFilter SDK Demo
=====================================

wfp - client side WFP driver demo with API binaries and samples.

sockfilter - client side SockFilter driver demo with API binaries and samples.

server - server side gateway driver demo with API binaries and samples.

The demo drivers have a limitation on the number of filtered TCP connections and UDP sockets. 
After exceeding this limit the filtering continues again after system reboot.

The instructions for ordering a license for full version or source code:
http://www.netfiltersdk.com/buy_now.html

Package contents
=====================================

Each driver folder includes the following:

bin\Release - x86 and x64 versions of APIs with C++ interface, pre-built samples and the driver registration utility.
bin\Release_c_api - x86 and x64 versions of APIs with C interface, pre-built samples and the driver registration utility.
bin\driver - the demo driver binaries for x86 and x64 platforms.
lib - API lib files for linking C/C++ applications
samples - the examples of using APIs in C/C++/Deplhi/.NET
help - API documentation.


Driver installation
=====================================
Use the scripts bin\install_driver_32bit.bat and bin\install_driver_64bit.bat for installing and registering the driver on x86 and x64 systems respectively. 
The script install_driver_auto.bat detects the required build automatically.
The driver starts immediately and reboot is not required.

Run bin\uninstall_driver.bat to remove the driver from system.

The elevated administrative rights must be activated explicitly for registering the driver (run the scripts using "Run as administrator" context menu item in Windows Explorer). 

For Windows 7 and later versions of the Windows family of operating systems, kernel-mode software must have a digital signature. 
The included driver binaries are signed. But the drivers in Standard and Full sources versions are not signed.
For the end-user software you have to obtain the Code Signing certificate and sign the driver.

Supported platforms: 
    WFP driver: Windows 7/8/10/11 x86/x64
    SockFilter driver: Windows 8/10/11 x86/x64
    Gateway driver: Windows 8/10/11 x86/x64
