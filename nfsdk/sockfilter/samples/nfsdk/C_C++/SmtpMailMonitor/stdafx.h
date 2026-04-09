// stdafx.h : include file for standard system include files
#pragma once

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#define _CRT_SECURE_NO_DEPRECATE 1
#define _CRT_SECURE_NO_WARNINGS 1
#define _WINSOCK_DEPRECATED_NO_WARNINGS 1

// Windows headers
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <objbase.h>

// C standard headers
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <direct.h>
#include <io.h>
#include <sys/stat.h>

// C++ standard headers
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <iostream>
#include <regex>
#include <crtdbg.h>
