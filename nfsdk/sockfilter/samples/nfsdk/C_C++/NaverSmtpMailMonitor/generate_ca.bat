@echo off
REM ============================================================
REM  generate_ca.bat
REM  Generate a self-signed CA certificate for TLS MITM proxy
REM  (Similar to Fiddler's "DO_NOT_TRUST_FiddlerRoot" CA)
REM
REM  Requirements: OpenSSL must be installed and in PATH
REM    - Download: https://slproweb.com/products/Win32OpenSSL.html
REM    - Or via vcpkg: vcpkg install openssl:x64-windows
REM
REM  Output files:
REM    ca_key.pem   - CA private key (DO NOT share or commit!)
REM    ca_cert.pem  - CA certificate (install to Windows trust store)
REM
REM  SECURITY WARNING:
REM    - ca_key.pem must NEVER be uploaded to GitHub or shared
REM    - ca_cert.pem is safe to share but should be removed from
REM      the trust store when no longer needed
REM ============================================================

set CA_KEY=ca_key.pem
set CA_CERT=ca_cert.pem
set CA_DAYS=3650
set CA_SUBJECT=/CN=SmtpMailMonitor Proxy CA/O=SmtpMailMonitor/OU=Development
set CA_EXT_FILE=ca_ext.cnf

echo ============================================================
echo  SmtpMailMonitor - CA Certificate Generator
echo ============================================================
echo.

REM Check if OpenSSL is available (try PATH first, then known install paths)
set OPENSSL_CMD=openssl
where openssl >nul 2>&1
if %ERRORLEVEL% neq 0 (
    if exist "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" (
        set "OPENSSL_CMD=C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
        echo [INFO] OpenSSL found at: C:\Program Files\OpenSSL-Win64\bin
    ) else if exist "C:\OpenSSL-Win64\bin\openssl.exe" (
        set "OPENSSL_CMD=C:\OpenSSL-Win64\bin\openssl.exe"
        echo [INFO] OpenSSL found at: C:\OpenSSL-Win64\bin
    ) else (
        echo [ERROR] OpenSSL not found!
        echo         Please install OpenSSL first:
        echo         - https://slproweb.com/products/Win32OpenSSL.html
        echo.
        pause
        exit /b 1
    )
) else (
    echo [INFO] OpenSSL found in PATH
)

REM Check if files already exist
if exist %CA_KEY% (
    echo [WARNING] %CA_KEY% already exists.
    echo          Generating new keys will invalidate existing certificates.
    set /p CONFIRM="Overwrite? (y/N): "
    if /i not "%CONFIRM%"=="y" (
        echo Cancelled.
        pause
        exit /b 0
    )
)

echo [1/4] Generating CA private key (RSA 2048)...
"%OPENSSL_CMD%" genrsa -out %CA_KEY% 2048
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to generate CA key!
    pause
    exit /b 1
)
echo       OK: %CA_KEY%

echo.
echo [2/4] Creating CA extensions config...
(
echo [req]
echo distinguished_name = req_dn
echo x509_extensions = v3_ca
echo prompt = no
echo.
echo [req_dn]
echo CN = SmtpMailMonitor Proxy CA
echo O = SmtpMailMonitor
echo OU = Development
echo.
echo [v3_ca]
echo basicConstraints = critical, CA:TRUE
echo keyUsage = critical, keyCertSign, cRLSign
echo subjectKeyIdentifier = hash
echo authorityKeyIdentifier = keyid:always, issuer
) > %CA_EXT_FILE%
echo       OK: %CA_EXT_FILE%

echo.
echo [3/4] Generating self-signed CA certificate with extensions (valid %CA_DAYS% days)...
"%OPENSSL_CMD%" req -x509 -new -nodes -key %CA_KEY% -sha256 -days %CA_DAYS% -out %CA_CERT% -config %CA_EXT_FILE%
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to generate CA certificate!
    del %CA_EXT_FILE% 2>nul
    pause
    exit /b 1
)
del %CA_EXT_FILE% 2>nul
echo       OK: %CA_CERT%

echo.
echo [4/4] Installing CA certificate to Windows trust store...
echo       (This requires Administrator privileges)
echo.
certutil -addstore -f Root %CA_CERT%
if %ERRORLEVEL% neq 0 (
    echo.
    echo [WARNING] Failed to install certificate.
    echo          Please run this script as Administrator, or manually:
    echo          certutil -addstore Root %CA_CERT%
) else (
    echo       OK: Certificate installed to "Trusted Root Certification Authorities"
)

echo.
echo ============================================================
echo  Done!
echo.
echo  Files generated:
echo    %CA_KEY%   - CA private key (KEEP SECRET!)
echo    %CA_CERT%  - CA certificate (installed to trust store)
echo.
echo  IMPORTANT:
echo    - Do NOT commit %CA_KEY% to version control
echo    - The .gitignore file should already exclude *.pem files
echo    - To remove the CA later:
echo      certutil -delstore Root "SmtpMailMonitor Proxy CA"
echo ============================================================
echo.
pause
