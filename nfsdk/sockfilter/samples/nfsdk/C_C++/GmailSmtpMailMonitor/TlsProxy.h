/*
 * TlsProxy.h
 * ===========
 * TLS MITM proxy for SMTP and HTTPS traffic (Fiddler-style interception).
 *
 * Architecture:
 *   1. Listens on a local port (e.g., 10465)
 *   2. When a mail client connects (redirected by NetFilterSDK):
 *      a) Looks up the original server address
 *      b) Connects to the real server with TLS (proxy as TLS client)
 *      c) Accepts TLS from the client using a dynamically
 *         generated certificate (proxy as TLS server)
 *      d) Relays plaintext between both sides
 *      e) Feeds plaintext data to parser for logging/blocking
 *
 *   Supports:
 *     - Implicit TLS (port 465): TLS from connection start (SMTP)
 *     - STARTTLS (port 587): plaintext first, then TLS upgrade (SMTP)
 *     - HTTPS (port 443): TLS interception for web Gmail
 *       Uses HttpParser + GmailWebParser to extract email data
 *       from Gmail web API responses (mail.google.com/sync/...)
 *
 * Dependencies: OpenSSL, CertGenerator.h, SmtpParser.h,
 *               HttpParser.h, GmailWebParser.h
 */

#ifndef TLS_PROXY_H
#define TLS_PROXY_H

#include "CertGenerator.h"
#include "SmtpParser.h"
#include "HttpParser.h"
#include "GmailWebParser.h"
#include "JsonWriter.h"
#include "GuidUtil.h"

#include <process.h>  // _beginthreadex
#include <set>

// Forward declaration: logEmail and checkPiiInContent are in SmtpMailMonitor.cpp
extern void logEmailFromProxy(const ParsedEmail& email, bool blocked,
    const std::string& blockReason, int matchCount, const std::string& matchedPattern,
    const std::string& sourceInfo, const std::string& destInfo);
extern bool checkPiiAndBlock(const ParsedEmail& email, std::string& ruleName,
    int& matchCount, std::string& matchedPattern);

// Helper: int to string (avoid std::to_string for compatibility)
static std::string intToStr2(int val)
{
    char buf[32];
    _snprintf(buf, sizeof(buf), "%d", val);
    return std::string(buf);
}

// =============================================
//  Original destination tracking
// =============================================
// Maps client source port -> original remote address info
struct OriginalDest
{
    std::string hostname;     // Resolved hostname (e.g., "smtp.gmail.com")
    std::string ip;           // Original IP address
    unsigned short port;      // Original port (465, 587, 25, 443)
    bool implicitTls;         // true for port 465, false for 587/25
    bool isHttps;             // true for port 443 (web Gmail interception)

    OriginalDest() : port(0), implicitTls(false), isHttps(false) {}
};

static CRITICAL_SECTION g_destMapLock;
static std::map<unsigned short, OriginalDest> g_originalDestMap;
static bool g_destMapInitialized = false;

static void initDestMap()
{
    if (!g_destMapInitialized)
    {
        InitializeCriticalSection(&g_destMapLock);
        g_destMapInitialized = true;
    }
}

static void saveOriginalDest(unsigned short localPort, const OriginalDest& dest)
{
    EnterCriticalSection(&g_destMapLock);
    g_originalDestMap[localPort] = dest;
    LeaveCriticalSection(&g_destMapLock);
}

static bool getOriginalDest(unsigned short localPort, OriginalDest& dest)
{
    EnterCriticalSection(&g_destMapLock);
    std::map<unsigned short, OriginalDest>::iterator it = g_originalDestMap.find(localPort);
    bool found = (it != g_originalDestMap.end());
    if (found) dest = it->second;
    LeaveCriticalSection(&g_destMapLock);
    return found;
}

static void removeOriginalDest(unsigned short localPort)
{
    EnterCriticalSection(&g_destMapLock);
    g_originalDestMap.erase(localPort);
    LeaveCriticalSection(&g_destMapLock);
}

// =============================================
//  Per-connection proxy handler (runs in thread)
// =============================================
struct ProxyThreadParam
{
    SOCKET clientSock;
    CertGenerator* certGen;
    unsigned short clientPort;   // client's source port (for dest lookup)
};

// Resolve hostname from IP address (reverse DNS)
static std::string resolveHostname(const std::string& ip, unsigned short port)
{
    // Try well-known SMTP servers by port
    // For Gmail: smtp.gmail.com
    // This is a simplification; production code should do reverse DNS
    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    // Try common SMTP and web mail hostnames
    const char* knownHosts[] = {
        "smtp.gmail.com",
        "smtp-relay.gmail.com",
        "smtp.office365.com",
        "smtp.naver.com",
        "smtp.daum.net",
        "mail.google.com",
        "outlook.live.com",
        "mail.naver.com",
        NULL
    };

    for (int i = 0; knownHosts[i] != NULL; i++)
    {
        if (getaddrinfo(knownHosts[i], NULL, &hints, &result) == 0)
        {
            for (struct addrinfo* p = result; p != NULL; p = p->ai_next)
            {
                char resolvedIp[64] = "";
                struct sockaddr_in* sin = (struct sockaddr_in*)p->ai_addr;
                inet_ntop(AF_INET, &sin->sin_addr, resolvedIp, sizeof(resolvedIp));
                if (ip == resolvedIp)
                {
                    freeaddrinfo(result);
                    return knownHosts[i];
                }
            }
            freeaddrinfo(result);
        }
    }

    // Fallback: return IP as hostname
    return ip;
}

// Connect to the real server and return a TLS-wrapped SSL*
// hostname is used for SNI (Server Name Indication)
static SSL* connectToRealServer(const std::string& ip, unsigned short port,
    SOCKET* outSock, const std::string& hostname = "")
{
    // TCP connect
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return NULL;

    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        closesocket(sock);
        return NULL;
    }

    *outSock = sock;

    // Create TLS client context
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
    {
        closesocket(sock);
        return NULL;
    }

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)sock);

    // Set SNI (Server Name Indication) - required by Google and most servers
    if (!hostname.empty())
    {
        SSL_set_tlsext_host_name(ssl, hostname.c_str());
    }

    if (SSL_connect(ssl) <= 0)
    {
        unsigned long errCode = ERR_peek_last_error();
        char errBuf[256] = "";
        ERR_error_string_n(errCode, errBuf, sizeof(errBuf));
        printf("[TlsProxy] SSL_connect to real server failed: %s\n", errBuf);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        closesocket(sock);
        *outSock = INVALID_SOCKET;
        return NULL;
    }

    // SSL_CTX is ref-counted; SSL_new increments, SSL_free decrements.
    // We can free our reference now; the SSL object holds its own.
    SSL_CTX_free(ctx);

    return ssl;
}

// =============================================
//  SNI callback data for dynamic cert generation
// =============================================
struct SniCallbackData
{
    CertGenerator* certGen;
    std::string    requestedHostname;  // filled by SNI callback
    std::string    fallbackHostname;   // default if no SNI
};

// SNI callback: called during SSL_accept when browser sends ClientHello with SNI
static int sniCallback(SSL* ssl, int* ad, void* arg)
{
    SniCallbackData* data = (SniCallbackData*)arg;
    const char* serverName = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

    std::string hostname;
    if (serverName && strlen(serverName) > 0)
    {
        hostname = serverName;
        data->requestedHostname = hostname;
    }
    else
    {
        hostname = data->fallbackHostname;
        data->requestedHostname = hostname;
    }

    // Generate certificate for the requested hostname
    X509* cert = NULL;
    EVP_PKEY* key = NULL;
    if (!data->certGen->getCertForHost(hostname, &cert, &key))
    {
        printf("[TlsProxy] SNI callback: failed to get cert for %s\n", hostname.c_str());
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    // Set the certificate on this SSL connection
    SSL_use_certificate(ssl, cert);
    SSL_use_PrivateKey(ssl, key);

    return SSL_TLSEXT_ERR_OK;
}

// ALPN callback: negotiate HTTP/1.1 (Chrome sends h2 + http/1.1, we pick http/1.1)
static int alpnCallback(SSL* ssl, const unsigned char** out, unsigned char* outlen,
    const unsigned char* in, unsigned int inlen, void* arg)
{
    // We only support http/1.1
    static const unsigned char http11[] = { 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };

    // Search for http/1.1 in client's ALPN list
    const unsigned char* p = in;
    const unsigned char* end = in + inlen;
    while (p < end)
    {
        unsigned char len = *p;
        p++;
        if (p + len > end) break;

        if (len == 8 && memcmp(p, "http/1.1", 8) == 0)
        {
            *out = p;
            *outlen = len;
            return SSL_TLSEXT_ERR_OK;
        }
        p += len;
    }

    // If client doesn't offer http/1.1, don't negotiate ALPN
    // (let the connection proceed without ALPN)
    return SSL_TLSEXT_ERR_NOACK;
}

// Accept TLS from client using dynamically generated certificate
// Uses SNI callback to detect the exact hostname the browser requests
static SSL* acceptTlsFromClient(SOCKET clientSock, CertGenerator* certGen,
    const std::string& hostname)
{
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return NULL;

    // Pre-load a default certificate (required before SSL_accept,
    // will be overridden by SNI callback if browser sends SNI)
    X509* cert = NULL;
    EVP_PKEY* key = NULL;
    if (!certGen->getCertForHost(hostname, &cert, &key))
    {
        printf("[TlsProxy] Failed to get default cert for: %s\n", hostname.c_str());
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_certificate(ctx, cert) <= 0 ||
        SSL_CTX_use_PrivateKey(ctx, key) <= 0)
    {
        printf("[TlsProxy] Failed to set default cert/key on SSL context\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Set up SNI callback for dynamic cert generation
    SniCallbackData sniData;
    sniData.certGen = certGen;
    sniData.fallbackHostname = hostname;
    SSL_CTX_set_tlsext_servername_callback(ctx, sniCallback);
    SSL_CTX_set_tlsext_servername_arg(ctx, &sniData);

    // Set ALPN callback: negotiate http/1.1 (not h2)
    // This is critical for HTTPS proxying since we parse HTTP/1.1
    SSL_CTX_set_alpn_select_cb(ctx, alpnCallback, NULL);

    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)clientSock);

    if (SSL_accept(ssl) <= 0)
    {
        int err = SSL_get_error(ssl, -1);
        unsigned long errCode = ERR_peek_last_error();
        char errBuf[256] = "";
        ERR_error_string_n(errCode, errBuf, sizeof(errBuf));
        printf("[TlsProxy] SSL_accept from client failed (error=%d)\n", err);
        printf("[TlsProxy]   OpenSSL detail: %s\n", errBuf);
        ERR_print_errors_fp(stdout);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return NULL;
    }

    printf("[TlsProxy] TLS handshake OK (hostname=%s)\n",
        sniData.requestedHostname.c_str());

    return ssl;
}

// Relay data between client SSL and server SSL, parsing SMTP along the way
static void relaySmtpData(SSL* clientSsl, SSL* serverSsl,
    const std::string& sourceInfo, const std::string& destInfo)
{
    SmtpParser parser;
    char buf[8192];
    fd_set readfds;
    struct timeval tv;

    SOCKET clientFd = SSL_get_fd(clientSsl);
    SOCKET serverFd = SSL_get_fd(serverSsl);

    bool running = true;

    while (running)
    {
        FD_ZERO(&readfds);
        FD_SET(clientFd, &readfds);
        FD_SET(serverFd, &readfds);

        tv.tv_sec = 30;
        tv.tv_usec = 0;

        SOCKET maxFd = (clientFd > serverFd) ? clientFd : serverFd;
        int ret = select((int)maxFd + 1, &readfds, NULL, NULL, &tv);

        if (ret <= 0)
        {
            // Timeout or error
            if (ret < 0) running = false;
            continue;
        }

        // Client -> Server (outgoing mail data)
        if (FD_ISSET(clientFd, &readfds))
        {
            int n = SSL_read(clientSsl, buf, sizeof(buf));
            if (n <= 0)
            {
                running = false;
                break;
            }

            // Feed plaintext SMTP data to parser
            std::vector<ParsedEmail> emails = parser.feedData(buf, n);

            for (size_t i = 0; i < emails.size(); i++)
            {
                ParsedEmail& email = emails[i];

                printf("\n========================================\n");
                printf("[TlsProxy] Outgoing mail detected (TLS)!\n");
                printf("  Subject: %s\n", email.subject.c_str());
                printf("  From: %s\n", email.from.c_str());
                printf("  To: %s\n", email.to.c_str());
                printf("  Attachments: %d\n", (int)email.attachments.size());
                for (size_t k = 0; k < email.attachments.size(); k++)
                {
                    const AttachmentInfo& att = email.attachments[k];
                    printf("    [%d] %s (%zu bytes, %s)\n",
                        (int)(k + 1),
                        att.filename.empty() ? "(no name)" : att.filename.c_str(),
                        att.data.size(),
                        att.contentType.empty() ? "unknown" : att.contentType.c_str());
                }
                printf("========================================\n");

                // PII check
                std::string ruleName, matchedPattern;
                int matchCount = 0;
                bool shouldBlock = checkPiiAndBlock(email, ruleName, matchCount, matchedPattern);

                if (shouldBlock)
                {
                    printf("\n*** [BLOCKED] Mail blocked via TLS proxy! ***\n");
                    printf("  Rule: %s, Matches: %d\n\n", ruleName.c_str(), matchCount);

                    logEmailFromProxy(email, true, ruleName, matchCount, matchedPattern,
                        sourceInfo, destInfo);

                    // Send error to client and close
                    const char* errResp = "550 5.7.1 Message blocked by policy: PII detected\r\n";
                    SSL_write(clientSsl, errResp, (int)strlen(errResp));
                    running = false;
                    break;
                }

                // Log normal mail
                logEmailFromProxy(email, false, "", 0, "", sourceInfo, destInfo);
            }

            // Forward to real server (if not blocked)
            if (running)
            {
                SSL_write(serverSsl, buf, n);
            }
        }

        // Server -> Client (server responses)
        if (running && FD_ISSET(serverFd, &readfds))
        {
            int n = SSL_read(serverSsl, buf, sizeof(buf));
            if (n <= 0)
            {
                running = false;
                break;
            }

            // Forward server response to client as-is
            SSL_write(clientSsl, buf, n);
        }
    }
}

// Handle STARTTLS (port 587): relay plaintext until STARTTLS, then upgrade
static void handleStartTls(SOCKET clientSock, SOCKET serverSock,
    CertGenerator* certGen, const std::string& hostname,
    const std::string& sourceInfo, const std::string& destInfo)
{
    char buf[8192];
    bool startTlsDetected = false;

    // Phase 1: relay plaintext until STARTTLS command
    while (!startTlsDetected)
    {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(clientSock, &readfds);
        FD_SET(serverSock, &readfds);

        struct timeval tv;
        tv.tv_sec = 30;
        tv.tv_usec = 0;

        SOCKET maxFd = (clientSock > serverSock) ? clientSock : serverSock;
        int ret = select((int)maxFd + 1, &readfds, NULL, NULL, &tv);
        if (ret <= 0) return;

        // Client -> Server
        if (FD_ISSET(clientSock, &readfds))
        {
            int n = recv(clientSock, buf, sizeof(buf) - 1, 0);
            if (n <= 0) return;
            buf[n] = '\0';

            // Check for STARTTLS command
            std::string data(buf, n);
            std::string upper = data;
            for (size_t i = 0; i < upper.size(); i++)
                upper[i] = (char)toupper((unsigned char)upper[i]);

            if (upper.find("STARTTLS") != std::string::npos)
            {
                // Forward STARTTLS to real server
                send(serverSock, buf, n, 0);

                // Wait for server's "220 Ready" response
                int resp = recv(serverSock, buf, sizeof(buf) - 1, 0);
                if (resp <= 0) return;
                buf[resp] = '\0';

                // Forward "220 Ready" to client
                send(clientSock, buf, resp, 0);

                std::string respStr(buf, resp);
                if (respStr.find("220") != std::string::npos)
                {
                    startTlsDetected = true;
                    printf("[TlsProxy] STARTTLS detected, upgrading to TLS...\n");
                }
                else
                {
                    printf("[TlsProxy] STARTTLS rejected by server: %s\n", buf);
                    return;
                }
            }
            else
            {
                // Forward other commands to server
                send(serverSock, buf, n, 0);
            }
        }

        // Server -> Client
        if (FD_ISSET(serverSock, &readfds))
        {
            int n = recv(serverSock, buf, sizeof(buf), 0);
            if (n <= 0) return;
            send(clientSock, buf, n, 0);
        }
    }

    // Phase 2: TLS upgrade on both sides
    // Server side TLS (proxy as client)
    SSL_CTX* serverCtx = SSL_CTX_new(TLS_client_method());
    if (!serverCtx) return;

    SSL* serverSsl = SSL_new(serverCtx);
    SSL_set_fd(serverSsl, (int)serverSock);
    SSL_set_tlsext_host_name(serverSsl, hostname.c_str());

    if (SSL_connect(serverSsl) <= 0)
    {
        printf("[TlsProxy] STARTTLS: SSL_connect to server failed\n");
        SSL_free(serverSsl);
        SSL_CTX_free(serverCtx);
        return;
    }

    // Client side TLS (proxy as server)
    SSL* clientSsl = acceptTlsFromClient(clientSock, certGen, hostname);
    if (!clientSsl)
    {
        SSL_shutdown(serverSsl);
        SSL_free(serverSsl);
        SSL_CTX_free(serverCtx);
        return;
    }

    printf("[TlsProxy] STARTTLS upgrade complete, relaying encrypted SMTP...\n");

    // Phase 3: relay decrypted data
    relaySmtpData(clientSsl, serverSsl, sourceInfo, destInfo);

    // Cleanup
    SSL_shutdown(clientSsl);
    SSL_shutdown(serverSsl);
    SSL_free(clientSsl);
    SSL_free(serverSsl);
    SSL_CTX_free(serverCtx);
}

// Find all email addresses in raw text
static void findEmailAddresses(const std::string& data,
    std::vector<std::string>& emails, std::vector<size_t>& positions)
{
    // Email pattern: look for xxx@xxx.xxx with stricter validation
    size_t pos = 0;
    while (pos < data.size())
    {
        size_t at = data.find('@', pos);
        if (at == std::string::npos || at == 0) break;

        // Find start of email (scan backward from @)
        size_t start = at;
        while (start > 0)
        {
            char c = data[start - 1];
            if (isalnum((unsigned char)c) || c == '.' || c == '_' ||
                c == '-' || c == '+')
                start--;
            else
                break;
        }

        // Find end of email (scan forward from @)
        size_t end = at + 1;
        bool hasDot = false;
        int dotsAfterAt = 0;
        size_t lastDotPos = 0;
        while (end < data.size())
        {
            char c = data[end];
            if (isalnum((unsigned char)c) || c == '.' || c == '-')
            {
                if (c == '.') { hasDot = true; dotsAfterAt++; lastDotPos = end; }
                end++;
            }
            else break;
        }

        // Stricter validation:
        // - At least 2 chars before @
        // - At least 1 dot after @
        // - TLD must be at least 2 chars (rejects c@.za, S@.W etc.)
        // - Local part must start with alphanumeric
        size_t localLen = at - start;
        size_t domainLen = end - (at + 1);
        size_t tldLen = (lastDotPos > 0 && end > lastDotPos) ? (end - lastDotPos - 1) : 0;

        if (localLen >= 2 && domainLen >= 4 && hasDot && tldLen >= 2 &&
            isalnum((unsigned char)data[start]))
        {
            std::string email = data.substr(start, end - start);
            // Skip obvious non-emails
            if (email.find("..") == std::string::npos &&
                email[email.size() - 1] != '.')
            {
                emails.push_back(email);
                positions.push_back(start);
            }
        }

        pos = (end > at + 1) ? end : at + 1;
    }
}

// Extract text surrounding an email address (for subject/body context)
static std::string extractSurroundingText(const std::string& data,
    size_t pos, int radius)
{
    size_t start = (pos > (size_t)radius) ? pos - radius : 0;
    size_t end = (pos + radius < data.size()) ? pos + radius : data.size();

    std::string result;
    for (size_t i = start; i < end; i++)
    {
        unsigned char c = (unsigned char)data[i];
        // Keep printable ASCII and UTF-8 multibyte chars
        if (c >= 0x20 || c >= 0x80 || c == '\n' || c == '\r' || c == '\t')
            result += (char)c;
    }
    return result;
}

// Scan accumulated data for email-related content and log if found.
// This is a simple heuristic scanner that looks for email address patterns
// with nearby readable text (subject, body).
// Check if string is a Gmail internal identifier (not user content)
static bool isGmailInternalString(const std::string& s)
{
    if (s.find("thread-") == 0) return true;
    if (s.find("msg-") == 0) return true;
    if (s.find("label_") == 0) return true;
    if (s.find("^") == 0) return true;
    if (s.find("gmail.pinto") != std::string::npos) return true;
    if (s.find("INBOX") == 0) return true;
    return false;
}

// Dedup tracker: avoid logging the same sender+recipient pair multiple times
static CRITICAL_SECTION g_deduplicateLock;
static std::map<std::string, time_t> g_recentDetections;
static bool g_deduplicateInitialized = false;

static bool isDuplicateDetection(const std::string& from, const std::string& to)
{
    if (!g_deduplicateInitialized)
    {
        InitializeCriticalSection(&g_deduplicateLock);
        g_deduplicateInitialized = true;
    }

    std::string key = from + "->" + to;
    time_t now = time(NULL);

    EnterCriticalSection(&g_deduplicateLock);

    // Clean old entries (older than 10 seconds)
    std::map<std::string, time_t>::iterator it = g_recentDetections.begin();
    while (it != g_recentDetections.end())
    {
        if (now - it->second > 10)
        {
            std::map<std::string, time_t>::iterator toErase = it;
            ++it;
            g_recentDetections.erase(toErase);
        }
        else
            ++it;
    }

    bool duplicate = false;
    it = g_recentDetections.find(key);
    if (it != g_recentDetections.end())
    {
        duplicate = true;
        it->second = now;  // refresh
    }
    else
    {
        g_recentDetections[key] = now;
    }

    LeaveCriticalSection(&g_deduplicateLock);
    return duplicate;
}

// Strip HTML tags from string, returning plain text
static std::string stripHtmlTags(const std::string& html)
{
    std::string result;
    bool inTag = false;
    for (size_t i = 0; i < html.size(); i++)
    {
        if (html[i] == '<') { inTag = true; continue; }
        if (html[i] == '>') { inTag = false; continue; }
        if (!inTag)
        {
            if (html[i] == '&')
            {
                // Handle common HTML entities
                if (html.substr(i, 4) == "&lt;") { result += '<'; i += 3; continue; }
                if (html.substr(i, 4) == "&gt;") { result += '>'; i += 3; continue; }
                if (html.substr(i, 5) == "&amp;") { result += '&'; i += 4; continue; }
                if (html.substr(i, 6) == "&nbsp;") { result += ' '; i += 5; continue; }
                if (html.substr(i, 6) == "&quot;") { result += '"'; i += 5; continue; }
            }
            result += html[i];
        }
    }
    return result;
}

// Extract the next quoted string from data starting at pos.
// Returns the string content (without quotes) and advances pos past the closing quote.
static std::string extractNextQuotedString(const std::string& data, size_t& pos)
{
    size_t q1 = data.find('"', pos);
    if (q1 == std::string::npos) return "";

    std::string result;
    size_t i = q1 + 1;
    while (i < data.size())
    {
        if (data[i] == '\\' && i + 1 < data.size())
        {
            // Escaped character
            char next = data[i + 1];
            if (next == '"') { result += '"'; i += 2; }
            else if (next == '\\') { result += '\\'; i += 2; }
            else if (next == 'n') { result += '\n'; i += 2; }
            else if (next == 'r') { result += '\r'; i += 2; }
            else if (next == 't') { result += '\t'; i += 2; }
            else { result += next; i += 2; }
        }
        else if (data[i] == '"')
        {
            pos = i + 1;
            return result;
        }
        else
        {
            result += data[i];
            i++;
        }
    }
    pos = data.size();
    return result;
}

// Heuristic: does this quoted string look like an attachment filename?
// Used for Gmail web compose data (attachments referenced by filename only).
static bool looksLikeAttachmentFilename(const std::string& s)
{
    if (s.size() < 4 || s.size() > 200) return false;
    if (s.find("://") != std::string::npos) return false;
    if (s.find('@') != std::string::npos) return false;
    if (s.find('/') != std::string::npos) return false;
    if (s.find('\\') != std::string::npos) return false;
    if (s.find('<') != std::string::npos) return false;
    if (s.find('>') != std::string::npos) return false;
    if (s.find('\n') != std::string::npos) return false;

    size_t dotPos = s.rfind('.');
    if (dotPos == std::string::npos || dotPos == 0 || dotPos == s.size() - 1)
        return false;

    size_t extLen = s.size() - dotPos - 1;
    if (extLen < 2 || extLen > 8) return false;

    for (size_t i = dotPos + 1; i < s.size(); i++)
    {
        if (!isalnum((unsigned char)s[i])) return false;
    }

    static const char* knownExts[] = {
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
        "txt", "csv", "rtf", "odt", "ods", "odp",
        "zip", "rar", "7z", "tar", "gz", "tgz",
        "png", "jpg", "jpeg", "gif", "bmp", "webp", "svg", "tiff", "tif",
        "mp4", "mov", "avi", "mkv", "wmv", "flv", "webm",
        "mp3", "wav", "ogg", "flac", "m4a",
        "hwp", "hwpx",
        "json", "xml", "html", "htm",
        "exe", "msi",
        NULL
    };

    std::string ext = s.substr(dotPos + 1);
    for (size_t i = 0; i < ext.size(); i++)
        ext[i] = (char)tolower((unsigned char)ext[i]);

    for (int i = 0; knownExts[i] != NULL; i++)
    {
        if (ext == knownExts[i]) return true;
    }
    return false;
}

// Guess MIME type from filename extension (Gmail web doesn't expose
// content-type for attachments in compose data)
static std::string guessContentTypeFromExt(const std::string& filename)
{
    size_t dot = filename.rfind('.');
    if (dot == std::string::npos) return "application/octet-stream";

    std::string ext = filename.substr(dot + 1);
    for (size_t i = 0; i < ext.size(); i++)
        ext[i] = (char)tolower((unsigned char)ext[i]);

    if (ext == "pdf") return "application/pdf";
    if (ext == "doc") return "application/msword";
    if (ext == "docx") return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    if (ext == "xls") return "application/vnd.ms-excel";
    if (ext == "xlsx") return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
    if (ext == "ppt") return "application/vnd.ms-powerpoint";
    if (ext == "pptx") return "application/vnd.openxmlformats-officedocument.presentationml.presentation";
    if (ext == "txt") return "text/plain";
    if (ext == "csv") return "text/csv";
    if (ext == "json") return "application/json";
    if (ext == "xml") return "application/xml";
    if (ext == "zip") return "application/zip";
    if (ext == "rar") return "application/vnd.rar";
    if (ext == "7z") return "application/x-7z-compressed";
    if (ext == "png") return "image/png";
    if (ext == "jpg" || ext == "jpeg") return "image/jpeg";
    if (ext == "gif") return "image/gif";
    if (ext == "bmp") return "image/bmp";
    if (ext == "webp") return "image/webp";
    if (ext == "svg") return "image/svg+xml";
    if (ext == "mp4") return "video/mp4";
    if (ext == "mov") return "video/quicktime";
    if (ext == "avi") return "video/x-msvideo";
    if (ext == "mp3") return "audio/mpeg";
    if (ext == "wav") return "audio/wav";
    if (ext == "hwp") return "application/x-hwp";
    if (ext == "hwpx") return "application/haansofthwpx";
    return "application/octet-stream";
}

// Extract attachment metadata from Gmail compose data.
// Gmail web only includes filenames in the compose stream — actual file
// bytes are uploaded via separate /upload/ endpoints, so we record the
// filename and a guessed MIME type only.
//
// Bounded scanner: relay buffer can hold up to 64KB of mixed text/binary
// (Gmail multiplexes compose JSON with file-upload chunks on the same TLS
// stream). A naive whole-buffer quoted-string scan goes O(N^2) on
// unterminated quotes from binary, so we cap both the scanned region and
// the per-quoted-string scan length.
static void extractGmailAttachments(const std::string& data, ParsedEmail& email)
{
    const size_t MAX_SCAN = 32768;       // hard cap on bytes scanned
    const size_t MAX_QUOTED_LEN = 256;   // attachment filenames fit easily

    size_t scanLen = data.size() < MAX_SCAN ? data.size() : MAX_SCAN;

    std::set<std::string> seen;
    size_t pos = 0;
    while (pos < scanLen)
    {
        size_t qStart = data.find('"', pos);
        if (qStart == std::string::npos || qStart >= scanLen) break;

        size_t maxEnd = qStart + 1 + MAX_QUOTED_LEN;
        if (maxEnd > scanLen) maxEnd = scanLen;

        size_t qEnd = std::string::npos;
        for (size_t i = qStart + 1; i < maxEnd; i++)
        {
            if (data[i] == '\\' && i + 1 < maxEnd) { i++; continue; }
            if (data[i] == '"') { qEnd = i; break; }
        }

        if (qEnd == std::string::npos)
        {
            // Unterminated within bound — skip past this quote
            pos = qStart + 1;
            continue;
        }

        std::string s = data.substr(qStart + 1, qEnd - qStart - 1);
        s = GmailWebParser::decodeUnicodeEscapes(s);

        if (looksLikeAttachmentFilename(s) && seen.find(s) == seen.end())
        {
            seen.insert(s);
            AttachmentInfo att;
            att.filename = s;
            att.contentType = guessContentTypeFromExt(s);
            // att.data left empty: bytes not present in compose endpoint
            email.attachments.push_back(att);
        }

        pos = qEnd + 1;
    }
}

// Parse Gmail compose/send data to extract sender, recipient, subject, body.
// Gmail format (observed):
//   [...[1,"sender@email.com","SenderName",...,"sender@email.com"],
//    [[1,"recipient@email.com","RecipientName"]],
//    null,null,null,TIMESTAMP,"SUBJECT",
//    [null,[[0,"<div>HTML_BODY</div>"]]]...]
static bool parseGmailComposeData(const std::string& data,
    std::string& sender, std::string& senderName,
    std::string& recipient, std::string& recipientName,
    std::string& subject, std::string& bodyHtml)
{
    // Look for the compose data pattern: msg-a: followed by sender info
    // Pattern: "msg-a:r-DIGITS",[1,"email@addr","Name"
    size_t msgPos = data.find("\"msg-a:");
    if (msgPos == std::string::npos) return false;

    // Find the sender array: [1,"email","name"
    size_t searchFrom = msgPos;
    size_t senderStart = data.find(",[1,\"", searchFrom);
    if (senderStart == std::string::npos) return false;
    senderStart += 4;  // skip ,[1, — pos now at opening "

    // Extract sender email
    size_t pos = senderStart;
    sender = extractNextQuotedString(data, pos);
    if (sender.find('@') == std::string::npos) return false;

    // Skip to next quoted string for sender name
    // Pattern: ,"SenderName"
    size_t nameQuote = data.find(",\"", pos);
    if (nameQuote != std::string::npos && nameQuote - pos < 5)
    {
        pos = nameQuote + 1;
        senderName = extractNextQuotedString(data, pos);
    }

    // Find recipient array: [[1,"email","name"]]
    size_t rcptStart = data.find("[[1,\"", pos);
    if (rcptStart == std::string::npos) return false;
    pos = rcptStart + 4;  // skip [[1, — pos now at opening "
    recipient = extractNextQuotedString(data, pos);
    if (recipient.find('@') == std::string::npos) return false;

    // Recipient name
    nameQuote = data.find(",\"", pos);
    if (nameQuote != std::string::npos && nameQuote - pos < 5)
    {
        pos = nameQuote + 1;
        recipientName = extractNextQuotedString(data, pos);
    }

    // After recipient section, find: ]],null,null,null,TIMESTAMP,"SUBJECT"
    // Skip past the closing ]]
    size_t rcptEnd = data.find("]]", pos);
    if (rcptEnd == std::string::npos) return false;
    pos = rcptEnd + 2;

    // Now scan forward for the subject.
    // Gmail format after recipient ]]: ],null,null,null,TIMESTAMP,"SUBJECT",[body...]
    // The subject is the first quoted string after the timestamp number.
    // We look for: a large number (timestamp) followed by ,"SUBJECT"
    size_t limit = pos + 300;
    if (limit > data.size()) limit = data.size();

    // Find the timestamp (a number > 1000000000000, i.e., 13+ digits)
    size_t tsPos = pos;
    bool foundTimestamp = false;
    while (tsPos < limit)
    {
        // Look for a digit sequence
        if (isdigit((unsigned char)data[tsPos]))
        {
            size_t numStart = tsPos;
            while (tsPos < limit && isdigit((unsigned char)data[tsPos])) tsPos++;
            if (tsPos - numStart >= 10)  // timestamp is 13+ digits
            {
                foundTimestamp = true;
                break;
            }
        }
        else
            tsPos++;
    }

    if (foundTimestamp)
    {
        // Subject is the next quoted string after the timestamp
        // Pattern: TIMESTAMP,"SUBJECT"
        size_t nextQuote = data.find('"', tsPos);
        if (nextQuote != std::string::npos && nextQuote < tsPos + 20)
        {
            pos = nextQuote;
            subject = extractNextQuotedString(data, pos);
            // subject may be empty ("") which is valid - means no subject
        }
    }

    // Find HTML body: [[0,"<div...>BODY</div>"]]
    size_t bodyMarker = data.find("[[0,\"", pos);
    if (bodyMarker != std::string::npos)
    {
        // Position at the opening " of the HTML content
        pos = bodyMarker + 4;  // skip [[0, — pos now at "
        bodyHtml = extractNextQuotedString(data, pos);
    }
    else
    {
        // Try alternate pattern [0,"
        bodyMarker = data.find("[0,\"", pos);
        if (bodyMarker != std::string::npos)
        {
            pos = bodyMarker + 3;  // skip [0, — pos now at "
            bodyHtml = extractNextQuotedString(data, pos);
        }
    }

    return (!sender.empty() && !recipient.empty());
}

// Pending email detection: holds the latest parsed data for a sender->recipient pair.
// We don't log immediately because Gmail sends compose data incrementally
// (first auto-save with empty subject, then updates with subject/body, then send).
// We keep updating and only do the final log after a timeout or when new pair appears.
struct PendingDetection
{
    std::string sender, senderName;
    std::string recipient, recipientName;
    std::string subject, bodyPlain, bodyHtml;
    std::string sourceInfo, destInfo;
    std::vector<AttachmentInfo> attachments;
    time_t lastUpdate;
    bool logged;

    PendingDetection() : lastUpdate(0), logged(false) {}
};

static CRITICAL_SECTION g_pendingLock;
static std::map<std::string, PendingDetection> g_pendingDetections;
static bool g_pendingInitialized = false;

// Flush a pending detection: do the actual console output, JSON log, PII check
static void flushPendingDetection(PendingDetection& det)
{
    if (det.logged) return;
    det.logged = true;

    ParsedEmail email;
    email.from = det.sender;
    email.to = det.recipient;
    email.smtpRcptTo.push_back(det.recipient);
    email.subject = det.subject;
    email.bodyPlainText = det.bodyPlain;
    email.attachments = det.attachments;

    // Print detection
    printf("\n========================================\n");
    printf("[TlsProxy/HTTPS] Gmail email detected!\n");
    printf("  From: %s (%s)\n", det.sender.c_str(), det.senderName.c_str());
    printf("  To: %s (%s)\n", det.recipient.c_str(), det.recipientName.c_str());
    printf("  Subject: %s\n",
        det.subject.empty() ? "(no subject)" : det.subject.c_str());
    printf("  Body: %.200s%s\n",
        det.bodyPlain.empty() ? "(empty)" : det.bodyPlain.c_str(),
        det.bodyPlain.size() > 200 ? "..." : "");
    if (!det.attachments.empty())
    {
        printf("  Attachments: %d\n", (int)det.attachments.size());
        for (size_t k = 0; k < det.attachments.size(); k++)
        {
            const AttachmentInfo& att = det.attachments[k];
            if (att.data.empty())
            {
                printf("    [%d] %s (no body captured, %s)\n",
                    (int)(k + 1),
                    att.filename.empty() ? "(no name)" : att.filename.c_str(),
                    att.contentType.empty() ? "unknown" : att.contentType.c_str());
            }
            else
            {
                printf("    [%d] %s (%zu bytes, %s)\n",
                    (int)(k + 1),
                    att.filename.empty() ? "(no name)" : att.filename.c_str(),
                    att.data.size(),
                    att.contentType.empty() ? "unknown" : att.contentType.c_str());
            }
        }
    }
    printf("========================================\n");

    // PII check
    std::string ruleName, matchedPattern;
    int matchCount = 0;
    bool shouldBlock = checkPiiAndBlock(email, ruleName,
        matchCount, matchedPattern);

    if (shouldBlock)
    {
        printf("\n*** [BLOCKED] Gmail web email PII detected! ***\n");
        printf("  Rule: %s, Matches: %d\n\n", ruleName.c_str(), matchCount);
    }

    logEmailFromProxy(email, shouldBlock,
        shouldBlock ? ruleName : "",
        matchCount, matchedPattern,
        det.sourceInfo + " (Gmail Web)", det.destInfo);
}

// Check and flush any pending detections older than maxAge seconds
static void checkPendingDetections(int maxAge)
{
    if (!g_pendingInitialized) return;

    EnterCriticalSection(&g_pendingLock);

    time_t now = time(NULL);
    std::map<std::string, PendingDetection>::iterator it = g_pendingDetections.begin();
    while (it != g_pendingDetections.end())
    {
        if (!it->second.logged && (now - it->second.lastUpdate) >= maxAge)
        {
            flushPendingDetection(it->second);
        }
        // Clean up old entries
        if (it->second.logged && (now - it->second.lastUpdate) > 30)
        {
            std::map<std::string, PendingDetection>::iterator toErase = it;
            ++it;
            g_pendingDetections.erase(toErase);
        }
        else
            ++it;
    }

    LeaveCriticalSection(&g_pendingLock);
}

// Returns true when a PII block has been triggered for the current
// detection — caller (relayHttpsData) should then tear down the TLS
// connection so Gmail's server doesn't receive the rest of the
// compose POST body and the message isn't actually sent.
static bool scanForEmailData(std::string& data, const char* direction,
    const std::string& sourceInfo, const std::string& destInfo,
    const std::vector<std::pair<std::string, std::vector<unsigned char> > >& uploads)
{
    // Only scan CLIENT->SERVER data (outgoing emails)
    if (std::string(direction).find("SERVER") == 0)
        return false;

    // Quick check: must contain "msg-a:" (Gmail compose message marker)
    size_t msgaPos = data.find("\"msg-a:");
    if (msgaPos == std::string::npos)
        return false;

    // Body marker [[0," must be present
    if (data.find("[[0,\"", msgaPos) == std::string::npos)
        return false;

    // Try to parse Gmail compose data
    std::string sender, senderName, recipient, recipientName, subject, bodyHtml;
    if (!parseGmailComposeData(data, sender, senderName,
        recipient, recipientName, subject, bodyHtml))
        return false;

    // Decode unicode escapes in subject and body
    subject = GmailWebParser::decodeUnicodeEscapes(subject);
    std::string bodyPlain = stripHtmlTags(
        GmailWebParser::decodeUnicodeEscapes(bodyHtml));

    // Trim whitespace from body
    while (!bodyPlain.empty() &&
           (bodyPlain[0] == ' ' || bodyPlain[0] == '\n' || bodyPlain[0] == '\r'))
        bodyPlain.erase(0, 1);
    while (!bodyPlain.empty() &&
           (bodyPlain[bodyPlain.size()-1] == ' ' || bodyPlain[bodyPlain.size()-1] == '\n'))
        bodyPlain.erase(bodyPlain.size()-1, 1);

    // Extract attachment metadata (filename + guessed MIME type).
    // Gmail web doesn't include attachment bytes in the compose stream;
    // those are uploaded via separate /upload/ endpoints.
    ParsedEmail tempEmail;
    extractGmailAttachments(data, tempEmail);

    // Initialize pending detection system
    if (!g_pendingInitialized)
    {
        InitializeCriticalSection(&g_pendingLock);
        g_pendingInitialized = true;
    }

    // First, flush any old pending detections (older than 3 seconds)
    checkPendingDetections(3);

    std::string key = sender + "->" + recipient;

    EnterCriticalSection(&g_pendingLock);

    PendingDetection& det = g_pendingDetections[key];

    // Is this detection better than what we already have?
    bool isBetter = false;
    if (det.sender.empty())
    {
        // First detection for this pair
        isBetter = true;
    }
    else if (!det.logged)
    {
        // Update if: new one has subject but old one doesn't,
        // or new one has longer body
        if (!subject.empty() && det.subject.empty())
            isBetter = true;
        else if (!bodyPlain.empty() && det.bodyPlain.empty())
            isBetter = true;
        else if (bodyPlain.size() > det.bodyPlain.size())
            isBetter = true;
        else if (subject.size() > det.subject.size())
            isBetter = true;
        else
            isBetter = true;  // always update with latest data
    }
    else
    {
        // Already logged. Only update if new detection has non-empty subject
        // and old one was empty (corrective update)
        if (!subject.empty() && det.subject.empty())
        {
            det.logged = false;  // re-enable logging
            isBetter = true;
        }
    }

    if (isBetter)
    {
        det.sender = sender;
        det.senderName = senderName;
        det.recipient = recipient;
        det.recipientName = recipientName;
        det.subject = subject;
        det.bodyPlain = bodyPlain;
        det.bodyHtml = bodyHtml;

        // Build new attachment list, preserving any bytes we previously
        // matched (so re-runs don't drop captured uploads)
        std::vector<AttachmentInfo> newAttachments = tempEmail.attachments;
        for (size_t k = 0; k < newAttachments.size(); k++)
        {
            for (size_t m = 0; m < det.attachments.size(); m++)
            {
                if (det.attachments[m].filename == newAttachments[k].filename &&
                    !det.attachments[m].data.empty())
                {
                    newAttachments[k].data = det.attachments[m].data;
                    if (newAttachments[k].contentType.empty() ||
                        newAttachments[k].contentType == "application/octet-stream")
                    {
                        newAttachments[k].contentType = det.attachments[m].contentType;
                    }
                    break;
                }
            }
        }

        // Fill remaining empty attachment bodies from captured upload requests,
        // matching by order (Nth attachment <-> Nth upload).
        size_t uploadIdx = 0;
        for (size_t k = 0; k < newAttachments.size(); k++)
        {
            if (!newAttachments[k].data.empty()) continue;
            while (uploadIdx < uploads.size() && uploads[uploadIdx].second.empty())
                uploadIdx++;
            if (uploadIdx >= uploads.size()) break;
            newAttachments[k].data = uploads[uploadIdx].second;
            const std::string& upCt = uploads[uploadIdx].first;
            if (!upCt.empty() &&
                (newAttachments[k].contentType.empty() ||
                 newAttachments[k].contentType == "application/octet-stream"))
            {
                newAttachments[k].contentType = upCt;
            }
            uploadIdx++;
        }

        det.attachments = newAttachments;
        det.sourceInfo = sourceInfo;
        det.destInfo = destInfo;
        det.lastUpdate = time(NULL);

        // Count attachments with bytes for the debug log
        int withBytes = 0;
        for (size_t k = 0; k < det.attachments.size(); k++)
            if (!det.attachments[k].data.empty()) withBytes++;

        printf("[Gmail] Detection updated: %s -> %s, subject=\"%.30s\", body=%d bytes, attachments=%d (%d with body)\n",
            sender.c_str(), recipient.c_str(),
            subject.empty() ? "(empty)" : subject.c_str(),
            (int)bodyPlain.size(),
            (int)det.attachments.size(),
            withBytes);
    }

    // Early PII check — if the body, subject, or any text-like
    // attachment already contains enough RRN matches to hit the
    // configured threshold, flush the detection (saves JSON with
    // blocked=true) and signal the caller to tear down the TLS
    // connection so Gmail's server doesn't get the rest of the
    // compose POST body.
    bool shouldClose = false;
    if (!det.logged &&
        (!det.bodyPlain.empty() || !det.subject.empty() ||
         !det.attachments.empty()))
    {
        ParsedEmail testEmail;
        testEmail.bodyPlainText = det.bodyPlain;
        testEmail.subject = det.subject;
        // Critical: pass attachments through so checkPiiAndBlock's
        // buildPiiScanContent can scan their text. Without this, an
        // attachment-only PII (text in test.txt, none in the body)
        // slips past the early gate and only gets caught at flush time
        // — by which point the compose POST has already been forwarded
        // and the email has been sent.
        testEmail.attachments = det.attachments;

        std::string ruleName, matchedPattern;
        int matchCount = 0;
        if (checkPiiAndBlock(testEmail, ruleName, matchCount, matchedPattern))
        {
            printf("\n*** [BLOCKED] Gmail PII detected — closing TLS connection ***\n");
            printf("  Rule: %s, Matches: %d (threshold reached)\n",
                ruleName.c_str(), matchCount);
            printf("  Closing connection so Gmail's server cannot complete the send.\n\n");

            // Flush now: prints the standard detection block and writes
            // the JSON log with blocked=true via logEmailFromProxy.
            flushPendingDetection(det);
            shouldClose = true;
        }
    }

    LeaveCriticalSection(&g_pendingLock);

    // Don't clear data - keep accumulating for better detections
    return shouldClose;
}

// =============================================
//  Persistent upload cache (realattid -> body bytes)
// =============================================
// Gmail's web client uses the resumable-upload protocol:
//   1) POST /upload/?...&realattid=f_xxx   (X-Goog-Upload-Command: start)
//          body = metadata (compose-association); URL carries the realattid
//   2) POST /upload/?upload_id=...         (X-Goog-Upload-Command: upload)
//          body = the actual file bytes
//   3) Later compose POSTs reference "f_xxx" by string
//
// If the user attempts to send the same draft twice (e.g., we blocked the
// first send and they hit "Send" again), Gmail does NOT re-upload — it
// simply re-references the already-uploaded "f_xxx" in the new compose
// POST. So our per-connection capturedUploads is empty and we'd lose
// access to the file content. To fix that, we cache upload bodies
// globally keyed by realattid the first time we see them, and look them
// up when a later compose POST references the same id.

static CRITICAL_SECTION g_uploadCacheLock;
static std::map<std::string, std::vector<unsigned char> > g_uploadCache;
static bool g_uploadCacheInit = false;

static void initUploadCache()
{
    if (!g_uploadCacheInit)
    {
        InitializeCriticalSection(&g_uploadCacheLock);
        g_uploadCacheInit = true;
    }
}

static std::string extractRealAttIdFromUrl(const std::string& url)
{
    size_t pos = url.find("realattid=");
    if (pos == std::string::npos) return "";
    pos += 10;  // strlen("realattid=")
    size_t end = pos;
    while (end < url.size() && url[end] != '&' && url[end] != ' ') end++;
    return url.substr(pos, end - pos);
}

static void cacheUploadBody(const std::string& realattid,
    const std::vector<unsigned char>& body)
{
    if (realattid.empty() || body.empty()) return;
    initUploadCache();
    EnterCriticalSection(&g_uploadCacheLock);

    // Soft cap: when the cache grows large, drop the oldest half. This
    // is best-effort eviction (std::map iteration order is by key, which
    // is good enough for a long-running session — realattids look random
    // enough that the eviction won't always hit the same range).
    if (g_uploadCache.size() >= 200)
    {
        size_t toErase = g_uploadCache.size() / 2;
        std::map<std::string, std::vector<unsigned char> >::iterator it =
            g_uploadCache.begin();
        for (size_t i = 0; i < toErase && it != g_uploadCache.end(); i++)
            it = g_uploadCache.erase(it);
    }

    g_uploadCache[realattid] = body;
    LeaveCriticalSection(&g_uploadCacheLock);

    printf("[Gmail/Cache] Stored upload body for realattid=%s (%zu bytes)\n",
        realattid.c_str(), body.size());
}

static bool lookupCachedUploadBody(const std::string& realattid,
    std::vector<unsigned char>& outBody)
{
    if (realattid.empty()) return false;
    if (!g_uploadCacheInit) return false;
    bool found = false;
    EnterCriticalSection(&g_uploadCacheLock);
    std::map<std::string, std::vector<unsigned char> >::iterator it =
        g_uploadCache.find(realattid);
    if (it != g_uploadCache.end())
    {
        outBody = it->second;
        found = true;
    }
    LeaveCriticalSection(&g_uploadCacheLock);
    return found;
}

// Scan a compose POST body for "f_..." realattid references that look
// like Gmail attachment ids. Return them in the order they appear.
static std::vector<std::string> findRealAttIdsInComposeBody(
    const std::string& body)
{
    std::vector<std::string> result;
    std::set<std::string> seen;
    size_t pos = 0;
    while (pos < body.size())
    {
        size_t qStart = body.find("\"f_", pos);
        if (qStart == std::string::npos) break;

        size_t idStart = qStart + 1;  // after the opening quote
        size_t idEnd = idStart;
        const size_t MAX_ID_LEN = 96;
        while (idEnd < body.size() && idEnd - idStart < MAX_ID_LEN)
        {
            char c = body[idEnd];
            if (c == '"') break;
            if (!isalnum((unsigned char)c) && c != '_' && c != '-' && c != '.')
                break;
            idEnd++;
        }

        if (idEnd > idStart + 2 && idEnd < body.size() && body[idEnd] == '"')
        {
            std::string id = body.substr(idStart, idEnd - idStart);
            if (seen.find(id) == seen.end())
            {
                seen.insert(id);
                result.push_back(id);
            }
        }

        pos = idEnd + 1;
    }
    return result;
}

// =============================================
//  Client->Server stream filter (compose POST body buffering)
// =============================================
// Streams non-compose HTTP requests through to Gmail's server byte by
// byte (so file uploads and other traffic aren't delayed), but holds
// back the body of compose POST requests (POST .../sync/u/.../i/s)
// until the body is complete. At that point we run the existing PII
// scan; if any RRN match exceeds the configured threshold we never
// forward the body, so Gmail's server receives a truncated request and
// the message is genuinely not sent.

struct ClientStream
{
    enum Phase { READING_HEADERS, BUFFER_COMPOSE_BODY, PASSTHROUGH_BODY };
    Phase phase;
    std::string headerBuf;        // accumulating until \r\n\r\n
    std::string composeBuffer;    // headers + body for an active compose POST
    int  contentLength;
    int  bodyRemaining;
    // Realattid carried from the most recent /upload start command on
    // this connection — used to key the next /upload upload command's
    // body bytes when storing them in the global upload cache.
    std::string pendingRealAttId;

    ClientStream()
        : phase(READING_HEADERS), contentLength(0), bodyRemaining(0) {}
};

static int parseContentLengthFromHeaders(const std::string& headers)
{
    // Case-insensitive search for Content-Length
    size_t pos = headers.find("Content-Length:");
    if (pos == std::string::npos) pos = headers.find("content-length:");
    if (pos == std::string::npos) pos = headers.find("CONTENT-LENGTH:");
    if (pos == std::string::npos) return 0;

    size_t valStart = pos + 15;  // strlen("Content-Length:")
    while (valStart < headers.size() &&
           (headers[valStart] == ' ' || headers[valStart] == '\t'))
        valStart++;
    return atoi(headers.c_str() + valStart);
}

// True if the request line looks like a Gmail compose-send POST.
//   POST <path containing /sync/u/ AND /i/s> HTTP/1.1
static bool isComposeRequestLine(const std::string& firstLine)
{
    if (firstLine.find("POST ") != 0) return false;
    if (firstLine.find("/sync/u/") == std::string::npos) return false;
    if (firstLine.find("/i/s") == std::string::npos) return false;
    return true;
}

// Capture /upload bodies from any HTTP requests parsed out of the
// forwarded byte stream. Gmail's resumable upload sends the file across
// two requests:
//   start   — body = compose-association metadata, URL has realattid
//   upload  — body = actual file bytes, URL has upload_id (no realattid)
// We pair them up: remember the realattid from the start command, and
// when the matching upload command arrives, cache its body globally
// keyed by that realattid (so a later compose POST that re-references
// the same realattid can still get the bytes for PII scanning).
static void absorbUploadRequests(
    ClientStream& cs,
    const std::vector<HttpMessage>& reqs,
    std::vector<std::pair<std::string, std::vector<unsigned char> > >& captured)
{
    for (size_t r = 0; r < reqs.size(); r++)
    {
        const HttpMessage& req = reqs[r];
        if (req.isResponse) continue;
        if (req.url.find("/upload") == std::string::npos) continue;

        std::string lowerCmd;
        std::map<std::string, std::string>::const_iterator cmdIt =
            req.headers.find("x-goog-upload-command");
        if (cmdIt != req.headers.end())
        {
            lowerCmd = cmdIt->second;
            for (size_t i = 0; i < lowerCmd.size(); i++)
                lowerCmd[i] = (char)tolower((unsigned char)lowerCmd[i]);
        }

        bool isStart  = lowerCmd.find("start")  != std::string::npos;
        bool isUpload = lowerCmd.find("upload") != std::string::npos;

        if (isStart)
        {
            // Modern Gmail uploads carry no realattid in the URL —
            // realattid comes from the compose POST body instead, and
            // we tie it to the upload body in dispatchComposePost.
            std::string realattid = extractRealAttIdFromUrl(req.url);
            if (!realattid.empty())
            {
                cs.pendingRealAttId = realattid;
                printf("[Gmail/Cache] start cmd realattid=%s\n",
                    realattid.c_str());
            }
            continue;  // start body is metadata, not the file
        }

        if (!isUpload)
        {
            if (!lowerCmd.empty())
                printf("[Gmail] Skipped /upload request (cmd=%s, %d bytes)\n",
                    cmdIt->second.c_str(), (int)req.body.size());
            continue;
        }

        if (req.body.empty()) continue;

        std::vector<unsigned char> bytes(req.body.begin(), req.body.end());
        std::map<std::string, std::string>::const_iterator ctIt =
            req.headers.find("content-type");
        std::string ct = (ctIt != req.headers.end()) ? ctIt->second : "";
        std::map<std::string, std::string>::const_iterator uctIt =
            req.headers.find("x-goog-upload-header-content-type");
        if (uctIt != req.headers.end() && !uctIt->second.empty())
            ct = uctIt->second;

        captured.push_back(std::make_pair(ct, bytes));
        printf("[Gmail] Captured upload: %d bytes, type=%s, url=%.200s\n",
            (int)bytes.size(),
            ct.empty() ? "(none)" : ct.c_str(),
            req.url.c_str());

        // Best-effort: cache the body by realattid if we happen to
        // have one. With modern Gmail this usually doesn't fire because
        // realattid isn't in the upload URL — the actual cache fill
        // happens later in dispatchComposePost where we can pair the
        // body with the realattid named in the compose POST.
        std::string cacheKey = cs.pendingRealAttId;
        if (cacheKey.empty()) cacheKey = extractRealAttIdFromUrl(req.url);
        if (!cacheKey.empty())
        {
            cacheUploadBody(cacheKey, bytes);
            cs.pendingRealAttId.clear();
        }
    }
}

// Forward bytes to the server AND feed them to clientHttp so /upload
// tracking stays in sync.
static void forwardClientBytes(
    ClientStream& cs,
    SSL* serverSsl,
    HttpStreamParser& clientHttp,
    std::vector<std::pair<std::string, std::vector<unsigned char> > >& captured,
    const char* data, int len)
{
    if (len <= 0) return;
    SSL_write(serverSsl, data, len);
    std::vector<HttpMessage> reqs = clientHttp.feedData(data, len);
    if (!reqs.empty()) absorbUploadRequests(cs, reqs, captured);
}

// A compose POST has finished arriving. Run the PII scanner on its body;
// if it reaches the configured RRN threshold, drop the entire request
// (the server never sees it -> the message is genuinely not sent).
// Otherwise forward the buffered request through.
// Returns true if blocked (caller should tear down the connection).
static bool dispatchComposePost(
    ClientStream& cs,
    SSL* serverSsl,
    HttpStreamParser& clientHttp,
    std::vector<std::pair<std::string, std::vector<unsigned char> > >& capturedUploads,
    const std::string& sourceInfo,
    const std::string& destInfo)
{
    size_t hdrEnd = cs.composeBuffer.find("\r\n\r\n");
    if (hdrEnd == std::string::npos)
    {
        // Should not happen — we only enter BUFFER_COMPOSE_BODY after
        // seeing \r\n\r\n. Fall back to forwarding.
        forwardClientBytes(cs, serverSsl, clientHttp, capturedUploads,
            cs.composeBuffer.data(), (int)cs.composeBuffer.size());
        cs.composeBuffer.clear();
        cs.phase = ClientStream::READING_HEADERS;
        return false;
    }

    std::string body = cs.composeBuffer.substr(hdrEnd + 4);

    // Drop any stale PendingDetection for this sender->recipient pair so
    // scanForEmailData evaluates THIS compose POST as a fresh email.
    {
        std::string s, sn, r, rn, sj, bh;
        if (parseGmailComposeData(body, s, sn, r, rn, sj, bh) &&
            !s.empty() && !r.empty() && g_pendingInitialized)
        {
            EnterCriticalSection(&g_pendingLock);
            g_pendingDetections.erase(s + "->" + r);
            LeaveCriticalSection(&g_pendingLock);
        }
    }

    // Pair realattids (from this compose body) with upload bodies
    // (from this connection's captures), and persist the association
    // globally. This is the critical insight: Gmail's modern upload
    // protocol doesn't put realattid in the upload URL, so we can't
    // key uploads by realattid at upload time. But on the first send
    // attempt we DO see both sides — the upload bytes via /upload,
    // and the realattid that names them via the compose POST body.
    // Caching the pair now means a later retry (same realattid, no
    // re-upload) hits the cache and can be PII-scanned.
    std::vector<std::pair<std::string, std::vector<unsigned char> > > scanUploads
        = capturedUploads;
    {
        std::vector<std::string> ids = findRealAttIdsInComposeBody(body);
        printf("[Gmail/Cache] Compose body contains %d realattid-like "
            "reference(s); per-conn captured=%d\n",
            (int)ids.size(), (int)capturedUploads.size());

        // First pass: cache (realattid -> upload body) pairs. Match
        // by index (Nth realattid <-> Nth captured upload).
        size_t pairCount = (ids.size() < capturedUploads.size())
            ? ids.size() : capturedUploads.size();
        for (size_t i = 0; i < pairCount; i++)
        {
            if (capturedUploads[i].second.empty()) continue;
            std::vector<unsigned char> existing;
            if (lookupCachedUploadBody(ids[i], existing)) continue;
            cacheUploadBody(ids[i], capturedUploads[i].second);
        }

        // Second pass: for any realattid we don't yet have locally,
        // try the global cache (handles retry case where Gmail
        // re-references a previously-uploaded file without re-upload).
        for (size_t i = 0; i < ids.size(); i++)
        {
            std::vector<unsigned char> cached;
            if (!lookupCachedUploadBody(ids[i], cached))
            {
                printf("[Gmail/Cache]   ref[%d]=%s -> not in cache\n",
                    (int)i, ids[i].c_str());
                continue;
            }

            bool already = false;
            for (size_t k = 0; k < scanUploads.size(); k++)
            {
                if (scanUploads[k].second == cached) { already = true; break; }
            }
            if (already)
            {
                printf("[Gmail/Cache]   ref[%d]=%s -> already in scanUploads "
                    "(local capture)\n", (int)i, ids[i].c_str());
                continue;
            }

            scanUploads.push_back(std::make_pair(std::string(""), cached));
            printf("[Gmail/Cache]   ref[%d]=%s -> using cached body "
                "(%zu bytes)\n",
                (int)i, ids[i].c_str(), cached.size());
        }
    }

    // scanForEmailData parses the compose JSON, updates the PendingDetection,
    // runs the PII regex, and (when blocked) flushes the detection so the
    // JSON log records blocked=true. Its return value is the block signal.
    bool blocked = scanForEmailData(body, "CLIENT->SERVER",
        sourceInfo, destInfo, scanUploads);

    if (blocked)
    {
        printf("[Gmail/Block] Compose POST WITHHELD — %d bytes never "
            "reach Gmail's server. Email is not sent.\n",
            (int)cs.composeBuffer.size());
        cs.composeBuffer.clear();
        cs.phase = ClientStream::READING_HEADERS;
        return true;
    }

    // Clean — flush the entire request (headers + body) to the server in
    // one shot.
    forwardClientBytes(cs, serverSsl, clientHttp, capturedUploads,
        cs.composeBuffer.data(), (int)cs.composeBuffer.size());
    cs.composeBuffer.clear();
    cs.phase = ClientStream::READING_HEADERS;
    return false;
}

// Process one chunk of decrypted client->server bytes. Forwards them
// to the server one HTTP request at a time, buffering the body of
// compose POSTs so the PII scanner can decide before the bytes leave
// the proxy. Returns true if a block was triggered.
static bool processClientChunk(
    ClientStream& cs,
    const char* buf, int n,
    SSL* serverSsl,
    HttpStreamParser& clientHttp,
    std::vector<std::pair<std::string, std::vector<unsigned char> > >& capturedUploads,
    const std::string& sourceInfo,
    const std::string& destInfo)
{
    int pos = 0;
    while (pos < n)
    {
        if (cs.phase == ClientStream::READING_HEADERS)
        {
            int avail = n - pos;
            const int MAX_HEADER = 65536;

            if ((int)cs.headerBuf.size() + avail > MAX_HEADER)
            {
                // Pathological — bail and just forward
                forwardClientBytes(cs, serverSsl, clientHttp, capturedUploads,
                    cs.headerBuf.data(), (int)cs.headerBuf.size());
                forwardClientBytes(cs, serverSsl, clientHttp, capturedUploads,
                    buf + pos, avail);
                cs.headerBuf.clear();
                pos += avail;
                continue;
            }

            size_t prevSize = cs.headerBuf.size();
            cs.headerBuf.append(buf + pos, avail);

            size_t hdrEnd = cs.headerBuf.find("\r\n\r\n");
            if (hdrEnd == std::string::npos)
            {
                pos += avail;
                continue;  // need more
            }

            // Parse first line + Content-Length
            std::string headers = cs.headerBuf.substr(0, hdrEnd);
            size_t flEnd = headers.find("\r\n");
            std::string firstLine = (flEnd == std::string::npos)
                ? headers : headers.substr(0, flEnd);
            int contentLength = parseContentLengthFromHeaders(headers);

            // How many body bytes did we already read into headerBuf?
            int bodyAlreadyHave = (int)(cs.headerBuf.size() - hdrEnd - 4);
            int bodyRemaining = contentLength - bodyAlreadyHave;
            if (bodyRemaining < 0) bodyRemaining = 0;

            // pos in buf has advanced by `avail` already (we appended the
            // whole tail of buf into headerBuf).
            pos += avail;

            if (isComposeRequestLine(firstLine))
            {
                printf("[Gmail/Block] Compose POST detected, "
                    "buffering body (Content-Length=%d) for PII scan\n",
                    contentLength);

                cs.phase = ClientStream::BUFFER_COMPOSE_BODY;
                cs.composeBuffer = cs.headerBuf;
                cs.headerBuf.clear();
                cs.contentLength = contentLength;
                cs.bodyRemaining = bodyRemaining;

                if (cs.bodyRemaining <= 0)
                {
                    if (dispatchComposePost(cs, serverSsl, clientHttp,
                        capturedUploads, sourceInfo, destInfo))
                        return true;
                }
            }
            else
            {
                // Normal request — forward what we've accumulated and
                // switch to streaming mode for the body.
                forwardClientBytes(cs, serverSsl, clientHttp, capturedUploads,
                    cs.headerBuf.data(), (int)cs.headerBuf.size());
                cs.headerBuf.clear();

                if (bodyRemaining > 0)
                {
                    cs.phase = ClientStream::PASSTHROUGH_BODY;
                    cs.bodyRemaining = bodyRemaining;
                }
                else
                {
                    cs.phase = ClientStream::READING_HEADERS;
                }
            }
        }
        else if (cs.phase == ClientStream::BUFFER_COMPOSE_BODY)
        {
            int avail = n - pos;
            int toCopy = (avail < cs.bodyRemaining) ? avail : cs.bodyRemaining;
            cs.composeBuffer.append(buf + pos, toCopy);
            cs.bodyRemaining -= toCopy;
            pos += toCopy;

            if (cs.bodyRemaining <= 0)
            {
                if (dispatchComposePost(cs, serverSsl, clientHttp,
                    capturedUploads, sourceInfo, destInfo))
                    return true;
            }
        }
        else  // PASSTHROUGH_BODY
        {
            int avail = n - pos;
            int toForward = (avail < cs.bodyRemaining) ? avail : cs.bodyRemaining;
            forwardClientBytes(cs, serverSsl, clientHttp, capturedUploads,
                buf + pos, toForward);
            cs.bodyRemaining -= toForward;
            pos += toForward;
            if (cs.bodyRemaining <= 0)
                cs.phase = ClientStream::READING_HEADERS;
        }
    }
    return false;
}

// Scan raw decrypted data for email-related patterns.
// Instead of parsing HTTP, we accumulate chunks and search for
// email address patterns + surrounding text (subject, body).
// This works regardless of HTTP version or Gmail API format.
static void relayHttpsData(SSL* clientSsl, SSL* serverSsl,
    const std::string& sourceInfo, const std::string& destInfo)
{
    char buf[16384];
    fd_set readfds;
    struct timeval tv;

    SOCKET clientFd = SSL_get_fd(clientSsl);
    SOCKET serverFd = SSL_get_fd(serverSsl);

    bool running = true;
    int totalClientBytes = 0;
    int totalServerBytes = 0;

    // Stream filter that selectively buffers compose POST bodies so we
    // can scan for PII before the bytes ever reach Gmail's server.
    ClientStream cs;

    // HTTP parser for the bytes we DO forward — it's used to surface
    // /upload request bodies (Gmail attachment file content).
    HttpStreamParser clientHttp;
    std::vector<std::pair<std::string, std::vector<unsigned char> > > capturedUploads;

    while (running)
    {
        // IMPORTANT: Check SSL_pending() first!
        // OpenSSL may have already buffered data internally that select() won't see.
        // If we skip this check, the relay stalls (especially during file uploads).
        bool clientHasPending = (SSL_pending(clientSsl) > 0);
        bool serverHasPending = (SSL_pending(serverSsl) > 0);

        if (!clientHasPending && !serverHasPending)
        {
            // No SSL-buffered data, use select() to wait for socket-level data
            FD_ZERO(&readfds);
            FD_SET(clientFd, &readfds);
            FD_SET(serverFd, &readfds);

            tv.tv_sec = 60;
            tv.tv_usec = 0;

            SOCKET maxFd = (clientFd > serverFd) ? clientFd : serverFd;
            int ret = select((int)maxFd + 1, &readfds, NULL, NULL, &tv);

            if (ret <= 0)
            {
                if (ret < 0) running = false;
                // Periodically flush pending detections during idle
                checkPendingDetections(3);
                continue;
            }
        }
        else
        {
            // SSL has buffered data, fake the fd_set so we read it
            FD_ZERO(&readfds);
            if (clientHasPending) FD_SET(clientFd, &readfds);
            if (serverHasPending) FD_SET(serverFd, &readfds);
            // Also check socket-level with zero timeout (non-blocking poll)
            fd_set pollSet;
            FD_ZERO(&pollSet);
            FD_SET(clientFd, &pollSet);
            FD_SET(serverFd, &pollSet);
            tv.tv_sec = 0;
            tv.tv_usec = 0;
            SOCKET maxFd = (clientFd > serverFd) ? clientFd : serverFd;
            if (select((int)maxFd + 1, &pollSet, NULL, NULL, &tv) > 0)
            {
                if (FD_ISSET(clientFd, &pollSet)) FD_SET(clientFd, &readfds);
                if (FD_ISSET(serverFd, &pollSet)) FD_SET(serverFd, &readfds);
            }
        }

        // Client -> Server (browser sends data to Gmail)
        if (FD_ISSET(clientFd, &readfds) || SSL_pending(clientSsl) > 0)
        {
            int n = SSL_read(clientSsl, buf, sizeof(buf));
            if (n <= 0)
            {
                int err = SSL_get_error(clientSsl, n);
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
                {
                    running = false;
                    break;
                }
            }
            else
            {
                totalClientBytes += n;

                // Hand the chunk to the stream filter. Non-compose requests
                // are forwarded to Gmail's server immediately byte-by-byte;
                // compose POST bodies are buffered until complete, scanned,
                // and either forwarded (clean) or dropped (PII detected).
                bool blocked = processClientChunk(
                    cs, buf, n, serverSsl, clientHttp, capturedUploads,
                    sourceInfo, destInfo);

                if (blocked)
                {
                    // PII block triggered — the compose POST body was never
                    // forwarded, so Gmail's server doesn't have the message.
                    // Tear down the TLS connection.
                    running = false;
                    break;
                }
            }
        }

        // Periodically flush pending detections (3 second delay)
        checkPendingDetections(3);

        // Server -> Client (just forward, no scanning needed)
        if (FD_ISSET(serverFd, &readfds) || SSL_pending(serverSsl) > 0)
        {
            int n = SSL_read(serverSsl, buf, sizeof(buf));
            if (n <= 0)
            {
                int err = SSL_get_error(serverSsl, n);
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE)
                {
                    running = false;
                    break;
                }
            }
            else
            {
                int written = SSL_write(clientSsl, buf, n);
                if (written <= 0) { running = false; break; }

                totalServerBytes += n;
            }
        }
    }

    // Flush any pending detections immediately when connection closes —
    // catches detections that were updated but never blocked (i.e., legit
    // emails that finished forwarding) so their JSON log is saved.
    checkPendingDetections(0);

    printf("[Gmail] Session ended (client=%d KB, server=%d KB)\n",
        totalClientBytes / 1024, totalServerBytes / 1024);
}

// =============================================
//  SNI extraction from raw TLS ClientHello
// =============================================

// Parse SNI hostname from a TLS ClientHello message (raw bytes)
// Returns empty string if SNI not found
static std::string extractSniFromClientHello(const char* data, int len)
{
    // TLS record: type(1) + version(2) + length(2) + payload
    if (len < 5) return "";
    if ((unsigned char)data[0] != 0x16) return "";  // Not a Handshake record

    int recordLen = ((unsigned char)data[3] << 8) | (unsigned char)data[4];
    int pos = 5;  // Start of handshake payload

    if (pos >= len) return "";
    if ((unsigned char)data[pos] != 0x01) return "";  // Not ClientHello
    pos++;

    // Handshake length (3 bytes)
    if (pos + 3 > len) return "";
    pos += 3;

    // Client version (2 bytes)
    if (pos + 2 > len) return "";
    pos += 2;

    // Random (32 bytes)
    if (pos + 32 > len) return "";
    pos += 32;

    // Session ID (variable)
    if (pos + 1 > len) return "";
    int sessionIdLen = (unsigned char)data[pos];
    pos += 1 + sessionIdLen;

    // Cipher suites (variable)
    if (pos + 2 > len) return "";
    int cipherLen = ((unsigned char)data[pos] << 8) | (unsigned char)data[pos + 1];
    pos += 2 + cipherLen;

    // Compression methods (variable)
    if (pos + 1 > len) return "";
    int compLen = (unsigned char)data[pos];
    pos += 1 + compLen;

    // Extensions
    if (pos + 2 > len) return "";
    int extTotalLen = ((unsigned char)data[pos] << 8) | (unsigned char)data[pos + 1];
    pos += 2;

    int extEnd = pos + extTotalLen;
    if (extEnd > len) extEnd = len;

    while (pos + 4 <= extEnd)
    {
        int extType = ((unsigned char)data[pos] << 8) | (unsigned char)data[pos + 1];
        int extLen = ((unsigned char)data[pos + 2] << 8) | (unsigned char)data[pos + 3];
        pos += 4;

        if (extType == 0x0000 && extLen > 0)  // SNI extension
        {
            // Server Name List: list_length(2) + entries
            if (pos + 2 > extEnd) break;
            // int listLen = ((unsigned char)data[pos] << 8) | (unsigned char)data[pos + 1];
            int spos = pos + 2;

            if (spos + 3 > extEnd) break;
            int nameType = (unsigned char)data[spos];
            int nameLen = ((unsigned char)data[spos + 1] << 8) | (unsigned char)data[spos + 2];
            spos += 3;

            if (nameType == 0 && spos + nameLen <= extEnd)  // host_name
            {
                return std::string(data + spos, nameLen);
            }
        }

        pos += extLen;
    }

    return "";
}

// Raw TCP tunnel: just forward bytes between client and server without TLS termination
// Used for non-Gmail HTTPS traffic (pass-through without MITM)
static void rawTcpTunnel(SOCKET clientSock, SOCKET serverSock,
    const char* initialData, int initialLen)
{
    // First send the initial data (ClientHello) that we already peeked
    if (initialData && initialLen > 0)
    {
        send(serverSock, initialData, initialLen, 0);
    }

    fd_set readfds;
    struct timeval tv;
    char buf[16384];

    bool running = true;
    while (running)
    {
        FD_ZERO(&readfds);
        FD_SET(clientSock, &readfds);
        FD_SET(serverSock, &readfds);

        tv.tv_sec = 60;
        tv.tv_usec = 0;

        SOCKET maxFd = (clientSock > serverSock) ? clientSock : serverSock;
        int ret = select((int)maxFd + 1, &readfds, NULL, NULL, &tv);
        if (ret <= 0)
        {
            running = false;
            break;
        }

        if (FD_ISSET(clientSock, &readfds))
        {
            int n = recv(clientSock, buf, sizeof(buf), 0);
            if (n <= 0) { running = false; break; }
            send(serverSock, buf, n, 0);
        }

        if (FD_ISSET(serverSock, &readfds))
        {
            int n = recv(serverSock, buf, sizeof(buf), 0);
            if (n <= 0) { running = false; break; }
            send(clientSock, buf, n, 0);
        }
    }
}

// Only MITM mail.google.com - all other Google traffic passes through.
// This avoids breaking Chrome while still catching Gmail email data.
static bool isTargetHostname(const std::string& hostname)
{
    if (hostname == "mail.google.com") return true;
    return false;
}

// Thread function: handle one proxied connection
static unsigned __stdcall proxyConnectionThread(void* param)
{
    ProxyThreadParam* p = (ProxyThreadParam*)param;
    SOCKET clientSock = p->clientSock;
    CertGenerator* certGen = p->certGen;
    unsigned short clientPort = p->clientPort;
    delete p;

    // Look up original destination
    OriginalDest dest;
    if (!getOriginalDest(clientPort, dest))
    {
        printf("[TlsProxy] No original dest found for client port %d\n", clientPort);
        closesocket(clientSock);
        return 0;
    }
    removeOriginalDest(clientPort);

    std::string hostname = dest.hostname;
    if (hostname.empty())
        hostname = resolveHostname(dest.ip, dest.port);

    const char* modeStr = dest.isHttps ? "HTTPS" :
                          (dest.implicitTls ? "implicit TLS" : "STARTTLS");
    // Only log SMTP connections here; HTTPS connections logged after SNI check
    if (!dest.isHttps)
    {
        printf("[TlsProxy] Handling connection: client_port=%d -> %s:%d (%s) [%s]\n",
            clientPort, hostname.c_str(), dest.port, dest.ip.c_str(), modeStr);
    }

    std::string sourceInfo = "proxy_client:" + std::string(intToStr2(clientPort));
    std::string destInfo = hostname + ":" + std::string(intToStr2(dest.port));

    if (dest.isHttps)
    {
        // Port 443: HTTPS - use MSG_PEEK to read SNI without consuming data
        char peekBuf[4096];
        int peekLen = recv(clientSock, peekBuf, sizeof(peekBuf), MSG_PEEK);
        if (peekLen <= 0)
        {
            printf("[TlsProxy] Failed to peek ClientHello from browser\n");
            closesocket(clientSock);
            return 0;
        }

        std::string sniHostname = extractSniFromClientHello(peekBuf, peekLen);
        if (!sniHostname.empty())
        {
            hostname = sniHostname;
            destInfo = hostname + ":443";
        }
        // Decision: MITM only mail.google.com, tunnel everything else
        if (!isTargetHostname(hostname))
        {
            // Non-target: silently connect to real server and do raw TCP tunnel
            SOCKET serverSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (serverSock != INVALID_SOCKET)
            {
                struct sockaddr_in serverAddr;
                memset(&serverAddr, 0, sizeof(serverAddr));
                serverAddr.sin_family = AF_INET;
                serverAddr.sin_port = htons(dest.port);
                inet_pton(AF_INET, dest.ip.c_str(), &serverAddr.sin_addr);

                if (connect(serverSock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == 0)
                {
                    // Silent tunnel for non-Gmail traffic
                    rawTcpTunnel(clientSock, serverSock, NULL, 0);
                }
                closesocket(serverSock);
            }
            closesocket(clientSock);
            return 0;
        }

        // This IS mail.google.com - log it
        printf("[TlsProxy] SNI: %s (target) -> starting MITM\n", hostname.c_str());

        // Gmail traffic: do full MITM

        // Step 1: Connect to real Google server with TLS (proxy as client)
        SOCKET serverSock = INVALID_SOCKET;
        SSL* serverSsl = connectToRealServer(dest.ip, dest.port, &serverSock, hostname);
        if (!serverSsl)
        {
            printf("[TlsProxy] Failed TLS connect to %s:%d\n", dest.ip.c_str(), dest.port);
            closesocket(clientSock);
            return 0;
        }

        // Step 2: Accept TLS from browser (proxy as server with fake cert)
        // MSG_PEEK left the ClientHello in the socket buffer,
        // so SSL_accept will read it naturally
        SSL* clientSsl = acceptTlsFromClient(clientSock, certGen, hostname);
        if (!clientSsl)
        {
            printf("[TlsProxy] Failed MITM handshake with browser for %s\n", hostname.c_str());
            SSL_shutdown(serverSsl);
            SSL_free(serverSsl);
            closesocket(serverSock);
            closesocket(clientSock);
            return 0;
        }

        printf("[TlsProxy] HTTPS MITM established for %s\n", hostname.c_str());
        printf("[TlsProxy] Monitoring Gmail traffic for email data...\n");

        // Step 3: Relay decrypted HTTP, parsing Gmail sync data
        relayHttpsData(clientSsl, serverSsl, sourceInfo, destInfo);

        SSL_shutdown(clientSsl);
        SSL_shutdown(serverSsl);
        SSL_free(clientSsl);
        SSL_free(serverSsl);
        closesocket(serverSock);
    }
    else if (dest.implicitTls)
    {
        // Port 465: immediate TLS on both sides
        SOCKET serverSock = INVALID_SOCKET;
        SSL* serverSsl = connectToRealServer(dest.ip, dest.port, &serverSock, hostname);
        if (!serverSsl)
        {
            printf("[TlsProxy] Failed to connect to real server %s:%d\n",
                dest.ip.c_str(), dest.port);
            closesocket(clientSock);
            return 0;
        }

        SSL* clientSsl = acceptTlsFromClient(clientSock, certGen, hostname);
        if (!clientSsl)
        {
            printf("[TlsProxy] Failed TLS handshake with client\n");
            SSL_shutdown(serverSsl);
            SSL_free(serverSsl);
            closesocket(serverSock);
            closesocket(clientSock);
            return 0;
        }

        printf("[TlsProxy] Implicit TLS established, relaying SMTP...\n");
        relaySmtpData(clientSsl, serverSsl, sourceInfo, destInfo);

        SSL_shutdown(clientSsl);
        SSL_shutdown(serverSsl);
        SSL_free(clientSsl);
        SSL_free(serverSsl);
        closesocket(serverSock);
    }
    else
    {
        // Port 587/25: plaintext first, then STARTTLS
        SOCKET serverSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (serverSock == INVALID_SOCKET)
        {
            closesocket(clientSock);
            return 0;
        }

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(dest.port);
        inet_pton(AF_INET, dest.ip.c_str(), &addr.sin_addr);

        if (connect(serverSock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR)
        {
            printf("[TlsProxy] Failed to connect to %s:%d\n", dest.ip.c_str(), dest.port);
            closesocket(serverSock);
            closesocket(clientSock);
            return 0;
        }

        handleStartTls(clientSock, serverSock, certGen, hostname,
            sourceInfo, destInfo);

        closesocket(serverSock);
    }

    closesocket(clientSock);
    // Only log close for non-HTTPS (SMTP) connections to reduce noise
    if (!dest.isHttps)
        printf("[TlsProxy] Connection closed (client_port=%d)\n", clientPort);
    return 0;
}

// =============================================
//  TlsProxy main class
// =============================================
class TlsProxy
{
public:
    TlsProxy()
        : m_listenSock(INVALID_SOCKET)
        , m_port(0)
        , m_running(false)
        , m_thread(NULL)
    {
    }

    ~TlsProxy()
    {
        stop();
    }

    // Start the proxy on the specified port
    bool start(unsigned short port, CertGenerator* certGen)
    {
        if (m_running) return true;

        m_port = port;
        m_certGen = certGen;

        // Create listening socket
        m_listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (m_listenSock == INVALID_SOCKET)
        {
            printf("[TlsProxy] Failed to create listen socket\n");
            return false;
        }

        // Allow reuse
        int optval = 1;
        setsockopt(m_listenSock, SOL_SOCKET, SO_REUSEADDR, (char*)&optval, sizeof(optval));

        // Bind to localhost only (security: only accept redirected connections)
        struct sockaddr_in bindAddr;
        memset(&bindAddr, 0, sizeof(bindAddr));
        bindAddr.sin_family = AF_INET;
        bindAddr.sin_port = htons(port);
        bindAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // 127.0.0.1 only

        if (bind(m_listenSock, (sockaddr*)&bindAddr, sizeof(bindAddr)) == SOCKET_ERROR)
        {
            printf("[TlsProxy] Bind failed on port %d (error=%d)\n", port, WSAGetLastError());
            closesocket(m_listenSock);
            m_listenSock = INVALID_SOCKET;
            return false;
        }

        if (listen(m_listenSock, SOMAXCONN) == SOCKET_ERROR)
        {
            printf("[TlsProxy] Listen failed\n");
            closesocket(m_listenSock);
            m_listenSock = INVALID_SOCKET;
            return false;
        }

        m_running = true;

        // Start accept thread
        m_thread = (HANDLE)_beginthreadex(NULL, 0, acceptThread, this, 0, NULL);
        if (!m_thread)
        {
            printf("[TlsProxy] Failed to start accept thread\n");
            m_running = false;
            closesocket(m_listenSock);
            m_listenSock = INVALID_SOCKET;
            return false;
        }

        printf("[TlsProxy] Listening on 127.0.0.1:%d\n", port);
        return true;
    }

    void stop()
    {
        m_running = false;

        if (m_listenSock != INVALID_SOCKET)
        {
            closesocket(m_listenSock);
            m_listenSock = INVALID_SOCKET;
        }

        if (m_thread)
        {
            WaitForSingleObject(m_thread, 5000);
            CloseHandle(m_thread);
            m_thread = NULL;
        }
    }

    bool isRunning() const { return m_running; }

private:
    SOCKET          m_listenSock;
    unsigned short  m_port;
    bool            m_running;
    HANDLE          m_thread;
    CertGenerator*  m_certGen;

    static unsigned __stdcall acceptThread(void* param)
    {
        TlsProxy* self = (TlsProxy*)param;

        while (self->m_running)
        {
            struct sockaddr_in clientAddr;
            int addrLen = sizeof(clientAddr);

            SOCKET clientSock = accept(self->m_listenSock,
                (sockaddr*)&clientAddr, &addrLen);

            if (clientSock == INVALID_SOCKET)
            {
                if (self->m_running)
                    printf("[TlsProxy] Accept failed (error=%d)\n", WSAGetLastError());
                continue;
            }

            unsigned short clientPort = ntohs(clientAddr.sin_port);

            // Spawn handler thread
            ProxyThreadParam* p = new ProxyThreadParam();
            p->clientSock = clientSock;
            p->certGen = self->m_certGen;
            p->clientPort = clientPort;

            HANDLE hThread = (HANDLE)_beginthreadex(NULL, 0,
                proxyConnectionThread, p, 0, NULL);
            if (hThread)
                CloseHandle(hThread);  // Detach
            else
            {
                printf("[TlsProxy] Failed to spawn handler thread\n");
                delete p;
                closesocket(clientSock);
            }
        }

        return 0;
    }
};

#endif // TLS_PROXY_H
