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

static void scanForEmailData(std::string& data, const char* direction,
    const std::string& sourceInfo, const std::string& destInfo)
{
    // Only scan CLIENT->SERVER data (outgoing emails)
    if (std::string(direction).find("SERVER") == 0)
        return;

    // Quick check: must contain "msg-a:" (Gmail compose message marker)
    size_t msgaPos = data.find("\"msg-a:");
    if (msgaPos == std::string::npos)
        return;

    // Body marker [[0," must be present
    if (data.find("[[0,\"", msgaPos) == std::string::npos)
        return;

    // Try to parse Gmail compose data
    std::string sender, senderName, recipient, recipientName, subject, bodyHtml;
    if (!parseGmailComposeData(data, sender, senderName,
        recipient, recipientName, subject, bodyHtml))
        return;

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
        det.sourceInfo = sourceInfo;
        det.destInfo = destInfo;
        det.lastUpdate = time(NULL);

        printf("[Gmail] Detection updated: %s -> %s, subject=\"%.30s\", body=%d bytes\n",
            sender.c_str(), recipient.c_str(),
            subject.empty() ? "(empty)" : subject.c_str(),
            (int)bodyPlain.size());
    }

    LeaveCriticalSection(&g_pendingLock);

    // Don't clear data - keep accumulating for better detections
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

    // Accumulate CLIENT data only (outgoing = mail being sent)
    std::string clientDataBuf;

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
                // Forward to real server FIRST (priority: don't break uploads)
                int written = SSL_write(serverSsl, buf, n);
                if (written <= 0) { running = false; break; }

                totalClientBytes += n;

                // Only accumulate small-to-medium requests for email scanning
                // Skip accumulation for large transfers (file uploads)
                if (clientDataBuf.size() < 65536)
                {
                    clientDataBuf.append(buf, n);

                    // Scan when we have enough data
                    if (clientDataBuf.size() > 512)
                    {
                        scanForEmailData(clientDataBuf, "CLIENT->SERVER",
                            sourceInfo, destInfo);

                        // Trim buffer if getting large
                        if (clientDataBuf.size() > 32768)
                            clientDataBuf = clientDataBuf.substr(
                                clientDataBuf.size() - 2048);
                    }
                }
                else if (totalClientBytes % (256 * 1024) == 0)
                {
                    // Large transfer in progress (likely file upload)
                    printf("[Gmail] Large upload in progress (%d KB)...\n",
                        totalClientBytes / 1024);
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

    // Final scan on remaining client data
    if (!clientDataBuf.empty())
        scanForEmailData(clientDataBuf, "CLIENT->SERVER(final)", sourceInfo, destInfo);

    // Flush any pending detections immediately when connection closes
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
