/*
 * SmtpTestSender.cpp
 * ==================
 * Simple plaintext SMTP test client for verifying SmtpMailMonitor.
 *
 * This tool sends a test email via plaintext SMTP (no TLS) to a local
 * SMTP server so that SmtpMailMonitor can intercept and parse the traffic.
 *
 * Usage:
 *   SmtpTestSender.exe <server> <port> <from> <to> [--pii]
 *
 * Example:
 *   SmtpTestSender.exe 127.0.0.1 25 sender@test.com receiver@test.com
 *   SmtpTestSender.exe 127.0.0.1 25 sender@test.com receiver@test.com --pii
 *
 * The --pii flag includes Korean resident registration numbers in the body
 * to test the PII blocking feature.
 *
 * NOTE: Requires a local SMTP server (e.g. Papercut, hMailServer, smtp4dev)
 *       listening on the specified port WITHOUT TLS.
 *       Or you can just run it while SmtpMailMonitor is active - even if
 *       the server rejects the mail, the monitor will still parse the data.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>
#include <string>

#pragma comment(lib, "ws2_32.lib")

// Send a string and print it
static bool smtpSend(SOCKET sock, const char* data)
{
    printf("C: %s", data);
    int sent = send(sock, data, (int)strlen(data), 0);
    return (sent > 0);
}

// Receive response and print it
static bool smtpRecv(SOCKET sock)
{
    char buf[4096] = {0};
    int len = recv(sock, buf, sizeof(buf) - 1, 0);
    if (len <= 0)
    {
        printf("  [recv failed or connection closed]\n");
        return false;
    }
    buf[len] = '\0';
    printf("S: %s", buf);
    if (buf[len-1] != '\n') printf("\n");

    // Check for error response (4xx or 5xx)
    if (buf[0] == '4' || buf[0] == '5')
        return false;

    return true;
}

// Get local machine's real (non-loopback) IPv4 address
static std::string getLocalIpAddress()
{
    char hostname[256] = "";
    if (gethostname(hostname, sizeof(hostname)) != 0)
        return "";

    struct addrinfo hints2, *res = NULL;
    memset(&hints2, 0, sizeof(hints2));
    hints2.ai_family = AF_INET;
    hints2.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints2, &res) != 0)
        return "";

    std::string ip;
    for (struct addrinfo* p = res; p != NULL; p = p->ai_next)
    {
        struct sockaddr_in* sin = (struct sockaddr_in*)p->ai_addr;
        char buf[64] = "";
        inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
        // Skip loopback
        if (strncmp(buf, "127.", 4) != 0)
        {
            ip = buf;
            break;
        }
    }
    freeaddrinfo(res);
    return ip;
}

// Check if the server address is loopback
static bool isLoopback(const char* server)
{
    if (_stricmp(server, "localhost") == 0) return true;
    if (strcmp(server, "127.0.0.1") == 0) return true;
    if (strcmp(server, "::1") == 0) return true;
    return false;
}

static void printUsage()
{
    printf("SmtpTestSender - Plaintext SMTP test client\n\n");
    printf("Usage:\n");
    printf("  SmtpTestSender.exe <server> <port> <from> <to> [--pii] [--attach]\n\n");
    printf("Options:\n");
    printf("  --pii     Include resident registration numbers in body (for block test)\n");
    printf("  --attach  Include a simulated MIME attachment\n\n");

    // Show the real IP for convenience
    std::string localIp = getLocalIpAddress();

    printf("IMPORTANT: Do NOT use 127.0.0.1 or localhost!\n");
    printf("  The sockfilter driver cannot intercept loopback traffic.\n");
    printf("  Use your machine's real IP address instead.\n\n");

    if (!localIp.empty())
    {
        printf("  Your IP appears to be: %s\n\n", localIp.c_str());
        printf("Examples:\n");
        printf("  SmtpTestSender.exe %s 25 sender@test.com receiver@test.com\n", localIp.c_str());
        printf("  SmtpTestSender.exe %s 25 sender@test.com receiver@test.com --pii\n", localIp.c_str());
    }
    else
    {
        printf("Examples:\n");
        printf("  SmtpTestSender.exe 192.168.x.x 25 sender@test.com receiver@test.com\n");
        printf("  SmtpTestSender.exe 192.168.x.x 25 sender@test.com receiver@test.com --pii\n");
    }
}

int main(int argc, char* argv[])
{
    if (argc < 5)
    {
        printUsage();
        return 1;
    }

    const char* server = argv[1];
    int port = atoi(argv[2]);
    const char* mailFrom = argv[3];
    const char* mailTo = argv[4];

    bool includePii = false;
    bool includeAttach = false;

    for (int i = 5; i < argc; i++)
    {
        if (strcmp(argv[i], "--pii") == 0) includePii = true;
        if (strcmp(argv[i], "--attach") == 0) includeAttach = true;
    }

    // Initialize Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // Warn if user is trying to use loopback
    if (isLoopback(server))
    {
        printf("============================================================\n");
        printf("  WARNING: You are using a loopback address (%s).\n", server);
        printf("  The sockfilter driver CANNOT intercept loopback traffic!\n");
        printf("  SmtpMailMonitor will NOT detect this connection.\n");
        printf("============================================================\n");

        std::string realIp = getLocalIpAddress();
        if (!realIp.empty())
        {
            printf("  Your real IP: %s\n", realIp.c_str());
            printf("  Make sure your SMTP server listens on 0.0.0.0 (not just 127.0.0.1),\n");
            printf("  then re-run with:  SmtpTestSender.exe %s %d %s %s",
                realIp.c_str(), port, mailFrom, mailTo);
            if (includePii) printf(" --pii");
            if (includeAttach) printf(" --attach");
            printf("\n");
        }
        printf("============================================================\n\n");
        printf("Continuing anyway (for SMTP server test only)...\n\n");
    }

    // Resolve address
    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char portStr[16];
    _snprintf(portStr, sizeof(portStr), "%d", port);

    if (getaddrinfo(server, portStr, &hints, &result) != 0)
    {
        printf("[ERROR] Cannot resolve server: %s\n", server);
        WSACleanup();
        return 1;
    }

    // Connect
    SOCKET sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock == INVALID_SOCKET)
    {
        printf("[ERROR] Socket creation failed\n");
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    printf("[INFO] Connecting to %s:%d ...\n", server, port);
    if (connect(sock, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR)
    {
        printf("[ERROR] Connection failed (error=%d)\n", WSAGetLastError());
        printf("[HINT] Make sure a local SMTP server is running on port %d.\n", port);
        printf("       Recommended: smtp4dev (https://github.com/rnwood/smtp4dev)\n");
        printf("       Or: Papercut SMTP (https://github.com/ChangemakerStudios/Papercut-SMTP)\n");
        closesocket(sock);
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }
    freeaddrinfo(result);

    printf("[INFO] Connected! Sending test email...\n\n");

    // SMTP conversation
    smtpRecv(sock);  // Server greeting

    // EHLO
    smtpSend(sock, "EHLO testclient\r\n");
    smtpRecv(sock);

    // MAIL FROM
    char cmdBuf[512];
    _snprintf(cmdBuf, sizeof(cmdBuf), "MAIL FROM:<%s>\r\n", mailFrom);
    smtpSend(sock, cmdBuf);
    smtpRecv(sock);

    // RCPT TO
    _snprintf(cmdBuf, sizeof(cmdBuf), "RCPT TO:<%s>\r\n", mailTo);
    smtpSend(sock, cmdBuf);
    smtpRecv(sock);

    // DATA
    smtpSend(sock, "DATA\r\n");
    smtpRecv(sock);

    // Build email content
    std::string boundary = "----=_Part_12345_TestBoundary";

    std::string emailData;

    if (includeAttach)
    {
        // MIME multipart message with attachment
        emailData += "From: Test Sender <" + std::string(mailFrom) + ">\r\n";
        emailData += "To: Test Receiver <" + std::string(mailTo) + ">\r\n";
        emailData += "Subject: [TEST] SmtpMailMonitor Test Email with Attachment\r\n";
        emailData += "Date: Tue, 07 Apr 2026 12:00:00 +0900\r\n";
        emailData += "Message-ID: <test-msg-001@smtptest.local>\r\n";
        emailData += "MIME-Version: 1.0\r\n";
        emailData += "Content-Type: multipart/mixed; boundary=\"" + boundary + "\"\r\n";
        emailData += "X-Mailer: SmtpTestSender/1.0\r\n";
        emailData += "\r\n";

        // Text part
        emailData += "--" + boundary + "\r\n";
        emailData += "Content-Type: text/plain; charset=UTF-8\r\n";
        emailData += "Content-Transfer-Encoding: 7bit\r\n";
        emailData += "\r\n";
        emailData += "This is a test email sent by SmtpTestSender.\r\n";
        emailData += "It contains a simulated attachment for testing.\r\n";

        if (includePii)
        {
            emailData += "\r\n";
            emailData += "=== PII Test Data (Korean Resident Registration Numbers) ===\r\n";
            emailData += "Person A: 850101-1234567\r\n";
            emailData += "Person B: 900315-2345678\r\n";
            emailData += "Person C: 951220-1456789\r\n";
            emailData += "=== End PII Test Data ===\r\n";
        }

        emailData += "\r\n";

        // Attachment part (simulated .txt file, base64 encoded)
        emailData += "--" + boundary + "\r\n";
        emailData += "Content-Type: application/octet-stream; name=\"test_document.txt\"\r\n";
        emailData += "Content-Disposition: attachment; filename=\"test_document.txt\"\r\n";
        emailData += "Content-Transfer-Encoding: base64\r\n";
        emailData += "\r\n";
        // Base64 of "Hello, this is a test attachment file.\r\nLine 2 of the test file.\r\n"
        emailData += "SGVsbG8sIHRoaXMgaXMgYSB0ZXN0IGF0dGFjaG1lbnQgZmlsZS4NCkxpbmUg\r\n";
        emailData += "MiBvZiB0aGUgdGVzdCBmaWxlLg0K\r\n";
        emailData += "\r\n";

        // End boundary
        emailData += "--" + boundary + "--\r\n";
    }
    else
    {
        // Simple plain text message
        emailData += "From: Test Sender <" + std::string(mailFrom) + ">\r\n";
        emailData += "To: Test Receiver <" + std::string(mailTo) + ">\r\n";
        emailData += "Subject: [TEST] SmtpMailMonitor Test Email\r\n";
        emailData += "Date: Tue, 07 Apr 2026 12:00:00 +0900\r\n";
        emailData += "Message-ID: <test-msg-002@smtptest.local>\r\n";
        emailData += "MIME-Version: 1.0\r\n";
        emailData += "Content-Type: text/plain; charset=UTF-8\r\n";
        emailData += "Content-Transfer-Encoding: 7bit\r\n";
        emailData += "X-Mailer: SmtpTestSender/1.0\r\n";
        emailData += "\r\n";
        emailData += "This is a test email sent by SmtpTestSender.\r\n";
        emailData += "This email is used to verify SmtpMailMonitor functionality.\r\n";
        emailData += "\r\n";
        emailData += "Features being tested:\r\n";
        emailData += "  1. Email content JSON logging\r\n";
        emailData += "  2. Header parsing (Subject, From, To, Date, etc.)\r\n";
        emailData += "  3. Body content extraction\r\n";

        if (includePii)
        {
            emailData += "\r\n";
            emailData += "=== PII Test Data (Korean Resident Registration Numbers) ===\r\n";
            emailData += "Person A: 850101-1234567\r\n";
            emailData += "Person B: 900315-2345678\r\n";
            emailData += "Person C: 951220-1456789\r\n";
            emailData += "=== End PII Test Data ===\r\n";
        }

        emailData += "\r\n";
        emailData += "-- End of test email --\r\n";
    }

    // Send email data
    smtpSend(sock, emailData.c_str());

    // End of DATA
    smtpSend(sock, ".\r\n");
    smtpRecv(sock);

    // QUIT
    smtpSend(sock, "QUIT\r\n");
    smtpRecv(sock);

    closesocket(sock);
    WSACleanup();

    printf("\n[INFO] Test email sent successfully!\n");

    if (includePii)
    {
        printf("[INFO] PII data included - SmtpMailMonitor should BLOCK this email.\n");
    }
    else
    {
        printf("[INFO] No PII data - SmtpMailMonitor should LOG this email normally.\n");
    }

    printf("[INFO] Check the mail_logs directory for JSON output.\n");

    return 0;
}
