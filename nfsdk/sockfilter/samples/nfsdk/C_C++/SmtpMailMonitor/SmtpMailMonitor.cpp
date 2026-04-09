/*
 * SmtpMailMonitor.cpp
 * ===================
 * NetFilterSDK-based SMTP mail monitoring/blocking system
 *
 * Features:
 *   1-1) Log outgoing email content as JSON files (GUID-based unique ID)
 *   1-2) Save email attachments to separate folders + metadata in JSON
 *   1-3) Store mail logs in SQLite DB (optional)
 *   2)   Block emails containing PII (resident registration numbers) based on policy
 *
 * Usage:
 *   SmtpMailMonitor.exe [-log <path>] [-db <dbpath>] [-policy <policypath>]
 */

#include "stdafx.h"
#include "nfapi.h"
#include "samples_config.h"

#include "SmtpParser.h"
#include "JsonWriter.h"
#include "GuidUtil.h"

// SQLite3 (add sqlite3.c / sqlite3.h amalgamation to project, or leave USE_SQLITE undefined)
#ifdef USE_SQLITE
#include "sqlite3.h"
#pragma comment(lib, "sqlite3.lib")
#endif

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ole32.lib")

using namespace nfapi;

// =============================================
//  Global settings
// =============================================
static std::string g_logBasePath = ".\\mail_logs";
static std::string g_dbPath = ".\\mail_logs\\mail_log.db";
static std::string g_policyPath = ".\\block_policy.json";

// Block policy structure
struct BlockPolicy
{
    struct PatternRule
    {
        std::string name;
        std::string pattern;     // regex pattern
        int         threshold;   // block if match count >= threshold
        bool        enabled;
    };

    std::vector<PatternRule> rules;
    bool blockingEnabled;

    BlockPolicy() : blockingEnabled(true) {}
};

static BlockPolicy g_blockPolicy;

// =============================================
//  Utility functions
// =============================================

// Helper: int to string (replaces std::to_string for compatibility)
static std::string intToStr(int val)
{
    char buf[32];
    _snprintf(buf, sizeof(buf), "%d", val);
    return std::string(buf);
}

// Create directory recursively
static void ensureDirectoryExists(const std::string& path)
{
    size_t pos = 0;
    while ((pos = path.find_first_of("\\/", pos + 1)) != std::string::npos)
    {
        std::string sub = path.substr(0, pos);
        _mkdir(sub.c_str());
    }
    _mkdir(path.c_str());
}

// Get current timestamp in ISO 8601 format
static std::string getCurrentTimestamp()
{
    time_t now = time(NULL);
    struct tm tmLocal;
    localtime_s(&tmLocal, &now);

    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tmLocal);

    // Add timezone offset
    char tzBuf[16];
    strftime(tzBuf, sizeof(tzBuf), "%z", &tmLocal);
    std::string tz(tzBuf);
    if (tz.size() >= 5)
    {
        // "+0900" -> "+09:00"
        tz.insert(3, ":");
    }

    return std::string(buf) + tz;
}

// Write string to file
static bool writeStringToFile(const std::string& path, const std::string& content)
{
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) return false;
    fwrite(content.c_str(), 1, content.size(), f);
    fclose(f);
    return true;
}

// Write binary data to file
static bool writeBinaryToFile(const std::string& path, const std::vector<unsigned char>& data)
{
    FILE* f = fopen(path.c_str(), "wb");
    if (!f) return false;
    if (!data.empty())
        fwrite(&data[0], 1, data.size(), f);
    fclose(f);
    return true;
}

// Read entire file to string
static std::string readFileToString(const std::string& path)
{
    std::ifstream ifs(path.c_str(), std::ios::binary);
    if (!ifs.is_open()) return "";
    std::ostringstream oss;
    oss << ifs.rdbuf();
    return oss.str();
}

// Simple JSON string value extractor
static std::string jsonExtractString(const std::string& json, const std::string& key)
{
    std::string searchKey = "\"" + key + "\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return "";

    pos = json.find(':', pos + searchKey.size());
    if (pos == std::string::npos) return "";
    pos++;

    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n'))
        pos++;

    if (pos < json.size() && json[pos] == '"')
    {
        pos++;
        size_t end = pos;
        while (end < json.size() && json[end] != '"')
        {
            if (json[end] == '\\') end++;
            end++;
        }
        return json.substr(pos, end - pos);
    }
    return "";
}

// Simple JSON int extractor
static int jsonExtractInt(const std::string& json, const std::string& key)
{
    std::string searchKey = "\"" + key + "\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return 0;

    pos = json.find(':', pos + searchKey.size());
    if (pos == std::string::npos) return 0;
    pos++;

    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t'))
        pos++;

    return atoi(json.c_str() + pos);
}

// Simple JSON bool extractor
static bool jsonExtractBool(const std::string& json, const std::string& key)
{
    std::string searchKey = "\"" + key + "\"";
    size_t pos = json.find(searchKey);
    if (pos == std::string::npos) return false;

    pos = json.find(':', pos + searchKey.size());
    if (pos == std::string::npos) return false;
    pos++;

    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t'))
        pos++;

    return (json.substr(pos, 4) == "true");
}

// =============================================
//  Load block policy from JSON file
// =============================================
static void loadBlockPolicy(const std::string& policyPath)
{
    std::string json = readFileToString(policyPath);
    if (json.empty())
    {
        printf("[Policy] Policy file not found: %s\n", policyPath.c_str());
        printf("[Policy] Using default policy (block if >= 2 resident registration numbers)\n");

        BlockPolicy::PatternRule defaultRule;
        defaultRule.name = "resident_registration_number";
        // Korean RRN pattern: YYMMDD-NNNNNNN
        defaultRule.pattern = "\\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\\d|3[01])[-\\s]?[1-4]\\d{6}";
        defaultRule.threshold = 2;
        defaultRule.enabled = true;
        g_blockPolicy.rules.push_back(defaultRule);
        g_blockPolicy.blockingEnabled = true;
        return;
    }

    printf("[Policy] Loading policy file: %s\n", policyPath.c_str());

    g_blockPolicy.blockingEnabled = jsonExtractBool(json, "blocking_enabled");

    // Parse "rules" array
    size_t rulesPos = json.find("\"rules\"");
    if (rulesPos == std::string::npos) return;

    size_t arrStart = json.find('[', rulesPos);
    size_t arrEnd = json.find(']', arrStart);
    if (arrStart == std::string::npos || arrEnd == std::string::npos) return;

    std::string rulesStr = json.substr(arrStart, arrEnd - arrStart + 1);

    // Parse each rule object
    size_t objPos = 0;
    while ((objPos = rulesStr.find('{', objPos)) != std::string::npos)
    {
        size_t objEnd = rulesStr.find('}', objPos);
        if (objEnd == std::string::npos) break;

        std::string objStr = rulesStr.substr(objPos, objEnd - objPos + 1);

        BlockPolicy::PatternRule rule;
        rule.name = jsonExtractString(objStr, "name");
        rule.pattern = jsonExtractString(objStr, "pattern");
        rule.threshold = jsonExtractInt(objStr, "threshold");
        rule.enabled = jsonExtractBool(objStr, "enabled");

        if (!rule.pattern.empty())
        {
            // Restore escaped backslashes from JSON (\\d -> \d)
            std::string fixedPattern;
            for (size_t i = 0; i < rule.pattern.size(); i++)
            {
                if (rule.pattern[i] == '\\' && i + 1 < rule.pattern.size() && rule.pattern[i + 1] == '\\')
                {
                    fixedPattern += '\\';
                    i++;
                }
                else
                {
                    fixedPattern += rule.pattern[i];
                }
            }
            rule.pattern = fixedPattern;

            g_blockPolicy.rules.push_back(rule);
            printf("[Policy] Rule loaded: name=%s, threshold=%d, enabled=%s\n",
                rule.name.c_str(), rule.threshold, rule.enabled ? "true" : "false");
        }

        objPos = objEnd + 1;
    }
}

// =============================================
//  PII check (determine whether to block)
// =============================================
struct PiiCheckResult
{
    bool        shouldBlock;
    std::string ruleName;
    int         matchCount;
    std::string matchedPattern;

    PiiCheckResult() : shouldBlock(false), matchCount(0) {}
};

static PiiCheckResult checkPiiInContent(const std::string& content)
{
    PiiCheckResult result;

    if (!g_blockPolicy.blockingEnabled)
        return result;

    for (size_t i = 0; i < g_blockPolicy.rules.size(); i++)
    {
        const BlockPolicy::PatternRule& rule = g_blockPolicy.rules[i];
        if (!rule.enabled) continue;

        try
        {
            std::regex re(rule.pattern);
            std::sregex_iterator begin(content.begin(), content.end(), re);
            std::sregex_iterator end;

            int count = 0;
            for (std::sregex_iterator it = begin; it != end; ++it)
            {
                count++;
            }

            if (count >= rule.threshold)
            {
                result.shouldBlock = true;
                result.ruleName = rule.name;
                result.matchCount = count;
                result.matchedPattern = rule.pattern;

                printf("[BLOCK] PII detected! rule='%s', count=%d, threshold=%d -> BLOCKED\n",
                    rule.name.c_str(), count, rule.threshold);
                return result;
            }
            else if (count > 0)
            {
                printf("[WARN] PII detected: rule='%s', count=%d (below threshold %d -> allowed)\n",
                    rule.name.c_str(), count, rule.threshold);
            }
        }
        catch (const std::regex_error& e)
        {
            printf("[ERROR] Regex error (rule=%s): %s\n", rule.name.c_str(), e.what());
        }
    }

    return result;
}

// =============================================
//  SQLite database storage
// =============================================
#ifdef USE_SQLITE
static sqlite3* g_db = NULL;

static void initDatabase()
{
    ensureDirectoryExists(g_logBasePath);

    int rc = sqlite3_open(g_dbPath.c_str(), &g_db);
    if (rc != SQLITE_OK)
    {
        printf("[DB] SQLite open failed: %s\n", sqlite3_errmsg(g_db));
        g_db = NULL;
        return;
    }

    const char* sqlCreateMails =
        "CREATE TABLE IF NOT EXISTS mail_logs ("
        "  id TEXT PRIMARY KEY,"
        "  subject TEXT,"
        "  mail_from TEXT,"
        "  mail_to TEXT,"
        "  cc TEXT,"
        "  bcc TEXT,"
        "  smtp_mail_from TEXT,"
        "  date_header TEXT,"
        "  send_timestamp TEXT,"
        "  message_id TEXT,"
        "  body_plain TEXT,"
        "  body_html TEXT,"
        "  reply_to TEXT,"
        "  x_mailer TEXT,"
        "  importance TEXT,"
        "  raw_data_size INTEGER,"
        "  attachment_count INTEGER,"
        "  blocked INTEGER DEFAULT 0,"
        "  block_reason TEXT,"
        "  source_ip TEXT,"
        "  dest_ip TEXT,"
        "  process_name TEXT,"
        "  process_id INTEGER,"
        "  json_file_path TEXT,"
        "  created_at TEXT DEFAULT (datetime('now','localtime'))"
        ");";

    const char* sqlCreateAttachments =
        "CREATE TABLE IF NOT EXISTS mail_attachments ("
        "  id TEXT PRIMARY KEY,"
        "  mail_id TEXT NOT NULL,"
        "  filename TEXT,"
        "  content_type TEXT,"
        "  file_size INTEGER,"
        "  saved_path TEXT,"
        "  content_encoding TEXT,"
        "  created_at TEXT DEFAULT (datetime('now','localtime')),"
        "  FOREIGN KEY (mail_id) REFERENCES mail_logs(id)"
        ");";

    char* errMsg = NULL;
    sqlite3_exec(g_db, sqlCreateMails, NULL, NULL, &errMsg);
    if (errMsg) { printf("[DB] Table creation error: %s\n", errMsg); sqlite3_free(errMsg); }

    sqlite3_exec(g_db, sqlCreateAttachments, NULL, NULL, &errMsg);
    if (errMsg) { printf("[DB] Table creation error: %s\n", errMsg); sqlite3_free(errMsg); }

    printf("[DB] SQLite database initialized: %s\n", g_dbPath.c_str());
}

static void insertMailLog(const std::string& mailId, const ParsedEmail& email,
    const std::string& timestamp, bool blocked, const std::string& blockReason,
    const std::string& sourceIp, const std::string& destIp,
    const std::string& processName, DWORD processId,
    const std::string& jsonFilePath)
{
    if (!g_db) return;

    const char* sql =
        "INSERT INTO mail_logs (id, subject, mail_from, mail_to, cc, bcc, "
        "smtp_mail_from, date_header, send_timestamp, message_id, "
        "body_plain, body_html, reply_to, x_mailer, importance, "
        "raw_data_size, attachment_count, blocked, block_reason, "
        "source_ip, dest_ip, process_name, process_id, json_file_path) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK)
    {
        printf("[DB] INSERT prepare failed: %s\n", sqlite3_errmsg(g_db));
        return;
    }

    int idx = 1;
    sqlite3_bind_text(stmt, idx++, mailId.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, idx++, email.subject.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, idx++, email.from.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, idx++, email.to.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, idx++, email.cc.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, idx++, email.bcc.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, idx++, email.smtpMailFrom.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, idx++, email.date.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, idx++, timestamp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, idx++, email.messageId.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, idx++, email.bodyPlainText.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, idx++, email.bodyHtml.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, idx++, email.replyTo.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, idx++, email.xMailer.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, idx++, email.importance.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, idx++, (__int64)email.rawDataSize);
    sqlite3_bind_int(stmt, idx++, (int)email.attachments.size());
    sqlite3_bind_int(stmt, idx++, blocked ? 1 : 0);
    sqlite3_bind_text(stmt, idx++, blockReason.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, idx++, sourceIp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, idx++, destIp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, idx++, processName.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, idx++, (int)processId);
    sqlite3_bind_text(stmt, idx++, jsonFilePath.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE)
        printf("[DB] INSERT mail_logs failed: %s\n", sqlite3_errmsg(g_db));

    sqlite3_finalize(stmt);
}

static void insertAttachmentLog(const std::string& attId, const std::string& mailId,
    const AttachmentInfo& att, const std::string& savedPath)
{
    if (!g_db) return;

    const char* sql =
        "INSERT INTO mail_attachments (id, mail_id, filename, content_type, "
        "file_size, saved_path, content_encoding) VALUES (?,?,?,?,?,?,?);";

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(g_db, sql, -1, &stmt, NULL) != SQLITE_OK) return;

    int idx = 1;
    sqlite3_bind_text(stmt, idx++, attId.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, idx++, mailId.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, idx++, att.filename.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, idx++, att.contentType.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, idx++, (__int64)att.data.size());
    sqlite3_bind_text(stmt, idx++, savedPath.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, idx++, att.contentEncoding.c_str(), -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_DONE)
        printf("[DB] INSERT mail_attachments failed: %s\n", sqlite3_errmsg(g_db));

    sqlite3_finalize(stmt);
}

static void closeDatabase()
{
    if (g_db)
    {
        sqlite3_close(g_db);
        g_db = NULL;
    }
}
#else
// Stub functions when SQLite is not used
static void initDatabase() { printf("[DB] SQLite disabled (USE_SQLITE not defined). Skipping DB.\n"); }
static void insertMailLog(const std::string&, const ParsedEmail&,
    const std::string&, bool, const std::string&,
    const std::string&, const std::string&,
    const std::string&, DWORD, const std::string&) {}
static void insertAttachmentLog(const std::string&, const std::string&,
    const AttachmentInfo&, const std::string&) {}
static void closeDatabase() {}
#endif

// =============================================
//  Email logging (JSON + attachment saving)
// =============================================
static void logEmail(const ParsedEmail& email, bool blocked, const PiiCheckResult& piiResult,
    const std::string& sourceIp, const std::string& destIp,
    const std::string& processName, DWORD processId)
{
    // 1. Generate unique mail ID
    std::string mailId = GuidUtil::generateGuid();
    std::string timestamp = getCurrentTimestamp();

    printf("[LOG] Mail logging start: id=%s, subject=%s\n", mailId.c_str(), email.subject.c_str());

    // 2. Create mail storage directory
    std::string mailDir = g_logBasePath + "\\" + mailId;
    ensureDirectoryExists(mailDir);

    // 3. Save attachments + collect metadata
    JsonArray attachmentsJson;

    for (size_t i = 0; i < email.attachments.size(); i++)
    {
        const AttachmentInfo& att = email.attachments[i];
        std::string attId = GuidUtil::generateGuid();

        // Extract file extension
        std::string ext = "";
        size_t dotPos = att.filename.rfind('.');
        if (dotPos != std::string::npos)
            ext = att.filename.substr(dotPos);

        // Attachment save path: mailId/mailId_attId.ext
        std::string savedFileName = mailId + "_" + attId + ext;
        std::string savedFilePath = mailDir + "\\" + savedFileName;

        writeBinaryToFile(savedFilePath, att.data);

        printf("[LOG]   Attachment saved: %s (%zu bytes)\n", savedFileName.c_str(), att.data.size());

        // Attachment metadata JSON
        JsonBuilder attJson;
        attJson.add("id", attId);
        attJson.add("filename", att.filename);
        attJson.add("file_size", (__int64)att.data.size());
        attJson.add("content_type", att.contentType);
        attJson.add("content_encoding", att.contentEncoding);
        attJson.add("content_id", att.contentId);
        attJson.add("saved_filename", savedFileName);
        attJson.add("saved_path", savedFilePath);

        attachmentsJson.push_back(attJson.toValue());

        // SQLite insert
        insertAttachmentLog(attId, mailId, att, savedFilePath);
    }

    // 4. Build recipients JSON
    JsonArray rcptToJson;
    for (size_t i = 0; i < email.smtpRcptTo.size(); i++)
        rcptToJson.push_back(JsonValue(email.smtpRcptTo[i]));

    JsonBuilder recipientsJson;
    recipientsJson.add("to", JsonValue(email.to));
    recipientsJson.add("cc", JsonValue(email.cc));
    recipientsJson.add("bcc", JsonValue(email.bcc));
    recipientsJson.add("smtp_rcpt_to", JsonValue(rcptToJson));

    // 5. Collect extra headers
    JsonBuilder extraHeaders;
    for (std::map<std::string, std::string>::const_iterator it = email.allHeaders.begin();
        it != email.allHeaders.end(); ++it)
    {
        std::string lowerKey = it->first;
        for (size_t i = 0; i < lowerKey.size(); i++)
            lowerKey[i] = (char)tolower((unsigned char)lowerKey[i]);

        // Skip headers already stored as separate fields
        if (lowerKey == "subject" || lowerKey == "from" || lowerKey == "to" ||
            lowerKey == "cc" || lowerKey == "bcc" || lowerKey == "date" ||
            lowerKey == "message-id" || lowerKey == "content-type" ||
            lowerKey == "content-transfer-encoding" || lowerKey == "reply-to" ||
            lowerKey == "x-mailer" || lowerKey == "importance" || lowerKey == "x-priority" ||
            lowerKey == "mime-version")
            continue;

        extraHeaders.add(it->first, it->second);
    }

    // 6. Block info
    JsonBuilder blockInfoJson;
    blockInfoJson.add("blocked", blocked);
    if (blocked)
    {
        blockInfoJson.add("rule_name", piiResult.ruleName);
        blockInfoJson.add("match_count", piiResult.matchCount);
        blockInfoJson.add("matched_pattern", piiResult.matchedPattern);
    }

    // 7. Network/process info
    JsonBuilder networkInfo;
    networkInfo.add("source_ip", sourceIp);
    networkInfo.add("destination_ip", destIp);
    networkInfo.add("process_name", processName);
    networkInfo.add("process_id", (int)processId);

    // 8. Build complete JSON
    JsonBuilder root;
    root.add("id", mailId);
    root.add("subject", email.subject);
    root.add("from", email.from);
    root.add("recipients", recipientsJson.toValue());
    root.add("date", email.date);
    root.add("send_timestamp", timestamp);
    root.add("message_id", email.messageId);
    root.add("mime_version", email.mimeVersion);
    root.add("content_type", email.contentType);
    root.add("reply_to", email.replyTo);
    root.add("x_mailer", email.xMailer);
    root.add("importance", email.importance);
    root.add("smtp_envelope_from", email.smtpMailFrom);
    root.add("body_plain_text", email.bodyPlainText);
    root.add("body_html", email.bodyHtml);
    root.add("raw_data_size", (__int64)email.rawDataSize);
    root.add("attachment_count", (int)email.attachments.size());
    root.add("attachments", JsonValue(attachmentsJson));
    root.add("extra_headers", extraHeaders.toValue());
    root.add("block_info", blockInfoJson.toValue());
    root.add("network_info", networkInfo.toValue());

    // 9. Save JSON file
    std::string jsonFileName = mailId + "_mailbody.json";
    std::string jsonFilePath = mailDir + "\\" + jsonFileName;
    std::string jsonContent = root.serialize(0);

    if (writeStringToFile(jsonFilePath, jsonContent))
    {
        printf("[LOG] JSON saved: %s\n", jsonFilePath.c_str());
    }
    else
    {
        printf("[ERROR] JSON save failed: %s\n", jsonFilePath.c_str());
    }

    // 10. SQLite insert
    std::string blockReasonStr;
    if (blocked)
        blockReasonStr = piiResult.ruleName + " (" + intToStr(piiResult.matchCount) + " matches)";

    insertMailLog(mailId, email, timestamp, blocked, blockReasonStr,
        sourceIp, destIp, processName, processId, jsonFilePath);
}

// =============================================
//  Connection context management
// =============================================
struct ConnectionContext
{
    SmtpParser parser;
    std::string localAddr;
    std::string remoteAddr;
    std::string processName;
    DWORD       processId;
    bool        isSmtp;

    ConnectionContext() : processId(0), isSmtp(false) {}
};

static std::map<ENDPOINT_ID, ConnectionContext> g_connections;

// Convert address to string
static std::string addressToString(const unsigned char* addr)
{
    char buf[MAX_PATH] = "";
    DWORD dwLen = sizeof(buf);
    sockaddr* pAddr = (sockaddr*)addr;
    WSAAddressToString((LPSOCKADDR)pAddr,
        (pAddr->sa_family == AF_INET6) ? sizeof(sockaddr_in6) : sizeof(sockaddr_in),
        NULL, buf, &dwLen);
    return std::string(buf);
}

// Extract port number
static unsigned short getPort(const unsigned char* addr)
{
    sockaddr* pAddr = (sockaddr*)addr;
    if (pAddr->sa_family == AF_INET)
        return ntohs(((sockaddr_in*)pAddr)->sin_port);
    else if (pAddr->sa_family == AF_INET6)
        return ntohs(((sockaddr_in6*)pAddr)->sin6_port);
    return 0;
}

// =============================================
//  NF_EventHandler implementation
// =============================================
class SmtpEventHandler : public NF_EventHandler
{
    virtual void threadStart()
    {
        CoInitialize(NULL);
    }

    virtual void threadEnd()
    {
        CoUninitialize();
    }

    virtual void tcpConnectRequest(ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo)
    {
        unsigned short remotePort = getPort(pConnInfo->remoteAddress);

        // Filter only SMTP ports (25, 587, 465)
        if (remotePort == 25 || remotePort == 587 || remotePort == 465)
        {
            pConnInfo->filteringFlag |= NF_FILTER;
            printf("[SMTP] Connect request: id=%I64u, port=%d\n", id, remotePort);
        }
    }

    virtual void tcpConnected(ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo)
    {
        unsigned short remotePort = getPort(pConnInfo->remoteAddress);

        if (remotePort == 25 || remotePort == 587 || remotePort == 465)
        {
            ConnectionContext ctx;
            ctx.isSmtp = true;
            ctx.localAddr = addressToString(pConnInfo->localAddress);
            ctx.remoteAddr = addressToString(pConnInfo->remoteAddress);
            ctx.processId = pConnInfo->processId;

            char procName[MAX_PATH] = "";
            if (nf_getProcessName(pConnInfo->processId, procName, sizeof(procName) / sizeof(procName[0])))
                ctx.processName = procName;

            g_connections[id] = ctx;

            printf("[SMTP] Connected: id=%I64u, local=%s, remote=%s, process=%s\n",
                id, ctx.localAddr.c_str(), ctx.remoteAddr.c_str(), ctx.processName.c_str());
        }
    }

    virtual void tcpClosed(ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo)
    {
        std::map<ENDPOINT_ID, ConnectionContext>::iterator it = g_connections.find(id);
        if (it != g_connections.end())
        {
            printf("[SMTP] Closed: id=%I64u\n", id);
            g_connections.erase(it);
        }
    }

    virtual void tcpReceive(ENDPOINT_ID id, const char* buf, int len)
    {
        // Pass SMTP server responses through
        nf_tcpPostReceive(id, buf, len);
    }

    virtual void tcpSend(ENDPOINT_ID id, const char* buf, int len)
    {
        std::map<ENDPOINT_ID, ConnectionContext>::iterator it = g_connections.find(id);

        if (it == g_connections.end() || !it->second.isSmtp)
        {
            // Not an SMTP connection, pass through
            nf_tcpPostSend(id, buf, len);
            return;
        }

        ConnectionContext& ctx = it->second;

        // Feed SMTP data to parser
        std::vector<ParsedEmail> emails = ctx.parser.feedData(buf, len);

        for (size_t i = 0; i < emails.size(); i++)
        {
            ParsedEmail& email = emails[i];

            printf("\n========================================\n");
            printf("[SMTP] Outgoing mail detected!\n");
            printf("  Subject: %s\n", email.subject.c_str());
            printf("  From: %s\n", email.from.c_str());
            printf("  To: %s\n", email.to.c_str());
            printf("  Attachments: %d\n", (int)email.attachments.size());
            printf("========================================\n");

            // PII check (scan both plain text and HTML body)
            std::string combinedContent = email.bodyPlainText + " " + email.bodyHtml;
            combinedContent += " " + email.subject;

            PiiCheckResult piiResult = checkPiiInContent(combinedContent);

            if (piiResult.shouldBlock)
            {
                printf("\n*** [BLOCKED] Mail blocked due to PII detection! ***\n");
                printf("  Rule: %s\n", piiResult.ruleName.c_str());
                printf("  Match count: %d\n", piiResult.matchCount);
                printf("  Blocked subject: %s\n\n", email.subject.c_str());

                // Log blocked mail (blocked=true)
                logEmail(email, true, piiResult,
                    ctx.localAddr, ctx.remoteAddr,
                    ctx.processName, ctx.processId);

                // Block: close SMTP session
                nf_tcpClose(id);
                return;
            }

            // Log normal mail
            logEmail(email, false, piiResult,
                ctx.localAddr, ctx.remoteAddr,
                ctx.processName, ctx.processId);
        }

        // Forward data to server (if not blocked)
        nf_tcpPostSend(id, buf, len);
    }

    virtual void tcpCanReceive(ENDPOINT_ID id) {}
    virtual void tcpCanSend(ENDPOINT_ID id) {}

    // UDP events (unused)
    virtual void udpCreated(ENDPOINT_ID id, PNF_UDP_CONN_INFO pConnInfo) {}
    virtual void udpConnectRequest(ENDPOINT_ID id, PNF_UDP_CONN_REQUEST pConnReq) {}
    virtual void udpClosed(ENDPOINT_ID id, PNF_UDP_CONN_INFO pConnInfo) {}
    virtual void udpReceive(ENDPOINT_ID id, const unsigned char* remoteAddress, const char* buf, int len, PNF_UDP_OPTIONS options) {}
    virtual void udpSend(ENDPOINT_ID id, const unsigned char* remoteAddress, const char* buf, int len, PNF_UDP_OPTIONS options) {}
    virtual void udpCanReceive(ENDPOINT_ID id) {}
    virtual void udpCanSend(ENDPOINT_ID id) {}
};

// =============================================
//  Usage
// =============================================
void printUsage()
{
    printf("SmtpMailMonitor - NetFilterSDK SMTP Mail Monitor/Blocker\n\n");
    printf("Usage:\n");
    printf("  SmtpMailMonitor.exe [options]\n\n");
    printf("Options:\n");
    printf("  -log <path>      Mail log directory (default: .\\mail_logs)\n");
    printf("  -db <path>       SQLite DB file path (default: .\\mail_logs\\mail_log.db)\n");
    printf("  -policy <path>   Block policy file (default: .\\block_policy.json)\n");
    printf("  -h               Show this help\n\n");
    printf("Features:\n");
    printf("  1) Log outgoing mail content as JSON (GUID-based files)\n");
    printf("  2) Extract and save attachments\n");
    printf("  3) SQLite DB logging (when USE_SQLITE defined)\n");
    printf("  4) Block mail containing PII (resident registration numbers)\n");
}

// =============================================
//  main
// =============================================
int main(int argc, char* argv[])
{
    WSADATA wsaData;
    ::WSAStartup(MAKEWORD(2, 2), &wsaData);

#ifdef _DEBUG
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
    _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_DEBUG);
#endif

    // Parse command line arguments
    for (int i = 1; i < argc; i++)
    {
        if (_stricmp(argv[i], "-log") == 0 && i + 1 < argc)
        {
            g_logBasePath = argv[++i];
        }
        else if (_stricmp(argv[i], "-db") == 0 && i + 1 < argc)
        {
            g_dbPath = argv[++i];
        }
        else if (_stricmp(argv[i], "-policy") == 0 && i + 1 < argc)
        {
            g_policyPath = argv[++i];
        }
        else if (_stricmp(argv[i], "-h") == 0 || _stricmp(argv[i], "--help") == 0)
        {
            printUsage();
            return 0;
        }
    }

    printf("========================================\n");
    printf(" SmtpMailMonitor v1.0\n");
    printf(" NetFilterSDK SMTP Mail Monitor/Blocker\n");
    printf("========================================\n\n");

    printf("[Config] Log path:    %s\n", g_logBasePath.c_str());
    printf("[Config] DB path:     %s\n", g_dbPath.c_str());
    printf("[Config] Policy file: %s\n\n", g_policyPath.c_str());

    // Create log directory
    ensureDirectoryExists(g_logBasePath);

    // Load block policy
    loadBlockPolicy(g_policyPath);

    // Initialize SQLite DB
    initDatabase();

    // Initialize COM (for GUID generation)
    CoInitialize(NULL);

    // Initialize NetFilterSDK
    nf_adjustProcessPriviledges();
    nf_setOptions(0, 0);

    SmtpEventHandler eventHandler;

    if (nf_init(NFDRIVER_NAME, &eventHandler) != NF_STATUS_SUCCESS)
    {
        printf("[ERROR] Failed to connect to NetFilter driver!\n");
        printf("  - Check if driver is installed.\n");
        printf("  - Run as Administrator.\n");
        CoUninitialize();
        ::WSACleanup();
        return -1;
    }

    printf("[OK] NetFilter driver connected\n");

    // Set filtering rules: SMTP outbound traffic only
    NF_RULE rule;

    // Rule 1: SMTP port 25
    memset(&rule, 0, sizeof(rule));
    rule.protocol = IPPROTO_TCP;
    rule.direction = NF_D_OUT;
    rule.remotePort = htons(25);
    rule.filteringFlag = NF_FILTER | NF_INDICATE_CONNECT_REQUESTS;
    nf_addRule(&rule, TRUE);

    // Rule 2: SMTP Submission port 587
    memset(&rule, 0, sizeof(rule));
    rule.protocol = IPPROTO_TCP;
    rule.direction = NF_D_OUT;
    rule.remotePort = htons(587);
    rule.filteringFlag = NF_FILTER | NF_INDICATE_CONNECT_REQUESTS;
    nf_addRule(&rule, TRUE);

    // Rule 3: SMTPS port 465
    memset(&rule, 0, sizeof(rule));
    rule.protocol = IPPROTO_TCP;
    rule.direction = NF_D_OUT;
    rule.remotePort = htons(465);
    rule.filteringFlag = NF_FILTER | NF_INDICATE_CONNECT_REQUESTS;
    nf_addRule(&rule, TRUE);

    // Allow all other traffic (no filtering)
    memset(&rule, 0, sizeof(rule));
    rule.filteringFlag = NF_ALLOW;
    nf_addRule(&rule, FALSE);

    printf("[OK] SMTP port filtering rules set (25, 587, 465)\n");
    printf("\n");
    printf("[NOTE] The sockfilter driver does NOT intercept loopback (127.0.0.1) traffic.\n");
    printf("       When testing with SmtpTestSender, use your machine's real IP address,\n");
    printf("       NOT 127.0.0.1 or localhost. The SMTP server must listen on 0.0.0.0.\n");
    printf("\nMonitoring started. Press Enter to stop...\n\n");

    // Wait
    getchar();

    // Cleanup
    printf("\n[Exit] Stopping monitor...\n");

    nf_free();
    closeDatabase();
    CoUninitialize();
    ::WSACleanup();

    printf("[Exit] Done.\n");
    return 0;
}
