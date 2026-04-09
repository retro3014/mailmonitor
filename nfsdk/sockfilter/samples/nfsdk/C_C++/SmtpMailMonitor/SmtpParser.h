#pragma once
/*
 * SmtpParser.h
 * SMTP protocol parser and MIME message decoder
 *
 * Parses email headers, body, and attachments from SMTP DATA section.
 * Supports RFC 5321 (SMTP), RFC 2045-2049 (MIME), RFC 2047 (Encoded Words)
 */

#include "Base64Decoder.h"

// Attachment info structure
struct AttachmentInfo
{
    std::string filename;
    std::string contentType;
    std::string contentEncoding;
    std::string contentId;
    std::vector<unsigned char> data;
    size_t originalSize;

    AttachmentInfo() : originalSize(0) {}
};

// Parsed email structure
struct ParsedEmail
{
    // SMTP envelope
    std::string smtpMailFrom;
    std::vector<std::string> smtpRcptTo;

    // Email headers
    std::string subject;
    std::string from;
    std::string to;
    std::string cc;
    std::string bcc;
    std::string date;
    std::string messageId;
    std::string mimeVersion;
    std::string contentType;
    std::string contentTransferEncoding;
    std::string replyTo;
    std::string xMailer;
    std::string importance;

    // Body
    std::string bodyPlainText;
    std::string bodyHtml;

    // Attachments
    std::vector<AttachmentInfo> attachments;

    // All headers map (for extra info)
    std::map<std::string, std::string> allHeaders;

    // Raw data size
    size_t rawDataSize;

    ParsedEmail() : rawDataSize(0) {}
};

// SMTP session state
enum SmtpState
{
    SMTP_INIT,
    SMTP_EHLO,
    SMTP_MAIL_FROM,
    SMTP_RCPT_TO,
    SMTP_DATA,
    SMTP_DATA_CONTENT,
    SMTP_QUIT
};

class SmtpParser
{
public:
    SmtpParser() : m_state(SMTP_INIT) {}

    // Feed one SMTP line. Returns true when a complete email is parsed.
    bool feedLine(const std::string& line, ParsedEmail& parsedEmail)
    {
        // Collecting DATA content
        if (m_state == SMTP_DATA_CONTENT)
        {
            // End marker: standalone "." line
            if (line == "." || line == ".\r" || line == ".\r\n")
            {
                parsedEmail = parseEmailContent(m_dataBuffer);
                parsedEmail.smtpMailFrom = m_mailFrom;
                parsedEmail.smtpRcptTo = m_rcptTo;
                parsedEmail.rawDataSize = m_dataBuffer.size();

                m_state = SMTP_INIT;
                m_dataBuffer.clear();
                m_mailFrom.clear();
                m_rcptTo.clear();
                return true;
            }

            // Accumulate data (byte-stuffing: remove leading ".")
            if (line.size() > 0 && line[0] == '.')
                m_dataBuffer += line.substr(1);
            else
                m_dataBuffer += line;
            m_dataBuffer += "\r\n";
            return false;
        }

        // Parse SMTP commands
        std::string upperLine = toUpper(line);

        if (upperLine.find("EHLO ") == 0 || upperLine.find("HELO ") == 0)
        {
            m_state = SMTP_EHLO;
        }
        else if (upperLine.find("MAIL FROM:") == 0)
        {
            m_mailFrom = extractAngleBracket(line.substr(10));
            m_state = SMTP_MAIL_FROM;
        }
        else if (upperLine.find("RCPT TO:") == 0)
        {
            m_rcptTo.push_back(extractAngleBracket(line.substr(8)));
            m_state = SMTP_RCPT_TO;
        }
        else if (upperLine.find("DATA") == 0 && (upperLine.size() == 4 || upperLine[4] == '\r' || upperLine[4] == '\n'))
        {
            m_state = SMTP_DATA_CONTENT;
            m_dataBuffer.clear();
        }
        else if (upperLine.find("RSET") == 0)
        {
            m_state = SMTP_INIT;
            m_dataBuffer.clear();
            m_mailFrom.clear();
            m_rcptTo.clear();
        }
        else if (upperLine.find("QUIT") == 0)
        {
            m_state = SMTP_QUIT;
        }

        return false;
    }

    bool isCollectingData() const { return m_state == SMTP_DATA_CONTENT; }
    SmtpState getState() const { return m_state; }

    // Feed raw TCP data, split into lines, return completed emails
    std::vector<ParsedEmail> feedData(const char* buf, int len)
    {
        std::vector<ParsedEmail> results;
        m_lineBuffer.append(buf, len);

        while (true)
        {
            size_t pos = m_lineBuffer.find('\n');
            if (pos == std::string::npos)
                break;

            std::string line = m_lineBuffer.substr(0, pos);
            m_lineBuffer = m_lineBuffer.substr(pos + 1);

            // Remove trailing \r
            if (!line.empty() && line[line.size() - 1] == '\r')
                line.erase(line.size() - 1);

            ParsedEmail email;
            if (feedLine(line, email))
            {
                results.push_back(email);
            }
        }

        return results;
    }

    void reset()
    {
        m_state = SMTP_INIT;
        m_dataBuffer.clear();
        m_lineBuffer.clear();
        m_mailFrom.clear();
        m_rcptTo.clear();
    }

private:
    SmtpState m_state;
    std::string m_dataBuffer;
    std::string m_lineBuffer;
    std::string m_mailFrom;
    std::vector<std::string> m_rcptTo;

    // ---- Email content parsing (headers + MIME body/attachments) ----

    ParsedEmail parseEmailContent(const std::string& rawData)
    {
        ParsedEmail email;

        // Separate headers and body (blank line separator)
        size_t headerEnd = rawData.find("\r\n\r\n");
        std::string headerSection, bodySection;

        if (headerEnd != std::string::npos)
        {
            headerSection = rawData.substr(0, headerEnd);
            bodySection = rawData.substr(headerEnd + 4);
        }
        else
        {
            headerEnd = rawData.find("\n\n");
            if (headerEnd != std::string::npos)
            {
                headerSection = rawData.substr(0, headerEnd);
                bodySection = rawData.substr(headerEnd + 2);
            }
            else
            {
                headerSection = rawData;
            }
        }

        // Parse headers (with folded header support)
        parseHeaders(headerSection, email);

        // Analyze Content-Type
        std::string ct = toLower(email.contentType);
        std::string boundary = extractBoundary(email.contentType);

        if (!boundary.empty())
        {
            // MIME multipart message
            parseMimeParts(bodySection, boundary, email);
        }
        else if (ct.find("text/html") != std::string::npos)
        {
            email.bodyHtml = decodeBody(bodySection, email.contentTransferEncoding);
        }
        else
        {
            // text/plain or other
            email.bodyPlainText = decodeBody(bodySection, email.contentTransferEncoding);
        }

        return email;
    }

    // Parse email headers (RFC 2822 folding support)
    void parseHeaders(const std::string& headerSection, ParsedEmail& email)
    {
        std::vector<std::string> lines = splitLines(headerSection);
        std::string currentKey, currentValue;

        for (size_t i = 0; i < lines.size(); i++)
        {
            const std::string& line = lines[i];

            // Folded header (starts with space/tab)
            if (!line.empty() && (line[0] == ' ' || line[0] == '\t'))
            {
                if (!currentKey.empty())
                    currentValue += " " + trim(line);
                continue;
            }

            // Store previous header
            if (!currentKey.empty())
            {
                storeHeader(currentKey, currentValue, email);
            }

            // Parse new header
            size_t colonPos = line.find(':');
            if (colonPos != std::string::npos)
            {
                currentKey = trim(line.substr(0, colonPos));
                currentValue = trim(line.substr(colonPos + 1));
            }
            else
            {
                currentKey.clear();
                currentValue.clear();
            }
        }

        // Store last header
        if (!currentKey.empty())
        {
            storeHeader(currentKey, currentValue, email);
        }
    }

    void storeHeader(const std::string& key, const std::string& value, ParsedEmail& email)
    {
        std::string decodedValue = Base64Decoder::decodeRfc2047(value);
        std::string lowerKey = toLower(key);

        email.allHeaders[key] = decodedValue;

        if (lowerKey == "subject")               email.subject = decodedValue;
        else if (lowerKey == "from")             email.from = decodedValue;
        else if (lowerKey == "to")               email.to = decodedValue;
        else if (lowerKey == "cc")               email.cc = decodedValue;
        else if (lowerKey == "bcc")              email.bcc = decodedValue;
        else if (lowerKey == "date")             email.date = decodedValue;
        else if (lowerKey == "message-id")       email.messageId = decodedValue;
        else if (lowerKey == "mime-version")     email.mimeVersion = decodedValue;
        else if (lowerKey == "content-type")     email.contentType = value; // keep original for boundary parsing
        else if (lowerKey == "content-transfer-encoding") email.contentTransferEncoding = decodedValue;
        else if (lowerKey == "reply-to")         email.replyTo = decodedValue;
        else if (lowerKey == "x-mailer")         email.xMailer = decodedValue;
        else if (lowerKey == "importance" || lowerKey == "x-priority") email.importance = decodedValue;
    }

    // MIME multipart parsing
    void parseMimeParts(const std::string& body, const std::string& boundary, ParsedEmail& email)
    {
        std::string delimiter = "--" + boundary;
        std::string endDelimiter = "--" + boundary + "--";

        size_t pos = body.find(delimiter);
        if (pos == std::string::npos) return;

        pos += delimiter.size();
        if (pos < body.size() && body[pos] == '\r') pos++;
        if (pos < body.size() && body[pos] == '\n') pos++;

        while (pos < body.size())
        {
            size_t nextBound = body.find(delimiter, pos);
            if (nextBound == std::string::npos)
                break;

            std::string part = body.substr(pos, nextBound - pos);

            // Remove trailing CRLF
            if (part.size() >= 2 && part.substr(part.size() - 2) == "\r\n")
                part = part.substr(0, part.size() - 2);

            parseSingleMimePart(part, email);

            // Check end delimiter
            size_t afterDelim = nextBound + delimiter.size();
            if (afterDelim + 1 < body.size() && body[afterDelim] == '-' && body[afterDelim + 1] == '-')
                break;

            pos = afterDelim;
            if (pos < body.size() && body[pos] == '\r') pos++;
            if (pos < body.size() && body[pos] == '\n') pos++;
        }
    }

    void parseSingleMimePart(const std::string& part, ParsedEmail& email)
    {
        // Separate headers and body
        size_t sep = part.find("\r\n\r\n");
        std::string partHeaders, partBody;

        if (sep != std::string::npos)
        {
            partHeaders = part.substr(0, sep);
            partBody = part.substr(sep + 4);
        }
        else
        {
            sep = part.find("\n\n");
            if (sep != std::string::npos)
            {
                partHeaders = part.substr(0, sep);
                partBody = part.substr(sep + 2);
            }
            else
            {
                return;
            }
        }

        // Parse part headers
        std::map<std::string, std::string> headers;
        {
            std::vector<std::string> lines = splitLines(partHeaders);
            std::string curKey, curVal;
            for (size_t i = 0; i < lines.size(); i++)
            {
                if (!lines[i].empty() && (lines[i][0] == ' ' || lines[i][0] == '\t'))
                {
                    if (!curKey.empty()) curVal += " " + trim(lines[i]);
                    continue;
                }
                if (!curKey.empty()) headers[toLower(curKey)] = curVal;
                size_t c = lines[i].find(':');
                if (c != std::string::npos)
                {
                    curKey = trim(lines[i].substr(0, c));
                    curVal = trim(lines[i].substr(c + 1));
                }
                else { curKey.clear(); curVal.clear(); }
            }
            if (!curKey.empty()) headers[toLower(curKey)] = curVal;
        }

        std::string ct = headers.count("content-type") ? headers["content-type"] : "";
        std::string cte = headers.count("content-transfer-encoding") ? headers["content-transfer-encoding"] : "";
        std::string cd = headers.count("content-disposition") ? headers["content-disposition"] : "";
        std::string cid = headers.count("content-id") ? headers["content-id"] : "";

        std::string lowerCt = toLower(ct);
        std::string lowerCd = toLower(cd);

        // Handle nested multipart
        std::string nestedBoundary = extractBoundary(ct);
        if (!nestedBoundary.empty())
        {
            parseMimeParts(partBody, nestedBoundary, email);
            return;
        }

        // Determine if attachment
        bool isAttachment = (lowerCd.find("attachment") != std::string::npos);
        std::string filename = extractFilename(cd);
        if (filename.empty()) filename = extractFilename(ct);

        if (isAttachment || !filename.empty())
        {
            // Attachment
            AttachmentInfo att;
            att.filename = Base64Decoder::decodeRfc2047(filename);
            att.contentType = ct;
            att.contentEncoding = cte;
            att.contentId = cid;

            if (toLower(cte).find("base64") != std::string::npos)
            {
                att.data = Base64Decoder::decode(partBody);
            }
            else if (toLower(cte).find("quoted-printable") != std::string::npos)
            {
                std::string decoded = Base64Decoder::decodeQuotedPrintable(partBody);
                att.data.assign(decoded.begin(), decoded.end());
            }
            else
            {
                att.data.assign(partBody.begin(), partBody.end());
            }
            att.originalSize = att.data.size();

            email.attachments.push_back(att);
        }
        else if (lowerCt.find("text/html") != std::string::npos)
        {
            email.bodyHtml = decodeBody(partBody, cte);
        }
        else if (lowerCt.find("text/plain") != std::string::npos || lowerCt.empty())
        {
            email.bodyPlainText = decodeBody(partBody, cte);
        }
        else
        {
            // Other inline content -> treat as attachment
            if (!partBody.empty())
            {
                AttachmentInfo att;
                att.filename = "inline_content";
                att.contentType = ct;
                att.contentEncoding = cte;
                att.contentId = cid;

                if (toLower(cte).find("base64") != std::string::npos)
                    att.data = Base64Decoder::decode(partBody);
                else
                    att.data.assign(partBody.begin(), partBody.end());

                att.originalSize = att.data.size();
                email.attachments.push_back(att);
            }
        }
    }

    // ---- Utility functions ----

    std::string decodeBody(const std::string& body, const std::string& encoding)
    {
        std::string lowerEnc = toLower(encoding);
        if (lowerEnc.find("base64") != std::string::npos)
        {
            std::vector<unsigned char> decoded = Base64Decoder::decode(body);
            return std::string(decoded.begin(), decoded.end());
        }
        else if (lowerEnc.find("quoted-printable") != std::string::npos)
        {
            return Base64Decoder::decodeQuotedPrintable(body);
        }
        return body;
    }

    std::string extractBoundary(const std::string& contentType)
    {
        std::string lower = toLower(contentType);
        size_t pos = lower.find("boundary=");
        if (pos == std::string::npos) return "";

        pos += 9;
        std::string boundary;
        size_t origPos = pos;

        if (origPos < contentType.size() && contentType[origPos] == '"')
        {
            origPos++;
            size_t endQuote = contentType.find('"', origPos);
            if (endQuote != std::string::npos)
                boundary = contentType.substr(origPos, endQuote - origPos);
        }
        else
        {
            size_t endPos = contentType.find_first_of(" \t\r\n;", origPos);
            if (endPos != std::string::npos)
                boundary = contentType.substr(origPos, endPos - origPos);
            else
                boundary = contentType.substr(origPos);
        }
        return trim(boundary);
    }

    std::string extractFilename(const std::string& header)
    {
        std::string lower = toLower(header);
        const char* patterns[] = { "filename=\"", "filename=", "name=\"", "name=", NULL };

        for (int i = 0; patterns[i] != NULL; i++)
        {
            size_t pos = lower.find(patterns[i]);
            if (pos == std::string::npos) continue;

            pos += strlen(patterns[i]);
            bool quoted = (patterns[i][strlen(patterns[i]) - 1] == '"');

            if (quoted)
            {
                size_t endPos = header.find('"', pos);
                if (endPos != std::string::npos)
                    return header.substr(pos, endPos - pos);
            }
            else
            {
                size_t endPos = header.find_first_of(" \t\r\n;", pos);
                if (endPos != std::string::npos)
                    return header.substr(pos, endPos - pos);
                else
                    return header.substr(pos);
            }
        }
        return "";
    }

    std::string extractAngleBracket(const std::string& s)
    {
        size_t start = s.find('<');
        size_t end = s.find('>');
        if (start != std::string::npos && end != std::string::npos && end > start)
            return s.substr(start + 1, end - start - 1);
        return trim(s);
    }

    static std::vector<std::string> splitLines(const std::string& s)
    {
        std::vector<std::string> lines;
        size_t pos = 0;
        while (pos < s.size())
        {
            size_t nl = s.find('\n', pos);
            if (nl == std::string::npos)
            {
                std::string line = s.substr(pos);
                if (!line.empty() && line[line.size() - 1] == '\r')
                    line.erase(line.size() - 1);
                if (!line.empty())
                    lines.push_back(line);
                break;
            }
            std::string line = s.substr(pos, nl - pos);
            if (!line.empty() && line[line.size() - 1] == '\r')
                line.erase(line.size() - 1);
            lines.push_back(line);
            pos = nl + 1;
        }
        return lines;
    }

    static std::string toUpper(const std::string& s)
    {
        std::string r = s;
        for (size_t i = 0; i < r.size(); i++)
            r[i] = (char)toupper((unsigned char)r[i]);
        return r;
    }

    static std::string toLower(const std::string& s)
    {
        std::string r = s;
        for (size_t i = 0; i < r.size(); i++)
            r[i] = (char)tolower((unsigned char)r[i]);
        return r;
    }

    static std::string trim(const std::string& s)
    {
        size_t start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        size_t end = s.find_last_not_of(" \t\r\n");
        return s.substr(start, end - start + 1);
    }
};
