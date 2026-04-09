/*
 * GmailWebParser.h
 * =================
 * Extracts email data from Gmail's web API (HTTPS) responses.
 *
 * Gmail's web client sends/receives data via:
 *   POST https://mail.google.com/sync/u/0/i/s?hl=ko&c=...&rt=r&pt=ji
 *
 * The response body contains nested JSON arrays with email data.
 * This parser extracts: sender, recipients, subject, body, attachments.
 *
 * NOTE: Gmail's internal API format is undocumented and may change.
 *       This parser is based on observed patterns from Fiddler captures.
 *
 * Usage with HttpParser:
 *   HttpStreamParser httpParser;
 *   auto messages = httpParser.feedData(decryptedData, len);
 *   for (auto& msg : messages) {
 *       if (GmailWebParser::isGmailSyncResponse(msg)) {
 *           ParsedEmail email;
 *           if (GmailWebParser::extractEmail(msg.body, email)) {
 *               // email now has sender, recipients, subject, body, attachments
 *           }
 *       }
 *   }
 */

#ifndef GMAIL_WEB_PARSER_H
#define GMAIL_WEB_PARSER_H

#include <string>
#include <vector>
#include <algorithm>
#include "HttpParser.h"
#include "SmtpParser.h"  // Reuse ParsedEmail struct

class GmailWebParser
{
public:
    // Check if an HTTP response is likely to contain Gmail email data.
    // This is only used as a secondary check; the primary filter is
    // tracking whether the REQUEST was a Gmail sync request.
    static bool isGmailSyncResponse(const HttpMessage& msg)
    {
        // We never use this for standalone detection anymore.
        // Only responses to tracked sync requests are parsed.
        (void)msg;
        return false;
    }

    // Check if an HTTP request URL matches Gmail mail-send or sync endpoints
    static bool isGmailSyncRequest(const HttpMessage& msg)
    {
        if (msg.isResponse) return false;

        // Must be to mail.google.com
        std::map<std::string, std::string>::const_iterator hostIt;
        hostIt = msg.headers.find("host");
        bool isMailHost = false;
        if (hostIt != msg.headers.end())
        {
            if (hostIt->second.find("mail.google.com") != std::string::npos)
                isMailHost = true;
        }
        if (!isMailHost) return false;

        // Exact Gmail sync endpoint: /sync/u/0/i/s (mail send/receive)
        // From Fiddler capture: POST mail.google.com/sync/u/0/i/s?hl=ko&c=152&rt=r&pt=ji
        if (msg.url.find("/sync/u/") != std::string::npos &&
            msg.url.find("/i/s") != std::string::npos)
        {
            return true;
        }

        // Gmail compose/send via classic UI:
        // POST /mail/u/0/?...&view=sm (send mail)
        // POST /mail/u/0/?...&act=sm  (send mail)
        if (msg.method == "POST" && msg.url.find("/mail/u/") != std::string::npos)
        {
            if (msg.url.find("view=sm") != std::string::npos ||
                msg.url.find("act=sm") != std::string::npos)
            {
                return true;
            }
        }

        return false;
    }

    // Extract email data from Gmail sync response body
    // Returns true if email data was found
    static bool extractEmail(const std::string& body, ParsedEmail& email)
    {
        // Gmail uses nested JSON arrays. We look for patterns like:
        //   [1,"email@gmail.com","Display Name"]  - sender
        //   [[1,"recipient@gmail.com"]]            - recipients
        //   "Subject text"                          - subject
        //   "Body text"                             - body
        //   [["content-type","filename",size,...]]  - attachments

        bool found = false;

        // Try to find sender pattern: [1,"email","name"]
        found |= extractSender(body, email);

        // Try to find recipients
        found |= extractRecipients(body, email);

        // Try to find subject
        found |= extractSubject(body, email);

        // Try to find body text
        found |= extractBody(body, email);

        // Try to find attachments
        extractAttachments(body, email);

        return found;
    }

    // Extract all emails from a response (there may be multiple)
    static std::vector<ParsedEmail> extractAllEmails(const std::string& body)
    {
        std::vector<ParsedEmail> results;

        // Gmail sync responses can contain multiple email entries.
        // Each email block typically starts with a message ID pattern.
        // For simplicity, we extract one email per response for now.
        ParsedEmail email;
        if (extractEmail(body, email))
        {
            results.push_back(email);
        }

        return results;
    }

public:
    // ================================================================
    // JSON-like pattern extractors
    // These work on the raw response text without a full JSON parser.
    // ================================================================

    // Find sender: pattern [1,"email@domain.com","Display Name"]
    static bool extractSender(const std::string& body, ParsedEmail& email)
    {
        // Look for email-like pattern inside the nested arrays
        // Sender typically appears as [1,"user@gmail.com","Name"]

        // Strategy: find all email addresses, the first one that matches
        // a pattern like [1,"email","name"] is likely the sender

        size_t pos = 0;
        while (pos < body.size())
        {
            // Find [1," pattern (sender marker)
            size_t marker = body.find("[1,\"", pos);
            if (marker == std::string::npos) break;

            size_t emailStart = marker + 4;  // after [1,"
            size_t emailEnd = body.find("\"", emailStart);
            if (emailEnd == std::string::npos) break;

            std::string candidate = body.substr(emailStart, emailEnd - emailStart);

            // Check if it looks like an email address
            if (isEmailAddress(candidate))
            {
                email.from = candidate;

                // Try to get display name (next quoted string)
                size_t nameStart = body.find("\"", emailEnd + 1);
                if (nameStart != std::string::npos && nameStart < emailEnd + 5)
                {
                    nameStart++;  // skip opening quote
                    size_t nameEnd = body.find("\"", nameStart);
                    if (nameEnd != std::string::npos)
                    {
                        std::string name = body.substr(nameStart, nameEnd - nameStart);
                        // Decode unicode escapes if present
                        name = decodeUnicodeEscapes(name);
                        if (!name.empty() && name != ",")
                        {
                            email.from = name + " <" + candidate + ">";
                        }
                    }
                }
                return true;
            }

            pos = emailEnd + 1;
        }

        return false;
    }

    // Find recipients: pattern [[1,"recipient@domain.com"]]
    static bool extractRecipients(const std::string& body, ParsedEmail& email)
    {
        // Recipients appear as [[1,"email"]] or [[1,"email"],[1,"email2"]]
        // They are usually the second email-like pattern after the sender

        bool foundSender = false;
        size_t pos = 0;

        while (pos < body.size())
        {
            size_t marker = body.find("[1,\"", pos);
            if (marker == std::string::npos) break;

            size_t emailStart = marker + 4;
            size_t emailEnd = body.find("\"", emailStart);
            if (emailEnd == std::string::npos) break;

            std::string candidate = body.substr(emailStart, emailEnd - emailStart);

            if (isEmailAddress(candidate))
            {
                if (!foundSender)
                {
                    // First email is sender, skip it
                    foundSender = true;
                }
                else
                {
                    // This is a recipient
                    // Avoid duplicating sender as recipient
                    bool isDuplicate = false;
                    for (size_t i = 0; i < email.smtpRcptTo.size(); i++)
                    {
                        if (email.smtpRcptTo[i].find(candidate) != std::string::npos)
                        {
                            isDuplicate = true;
                            break;
                        }
                    }
                    if (!isDuplicate)
                    {
                        email.smtpRcptTo.push_back(candidate);
                    }
                }
            }

            pos = emailEnd + 1;
        }

        return !email.smtpRcptTo.empty();
    }

    // Find subject: typically a quoted string near specific markers
    static bool extractSubject(const std::string& body, ParsedEmail& email)
    {
        // The subject appears as a standalone quoted string in the response.
        // Strategy: look for strings that appear between email-related markers.
        // In the observed format, subject comes after recipient data.

        // Alternative approach: look for Korean/meaningful text strings
        // that are not email addresses and not URLs

        // From observed data, subject and body appear as separate quoted strings
        // in a specific position within the nested arrays.
        // We use a heuristic: find quoted strings that look like user content.

        std::vector<std::string> candidateStrings;
        extractQuotedStrings(body, candidateStrings);

        // Filter: remove email addresses, URLs, content-types, and known markers
        std::vector<std::string> userStrings;
        for (size_t i = 0; i < candidateStrings.size(); i++)
        {
            const std::string& s = candidateStrings[i];
            if (s.empty()) continue;
            if (isEmailAddress(s)) continue;
            if (s.find("http") == 0) continue;
            if (s.find("mail.google.com") != std::string::npos) continue;
            if (s.find("application/") == 0) continue;
            if (s.find("text/") == 0) continue;
            if (s.find("multipart/") == 0) continue;
            if (s.find("image/") == 0) continue;
            if (s.find("Content-") == 0) continue;
            if (s.find("boundary=") != std::string::npos) continue;
            if (s == "r" || s == "s" || s == "ji") continue;
            if (s.size() <= 1) continue;

            // Decode unicode escapes
            std::string decoded = decodeUnicodeEscapes(s);
            userStrings.push_back(decoded);
        }

        // Heuristic: first user-meaningful string is subject,
        // second is body (if they are different)
        if (userStrings.size() >= 1)
        {
            email.subject = userStrings[0];
            return true;
        }

        return false;
    }

    // Find body text
    static bool extractBody(const std::string& body, ParsedEmail& email)
    {
        std::vector<std::string> candidateStrings;
        extractQuotedStrings(body, candidateStrings);

        std::vector<std::string> userStrings;
        for (size_t i = 0; i < candidateStrings.size(); i++)
        {
            const std::string& s = candidateStrings[i];
            if (s.empty()) continue;
            if (isEmailAddress(s)) continue;
            if (s.find("http") == 0) continue;
            if (s.find("mail.google.com") != std::string::npos) continue;
            if (s.find("application/") == 0) continue;
            if (s.find("text/") == 0) continue;
            if (s.find("multipart/") == 0) continue;
            if (s.find("image/") == 0) continue;
            if (s.find("Content-") == 0) continue;
            if (s.find("boundary=") != std::string::npos) continue;
            if (s == "r" || s == "s" || s == "ji") continue;
            if (s.size() <= 1) continue;

            std::string decoded = decodeUnicodeEscapes(s);
            userStrings.push_back(decoded);
        }

        // Second user string is typically the body
        if (userStrings.size() >= 2)
        {
            email.bodyPlainText = userStrings[1];
            return true;
        }
        else if (userStrings.size() == 1)
        {
            // If only one string found, it might be both subject and body
            email.bodyPlainText = userStrings[0];
            return true;
        }

        return false;
    }

    // Find attachments: pattern [["content-type","filename",size,...]]
    static bool extractAttachments(const std::string& body, ParsedEmail& email)
    {
        // Attachments appear as ["content-type","filename",size,...]
        // Look for patterns with content-type followed by filename

        size_t pos = 0;
        bool found = false;

        while (pos < body.size())
        {
            // Look for content-type patterns in arrays
            size_t ctPos = findContentTypeInArray(body, pos);
            if (ctPos == std::string::npos) break;

            // Extract content-type
            size_t ctEnd = body.find("\"", ctPos);
            if (ctEnd == std::string::npos) break;

            std::string contentType = body.substr(pos, ctEnd - ctPos);

            // Next quoted string should be filename
            size_t fnStart = body.find("\"", ctEnd + 1);
            if (fnStart != std::string::npos && fnStart < ctEnd + 5)
            {
                fnStart++;
                size_t fnEnd = body.find("\"", fnStart);
                if (fnEnd != std::string::npos)
                {
                    std::string filename = body.substr(fnStart, fnEnd - fnStart);
                    filename = decodeUnicodeEscapes(filename);

                    // Check if it looks like a filename (has extension)
                    if (filename.find('.') != std::string::npos &&
                        !isEmailAddress(filename) &&
                        filename.find('/') == std::string::npos)
                    {
                        AttachmentInfo att;
                        att.filename = filename;
                        att.contentType = contentType;
                        email.attachments.push_back(att);
                        found = true;
                    }
                }
                pos = fnEnd != std::string::npos ? fnEnd + 1 : ctEnd + 1;
            }
            else
            {
                pos = ctEnd + 1;
            }
        }

        return found;
    }

    // ================================================================
    // Utility functions
    // ================================================================

    static bool isEmailAddress(const std::string& s)
    {
        size_t at = s.find('@');
        if (at == std::string::npos || at == 0 || at == s.size() - 1)
            return false;
        size_t dot = s.find('.', at);
        return (dot != std::string::npos && dot > at + 1 && dot < s.size() - 1);
    }

    // Extract all double-quoted strings from text
    static void extractQuotedStrings(const std::string& text,
                                      std::vector<std::string>& results)
    {
        size_t pos = 0;
        while (pos < text.size())
        {
            size_t qStart = text.find('"', pos);
            if (qStart == std::string::npos) break;

            // Handle escaped quotes
            std::string value;
            size_t i = qStart + 1;
            while (i < text.size())
            {
                if (text[i] == '\\' && i + 1 < text.size())
                {
                    if (text[i + 1] == '"')
                    {
                        value += '"';
                        i += 2;
                    }
                    else if (text[i + 1] == '\\')
                    {
                        value += '\\';
                        i += 2;
                    }
                    else if (text[i + 1] == 'n')
                    {
                        value += '\n';
                        i += 2;
                    }
                    else if (text[i + 1] == 'r')
                    {
                        value += '\r';
                        i += 2;
                    }
                    else if (text[i + 1] == 't')
                    {
                        value += '\t';
                        i += 2;
                    }
                    else if (text[i + 1] == 'u')
                    {
                        // Unicode escape \uXXXX
                        if (i + 5 < text.size())
                        {
                            value += text.substr(i, 6);
                            i += 6;
                        }
                        else
                        {
                            value += text[i];
                            i++;
                        }
                    }
                    else
                    {
                        value += text[i];
                        value += text[i + 1];
                        i += 2;
                    }
                }
                else if (text[i] == '"')
                {
                    break;
                }
                else
                {
                    value += text[i];
                    i++;
                }
            }

            if (i < text.size() && text[i] == '"')
            {
                results.push_back(value);
                pos = i + 1;
            }
            else
            {
                pos = qStart + 1;
            }
        }
    }

    // Decode \uXXXX unicode escapes to UTF-8
    static std::string decodeUnicodeEscapes(const std::string& input)
    {
        std::string result;
        size_t i = 0;

        while (i < input.size())
        {
            if (input[i] == '\\' && i + 5 < input.size() && input[i + 1] == 'u')
            {
                // Parse \uXXXX
                std::string hex = input.substr(i + 2, 4);
                unsigned int codepoint = (unsigned int)strtol(hex.c_str(), NULL, 16);

                // Convert to UTF-8
                if (codepoint <= 0x7F)
                {
                    result += (char)codepoint;
                }
                else if (codepoint <= 0x7FF)
                {
                    result += (char)(0xC0 | (codepoint >> 6));
                    result += (char)(0x80 | (codepoint & 0x3F));
                }
                else
                {
                    result += (char)(0xE0 | (codepoint >> 12));
                    result += (char)(0x80 | ((codepoint >> 6) & 0x3F));
                    result += (char)(0x80 | (codepoint & 0x3F));
                }
                i += 6;
            }
            else
            {
                result += input[i];
                i++;
            }
        }

        return result;
    }

    // Find content-type string inside an array context
    static size_t findContentTypeInArray(const std::string& body, size_t startPos)
    {
        // Look for quoted strings that look like MIME content types
        // e.g., "text/plain", "application/pdf", "image/png"
        const char* mimeTypes[] = {
            "\"text/", "\"application/", "\"image/", "\"audio/", "\"video/",
            NULL
        };

        size_t earliest = std::string::npos;
        for (int i = 0; mimeTypes[i] != NULL; i++)
        {
            size_t found = body.find(mimeTypes[i], startPos);
            if (found != std::string::npos)
            {
                // Check if it's inside an array context (preceded by [ or ,)
                if (found > 0)
                {
                    char prev = body[found - 1];
                    if (prev == '[' || prev == ',')
                    {
                        found++;  // skip the opening quote
                        if (found < earliest)
                            earliest = found;
                    }
                }
            }
        }

        return earliest;
    }
};

#endif // GMAIL_WEB_PARSER_H
