/*
 * HttpParser.h
 * =============
 * Simple HTTP request/response parser for TLS MITM proxy.
 * Parses HTTP stream to extract method, URL, headers, and body.
 *
 * This is NOT a full HTTP/2 parser - it handles HTTP/1.1 which is
 * what we see after TLS decryption (QUIC must be disabled in Chrome).
 */

#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H

#include <string>
#include <map>
#include <vector>

struct HttpMessage
{
    // Request fields
    std::string method;       // "GET", "POST", etc.
    std::string url;          // "/sync/u/0/i/s?..."
    std::string httpVersion;  // "HTTP/1.1"

    // Response fields
    int statusCode;           // 200, 404, etc.
    std::string statusText;   // "OK", "Not Found"

    // Common
    std::map<std::string, std::string> headers;
    std::string body;
    bool isResponse;
    bool isComplete;

    HttpMessage() : statusCode(0), isResponse(false), isComplete(false) {}
};

class HttpStreamParser
{
public:
    HttpStreamParser() : m_state(STATE_HEADER), m_contentLength(0), m_chunked(false) {}

    // Feed raw data from TLS decryption. Returns completed HTTP messages.
    std::vector<HttpMessage> feedData(const char* data, int len)
    {
        std::vector<HttpMessage> results;
        m_buffer.append(data, len);

        while (!m_buffer.empty())
        {
            if (m_state == STATE_HEADER)
            {
                // Look for end of headers (\r\n\r\n)
                size_t headerEnd = m_buffer.find("\r\n\r\n");
                if (headerEnd == std::string::npos)
                    break;  // Need more data

                std::string headerBlock = m_buffer.substr(0, headerEnd);
                m_buffer.erase(0, headerEnd + 4);

                m_current = HttpMessage();
                parseHeaderBlock(headerBlock);

                // Determine body length
                std::string clStr = getHeader("content-length");
                std::string teStr = getHeader("transfer-encoding");

                if (!clStr.empty())
                {
                    m_contentLength = atoi(clStr.c_str());
                    m_chunked = false;
                }
                else if (teStr.find("chunked") != std::string::npos)
                {
                    m_chunked = true;
                    m_contentLength = 0;
                }
                else
                {
                    m_contentLength = 0;
                    m_chunked = false;
                }

                if (m_contentLength > 0 || m_chunked)
                {
                    m_state = STATE_BODY;
                }
                else
                {
                    // No body
                    m_current.isComplete = true;
                    results.push_back(m_current);
                    m_state = STATE_HEADER;
                }
            }
            else if (m_state == STATE_BODY)
            {
                if (m_chunked)
                {
                    // Simple chunked handling: accumulate until we see "0\r\n"
                    size_t endChunk = m_buffer.find("\r\n0\r\n");
                    if (endChunk == std::string::npos)
                        endChunk = m_buffer.find("0\r\n\r\n");

                    if (endChunk != std::string::npos)
                    {
                        // Decode chunked body
                        std::string chunkedData = m_buffer.substr(0, endChunk);
                        m_current.body = decodeChunked(chunkedData);
                        m_current.isComplete = true;
                        results.push_back(m_current);

                        // Find the end of chunked encoding
                        size_t trueEnd = m_buffer.find("\r\n\r\n", endChunk);
                        if (trueEnd != std::string::npos)
                            m_buffer.erase(0, trueEnd + 4);
                        else
                            m_buffer.erase(0, endChunk + 5);

                        m_state = STATE_HEADER;
                    }
                    else
                    {
                        break;  // Need more data
                    }
                }
                else
                {
                    // Content-Length based
                    if ((int)m_buffer.size() >= m_contentLength)
                    {
                        m_current.body = m_buffer.substr(0, m_contentLength);
                        m_buffer.erase(0, m_contentLength);
                        m_current.isComplete = true;
                        results.push_back(m_current);
                        m_state = STATE_HEADER;
                    }
                    else
                    {
                        break;  // Need more data
                    }
                }
            }
        }

        return results;
    }

    void reset()
    {
        m_buffer.clear();
        m_state = STATE_HEADER;
        m_contentLength = 0;
        m_chunked = false;
    }

private:
    enum State { STATE_HEADER, STATE_BODY };

    State m_state;
    std::string m_buffer;
    HttpMessage m_current;
    int m_contentLength;
    bool m_chunked;

    void parseHeaderBlock(const std::string& block)
    {
        // Split into lines
        std::vector<std::string> lines;
        size_t pos = 0;
        while (pos < block.size())
        {
            size_t nl = block.find("\r\n", pos);
            if (nl == std::string::npos)
            {
                lines.push_back(block.substr(pos));
                break;
            }
            lines.push_back(block.substr(pos, nl - pos));
            pos = nl + 2;
        }

        if (lines.empty()) return;

        // First line: request line or status line
        const std::string& firstLine = lines[0];
        if (firstLine.substr(0, 5) == "HTTP/")
        {
            // Response: HTTP/1.1 200 OK
            m_current.isResponse = true;
            size_t sp1 = firstLine.find(' ');
            if (sp1 != std::string::npos)
            {
                m_current.httpVersion = firstLine.substr(0, sp1);
                size_t sp2 = firstLine.find(' ', sp1 + 1);
                if (sp2 != std::string::npos)
                {
                    m_current.statusCode = atoi(firstLine.substr(sp1 + 1, sp2 - sp1 - 1).c_str());
                    m_current.statusText = firstLine.substr(sp2 + 1);
                }
            }
        }
        else
        {
            // Request: POST /sync/u/0/i/s?... HTTP/1.1
            m_current.isResponse = false;
            size_t sp1 = firstLine.find(' ');
            if (sp1 != std::string::npos)
            {
                m_current.method = firstLine.substr(0, sp1);
                size_t sp2 = firstLine.find(' ', sp1 + 1);
                if (sp2 != std::string::npos)
                {
                    m_current.url = firstLine.substr(sp1 + 1, sp2 - sp1 - 1);
                    m_current.httpVersion = firstLine.substr(sp2 + 1);
                }
            }
        }

        // Parse headers
        for (size_t i = 1; i < lines.size(); i++)
        {
            size_t colon = lines[i].find(':');
            if (colon != std::string::npos)
            {
                std::string key = lines[i].substr(0, colon);
                std::string val = lines[i].substr(colon + 1);

                // Trim leading spaces from value
                size_t valStart = val.find_first_not_of(" \t");
                if (valStart != std::string::npos)
                    val = val.substr(valStart);

                // Lowercase key for easy lookup
                std::string lowerKey = key;
                for (size_t j = 0; j < lowerKey.size(); j++)
                    lowerKey[j] = (char)tolower((unsigned char)lowerKey[j]);

                m_current.headers[lowerKey] = val;
            }
        }
    }

    std::string getHeader(const std::string& lowerKey)
    {
        std::map<std::string, std::string>::iterator it = m_current.headers.find(lowerKey);
        if (it != m_current.headers.end())
            return it->second;
        return "";
    }

    std::string decodeChunked(const std::string& data)
    {
        std::string result;
        size_t pos = 0;

        while (pos < data.size())
        {
            // Read chunk size (hex)
            size_t nl = data.find("\r\n", pos);
            if (nl == std::string::npos) break;

            std::string sizeStr = data.substr(pos, nl - pos);
            int chunkSize = (int)strtol(sizeStr.c_str(), NULL, 16);
            if (chunkSize <= 0) break;

            pos = nl + 2;
            if (pos + chunkSize <= data.size())
            {
                result.append(data, pos, chunkSize);
                pos += chunkSize + 2;  // Skip chunk data + \r\n
            }
            else
            {
                break;
            }
        }

        return result;
    }
};

#endif // HTTP_PARSER_H
