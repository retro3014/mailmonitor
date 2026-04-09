#pragma once
/*
 * Base64Decoder.h
 * Base64 / Quoted-Printable / RFC2047 decoding utility
 */

class Base64Decoder
{
public:
    static std::vector<unsigned char> decode(const std::string& encoded)
    {
        static const std::string base64_chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        std::vector<unsigned char> result;
        int val = 0, valb = -8;

        for (size_t i = 0; i < encoded.size(); i++)
        {
            char c = encoded[i];
            if (c == '\r' || c == '\n' || c == ' ' || c == '\t')
                continue;
            if (c == '=')
                break;

            size_t pos = base64_chars.find(c);
            if (pos == std::string::npos)
                continue;

            val = (val << 6) + (int)pos;
            valb += 6;
            if (valb >= 0)
            {
                result.push_back((unsigned char)((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        return result;
    }

    // Quoted-Printable decoding
    static std::string decodeQuotedPrintable(const std::string& input)
    {
        std::string result;
        for (size_t i = 0; i < input.size(); i++)
        {
            if (input[i] == '=' && i + 2 < input.size())
            {
                if (input[i + 1] == '\r' || input[i + 1] == '\n')
                {
                    // soft line break
                    i++;
                    if (i + 1 < input.size() && input[i] == '\r' && input[i + 1] == '\n')
                        i++;
                    continue;
                }
                char hex[3] = { input[i + 1], input[i + 2], 0 };
                result += (char)strtol(hex, NULL, 16);
                i += 2;
            }
            else
            {
                result += input[i];
            }
        }
        return result;
    }

    // RFC 2047 encoded-word decoding (=?charset?encoding?text?=)
    static std::string decodeRfc2047(const std::string& input)
    {
        std::string result;
        size_t pos = 0;

        while (pos < input.size())
        {
            size_t start = input.find("=?", pos);
            if (start == std::string::npos)
            {
                result += input.substr(pos);
                break;
            }

            result += input.substr(pos, start - pos);

            size_t q1 = input.find('?', start + 2);
            if (q1 == std::string::npos) { result += input.substr(start); break; }

            size_t q2 = input.find('?', q1 + 1);
            if (q2 == std::string::npos) { result += input.substr(start); break; }

            size_t end = input.find("?=", q2 + 1);
            if (end == std::string::npos) { result += input.substr(start); break; }

            char encoding = input[q1 + 1];
            std::string encodedText = input.substr(q2 + 1, end - q2 - 1);

            if (encoding == 'B' || encoding == 'b')
            {
                std::vector<unsigned char> decoded = decode(encodedText);
                result.append(decoded.begin(), decoded.end());
            }
            else if (encoding == 'Q' || encoding == 'q')
            {
                // Q encoding: underscore -> space, =XX -> hex
                std::string qp;
                for (size_t j = 0; j < encodedText.size(); j++)
                {
                    if (encodedText[j] == '_')
                        qp += ' ';
                    else
                        qp += encodedText[j];
                }
                result += decodeQuotedPrintable(qp);
            }

            pos = end + 2;
        }
        return result;
    }
};
