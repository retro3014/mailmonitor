#pragma once
/*
 * JsonWriter.h
 * Lightweight JSON builder (no external dependency)
 * Includes special character escaping for JSON
 */

class JsonValue;
typedef std::vector<std::pair<std::string, JsonValue>> JsonObject;
typedef std::vector<JsonValue> JsonArray;

class JsonValue
{
public:
    enum Type { TYPE_NULL, TYPE_STRING, TYPE_INT, TYPE_BOOL, TYPE_OBJECT, TYPE_ARRAY };

    JsonValue() : m_type(TYPE_NULL), m_int(0), m_bool(false) {}
    JsonValue(const std::string& s) : m_type(TYPE_STRING), m_str(s), m_int(0), m_bool(false) {}
    JsonValue(const char* s) : m_type(TYPE_STRING), m_str(s ? s : ""), m_int(0), m_bool(false) {}
    JsonValue(int v) : m_type(TYPE_INT), m_int(v), m_bool(false) {}
    JsonValue(__int64 v) : m_type(TYPE_INT), m_int(v), m_bool(false) {}
    JsonValue(bool v) : m_type(TYPE_BOOL), m_int(0), m_bool(v) {}
    JsonValue(const JsonObject& obj) : m_type(TYPE_OBJECT), m_obj(obj), m_int(0), m_bool(false) {}
    JsonValue(const JsonArray& arr) : m_type(TYPE_ARRAY), m_arr(arr), m_int(0), m_bool(false) {}

    std::string serialize(int indent = 0) const
    {
        switch (m_type)
        {
        case TYPE_NULL:   return "null";
        case TYPE_STRING: return "\"" + escapeJson(m_str) + "\"";
        case TYPE_INT:    { char buf[32]; _snprintf(buf, sizeof(buf), "%I64d", m_int); return buf; }
        case TYPE_BOOL:   return m_bool ? "true" : "false";
        case TYPE_OBJECT: return serializeObject(indent);
        case TYPE_ARRAY:  return serializeArray(indent);
        }
        return "null";
    }

    // JSON special character escaping
    static std::string escapeJson(const std::string& s)
    {
        std::string result;
        result.reserve(s.size() + 16);
        for (size_t i = 0; i < s.size(); i++)
        {
            unsigned char c = (unsigned char)s[i];
            switch (c)
            {
            case '\"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\b': result += "\\b"; break;
            case '\f': result += "\\f"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:
                if (c < 0x20)
                {
                    char hex[8];
                    _snprintf(hex, sizeof(hex), "\\u%04x", c);
                    result += hex;
                }
                else
                {
                    result += (char)c;
                }
                break;
            }
        }
        return result;
    }

private:
    Type m_type;
    std::string m_str;
    __int64 m_int;
    bool m_bool;
    JsonObject m_obj;
    JsonArray m_arr;

    std::string makeIndent(int level) const
    {
        return std::string(level * 2, ' ');
    }

    std::string serializeObject(int indent) const
    {
        if (m_obj.empty()) return "{}";
        std::string s = "{\n";
        for (size_t i = 0; i < m_obj.size(); i++)
        {
            s += makeIndent(indent + 1);
            s += "\"" + escapeJson(m_obj[i].first) + "\": ";
            s += m_obj[i].second.serialize(indent + 1);
            if (i + 1 < m_obj.size()) s += ",";
            s += "\n";
        }
        s += makeIndent(indent) + "}";
        return s;
    }

    std::string serializeArray(int indent) const
    {
        if (m_arr.empty()) return "[]";
        std::string s = "[\n";
        for (size_t i = 0; i < m_arr.size(); i++)
        {
            s += makeIndent(indent + 1);
            s += m_arr[i].serialize(indent + 1);
            if (i + 1 < m_arr.size()) s += ",";
            s += "\n";
        }
        s += makeIndent(indent) + "]";
        return s;
    }
};

// JSON object builder helper
class JsonBuilder
{
public:
    JsonBuilder& add(const std::string& key, const JsonValue& val)
    {
        m_obj.push_back(std::make_pair(key, val));
        return *this;
    }

    JsonObject build() const { return m_obj; }
    JsonValue toValue() const { return JsonValue(m_obj); }

    std::string serialize(int indent = 0) const
    {
        return JsonValue(m_obj).serialize(indent);
    }

private:
    JsonObject m_obj;
};
