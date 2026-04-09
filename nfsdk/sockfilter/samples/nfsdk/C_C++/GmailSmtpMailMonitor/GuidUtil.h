#pragma once
/*
 * GuidUtil.h
 * Windows GUID generation utility
 */

#pragma comment(lib, "ole32.lib")

class GuidUtil
{
public:
    // Generate GUID string (e.g. "3F2504E0-4F89-11D3-9A0C-0305E82C3301")
    static std::string generateGuid()
    {
        GUID guid;
        CoCreateGuid(&guid);
        return guidToString(guid);
    }

    static std::string guidToString(const GUID& guid)
    {
        char buf[64];
        _snprintf(buf, sizeof(buf),
            "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            guid.Data1, guid.Data2, guid.Data3,
            guid.Data4[0], guid.Data4[1],
            guid.Data4[2], guid.Data4[3],
            guid.Data4[4], guid.Data4[5],
            guid.Data4[6], guid.Data4[7]);
        return std::string(buf);
    }
};
