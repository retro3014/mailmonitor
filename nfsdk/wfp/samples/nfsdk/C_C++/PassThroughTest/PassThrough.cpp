#include "stdafx.h"
#include <crtdbg.h>
#include <string>
#include <vector>
#include <algorithm>
#include "nfapi.h"
#include "samples_config.h"  // NFDRIVER_NAME = "netfilter2"

using namespace nfapi;

// 차단할 키워드 목록
std::vector<std::string> g_blockKeywords;

// 버퍼 내에 키워드가 존재하는지 검사
bool containsKeyword(const char* buf, int len)
{
    // 바이너리 안전한 검색을 위해 std::string으로 감쌈
    std::string data(buf, len);

    // 대소문자 무시 검색을 위해 소문자 변환 복사본 생성
    std::string dataLower = data;
    std::transform(dataLower.begin(), dataLower.end(),
        dataLower.begin(), ::tolower);

    for (const auto& keyword : g_blockKeywords)
    {
        std::string keyLower = keyword;
        std::transform(keyLower.begin(), keyLower.end(),
            keyLower.begin(), ::tolower);

        if (dataLower.find(keyLower) != std::string::npos)
        {
            printf("[BLOCKED] Keyword found: \"%s\"\n", keyword.c_str());
            return true;
        }
    }
    return false;
}

class EventHandler : public NF_EventHandler
{
    virtual void threadStart() {}
    virtual void threadEnd() {}

    virtual void tcpConnectRequest(ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo)
    {
        // 연결 요청은 그대로 허용 (데이터 레벨에서 차단)
    }

    virtual void tcpConnected(ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo)
    {
        char processName[MAX_PATH] = "";
        nf_getProcessNameA(pConnInfo->processId, processName, MAX_PATH);
        printf("[TCP Connected] id=%I64u pid=%d process=%s\n",
            id, pConnInfo->processId, processName);
    }

    virtual void tcpClosed(ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo)
    {
        printf("[TCP Closed] id=%I64u\n", id);
    }

    // ★ 핵심: 서버 → 클라이언트 수신 데이터 검사
    virtual void tcpReceive(ENDPOINT_ID id, const char* buf, int len)
    {
        if (containsKeyword(buf, len))
        {
            printf("[TCP Receive BLOCKED] id=%I64u len=%d\n", id, len);
            // 방법 A: 해당 패킷만 드롭 (nf_tcpPostReceive 호출 안 함)
            // 방법 B: 연결 자체를 끊기
            nf_tcpClose(id);
            return;
        }

        // 키워드 없으면 정상 통과
        nf_tcpPostReceive(id, buf, len);
    }

    // ★ 핵심: 클라이언트 → 서버 송신 데이터 검사
    virtual void tcpSend(ENDPOINT_ID id, const char* buf, int len)
    {
        if (containsKeyword(buf, len))
        {
            printf("[TCP Send BLOCKED] id=%I64u len=%d\n", id, len);
            nf_tcpClose(id);
            return;
        }

        nf_tcpPostSend(id, buf, len);
    }

    virtual void tcpCanReceive(ENDPOINT_ID id) {}
    virtual void tcpCanSend(ENDPOINT_ID id) {}

    // UDP도 동일한 패턴
    virtual void udpCreated(ENDPOINT_ID id, PNF_UDP_CONN_INFO pConnInfo) {}
    virtual void udpConnectRequest(ENDPOINT_ID id, PNF_UDP_CONN_REQUEST pConnReq) {}
    virtual void udpClosed(ENDPOINT_ID id, PNF_UDP_CONN_INFO pConnInfo) {}

    virtual void udpReceive(ENDPOINT_ID id, const unsigned char* remoteAddress,
        const char* buf, int len, PNF_UDP_OPTIONS options)
    {
        if (containsKeyword(buf, len))
        {
            printf("[UDP Receive BLOCKED] id=%I64u len=%d\n", id, len);
            return; // 드롭
        }
        nf_udpPostReceive(id, remoteAddress, buf, len, options);
    }

    virtual void udpSend(ENDPOINT_ID id, const unsigned char* remoteAddress,
        const char* buf, int len, PNF_UDP_OPTIONS options)
    {
        if (containsKeyword(buf, len))
        {
            printf("[UDP Send BLOCKED] id=%I64u len=%d\n", id, len);
            return; // 드롭
        }
        nf_udpPostSend(id, remoteAddress, buf, len, options);
    }

    virtual void udpCanReceive(ENDPOINT_ID id) {}
    virtual void udpCanSend(ENDPOINT_ID id) {}
};

int main(int argc, char* argv[])
{
    EventHandler eh;
    NF_RULE rule;
    WSADATA wsaData;

    ::WSAStartup(MAKEWORD(2, 2), &wsaData);
    nf_adjustProcessPriviledges();

    // 차단 키워드 설정 (커맨드라인 또는 하드코딩)
    if (argc > 1)
    {
        for (int i = 1; i < argc; i++)
            g_blockKeywords.push_back(argv[i]);
    }
    else
    {
		// 기본 테스트 키워드 - naver, google 등 자주 나오는 단어로 설정
        g_blockKeywords.push_back("naver");
		g_blockKeywords.push_back("google");
    }

    printf("=== Keyword Packet Filter Demo ===\n");
    printf("Blocking keywords:\n");
    for (const auto& kw : g_blockKeywords)
        printf("  - %s\n", kw.c_str());
    printf("\nPress Enter to stop...\n\n");

    // 드라이버 초기화
    if (nf_init(NFDRIVER_NAME, &eh) != NF_STATUS_SUCCESS)
    {
        printf("ERROR: Failed to connect to driver.\n");
        printf("Make sure the driver is installed (run install_driver_64bit.bat as admin)\n");
        return -1;
    }

    // 필터링 규칙: 모든 TCP 트래픽을 필터링 모드로
    memset(&rule, 0, sizeof(rule));
    rule.protocol = IPPROTO_TCP;
    rule.filteringFlag = NF_FILTER;
    nf_addRule(&rule, TRUE);

    // UDP도 필터링하려면 추가
    memset(&rule, 0, sizeof(rule));
    rule.protocol = IPPROTO_UDP;
    rule.filteringFlag = NF_FILTER;
    nf_addRule(&rule, TRUE);

    getchar();

    nf_free();
    ::WSACleanup();
    return 0;
}