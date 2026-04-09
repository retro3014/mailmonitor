# SmtpMailMonitor - NetFilterSDK 기반 메일 모니터링/차단 시스템

전산학 프로젝트: NetFilterSDK sockfilter 드라이버를 활용한 발신 이메일 감시 및 개인정보(주민등록번호) 포함 메일 차단 시스템.

## 주요 기능

1. **SMTP 메일 감시** (포트 25, 587, 465): TLS MITM 프록시를 통해 암호화된 SMTP 트래픽을 복호화하여 발신 이메일의 제목, 본문, 첨부파일을 JSON으로 로깅
2. **Gmail 웹메일 감시** (포트 443): HTTPS MITM 프록시로 `mail.google.com` 트래픽을 가로채어 Gmail 웹 인터페이스에서 보내는 메일 탐지
3. **개인정보 차단**: 정책 파일(`block_policy.json`)에 정의된 주민등록번호 패턴이 메일에 포함되면 전송 차단
4. **로그 저장**: 탐지된 메일을 GUID 기반 폴더에 JSON으로 저장, 첨부파일 별도 보관

## 파일 구조

```
GmailSmtpMailMonitor/
├── SmtpMailMonitor.cpp    # 메인 소스 (NetFilterSDK 이벤트 핸들러, 포트 리다이렉트)
├── TlsProxy.h             # TLS MITM 프록시 (SMTP/HTTPS 양방향 릴레이, Gmail 파서)
├── CertGenerator.h        # 동적 서버 인증서 생성 (SNI 기반)
├── SmtpParser.h           # SMTP 프로토콜 파서
├── HttpParser.h           # HTTP/1.1 파서
├── GmailWebParser.h       # Gmail 웹 API 데이터 유틸리티
├── JsonWriter.h           # JSON 로그 파일 생성
├── GuidUtil.h             # GUID 생성 유틸리티
├── generate_ca.bat        # CA 인증서 생성 스크립트
├── block_policy.json      # 차단 정책 (주민등록번호 패턴)
├── ca_key.pem             # CA 개인키 (generate_ca.bat으로 생성)
├── ca_cert.pem            # CA 인증서 (generate_ca.bat으로 생성)
└── mail_logs/             # 탐지된 메일 로그 저장 디렉토리
```

## 동작 원리

### SMTP 감시 
NetFilterSDK의 `tcpConnectRequest`에서 포트 465/587 연결을 로컬 TLS 프록시(127.0.0.1:10465)로 리다이렉트. 프록시가 양쪽 TLS를 종료하고 평문 SMTP 데이터를 파싱하여 이메일 내용을 추출.

### Gmail 웹 감시
1. DNS로 `mail.google.com` IP를 해석하여 포트 443 연결을 감지
2. `MSG_PEEK`로 TLS ClientHello의 SNI를 추출하여 `mail.google.com`만 MITM, 나머지는 투명 터널
3. 복호화된 HTTPS 트래픽에서 Gmail 동기화 API(`/sync/u/0/i/s`) 데이터를 파싱
4. `"msg-a:"` 마커로 메일 작성 데이터를 식별하고, `[[0,"<div>..."]]` 패턴으로 제목/본문 추출
5. Pending Detection 시스템: 같은 발신→수신 쌍에 대해 데이터가 점진적으로 도착하므로, 최신(가장 완전한) 데이터를 3초간 축적 후 최종 로그

### TLS MITM 구조
```
[브라우저/메일클라이언트] ←TLS→ [프록시(가짜 인증서)] ←TLS→ [실제 서버]
                                    ↓
                           평문 데이터 추출 → 파싱 → 로깅/차단
```

## 실행 방법

### 1. 사전 준비

**필수 소프트웨어:**
- Windows 10/11 (64-bit)
- Visual Studio 2019 이상
- OpenSSL 라이브러리 (libssl.lib, libcrypto.lib)
- NetFilterSDK sockfilter 드라이버

**OpenSSL 설치:**
```
프로젝트 설정 → C/C++ → Additional Include Directories → OpenSSL include 경로 추가
프로젝트 설정 → Linker → Additional Library Directories → OpenSSL lib 경로 추가
```

### 2. CA 인증서 생성

```batch
cd SmtpMailMonitor
generate_ca.bat
```

`ca_key.pem`과 `ca_cert.pem`이 생성됨. 이 CA 인증서를 시스템에 신뢰할 수 있는 루트 인증서로 등록해야 Chrome이 MITM 인증서를 수락함:

```batch
certutil -addstore Root ca_cert.pem
```

등록 확인:
```batch
certutil -store Root | findstr "SmtpMailMonitor"
```

### 3. NetFilterSDK 드라이버 설치

sockfilter 드라이버가 설치되어 있어야 함. NetFilterSDK 샘플에 포함된 드라이버 설치 절차를 따름.

### 4. 빌드 및 실행

Visual Studio에서 `SmtpMailMonitor.vcxproj` 열기 → Release x64로 빌드.

```batch
# 기본 실행 (SMTP + HTTPS 모두 감시)
SmtpMailMonitor.exe

# HTTPS(Gmail 웹) 감시 비활성화
SmtpMailMonitor.exe -no_https

# 커스텀 경로 지정
SmtpMailMonitor.exe -log .\my_logs -ca_key .\my_ca_key.pem -ca_cert .\my_ca_cert.pem -proxy_port 10465
```

**명령줄 옵션:**

| 옵션 | 설명 | 기본값 |
|------|------|--------|
| `-log <path>` | 메일 로그 저장 경로 | `.\mail_logs` |
| `-db <path>` | SQLite DB 경로 | `.\mail_logs\mail_log.db` |
| `-policy <path>` | 차단 정책 파일 | `.\block_policy.json` |
| `-ca_key <path>` | CA 개인키 파일 | `.\ca_key.pem` |
| `-ca_cert <path>` | CA 인증서 파일 | `.\ca_cert.pem` |
| `-proxy_port <port>` | TLS 프록시 포트 | `10465` |
| `-no_https` | Gmail 웹 감시 비활성화 | (활성화) |

### 5. 실행 결과 예시

```
[Policy] Loaded block policy: block_policy.json
[TlsProxy] Listening on 127.0.0.1:10465
[HTTPS] Resolved mail.google.com: 142.250.196.69
=== SmtpMailMonitor started (press Enter to stop) ===

[TlsProxy] SNI: mail.google.com (target) -> starting MITM
[TlsProxy] HTTPS MITM established for mail.google.com
[TlsProxy] Monitoring Gmail traffic for email data...
[Gmail] Detection updated: sender@gmail.com -> rcpt@naver.com, subject="테스트", body=12 bytes

========================================
[TlsProxy/HTTPS] Gmail email detected!
  From: sender@gmail.com (홍길동)
  To: rcpt@naver.com (김철수)
  Subject: 테스트 메일
  Body: 안녕하세요. 테스트입니다.
========================================
[LOG] JSON saved: .\mail_logs\XXXXXXXX-...\XXXXXXXX-..._mailbody.json
```

PII 포함 메일 차단 시:
```
*** [BLOCKED] Gmail web email PII detected! ***
  Rule: resident_id, Matches: 1
```
