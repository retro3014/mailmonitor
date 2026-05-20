================================================================================
 SmtpMailMonitor - NetFilterSDK 기반 SMTP 메일 모니터링/차단 시스템
================================================================================

[ 개요 ]
  NetFilterSDK의 sockfilter 드라이버를 활용하여 아웃바운드 SMTP 트래픽을
  실시간으로 감시하고, 발송 메일의 내용/첨부파일을 로깅하며,
  개인정보(주민등록번호 등)가 포함된 메일의 발송을 차단합니다.

[ 기능 ]
  1-1) 메일 내용 로깅
       - 발송 메일 1건당 1개의 JSON 파일 생성
       - GUID 기반 고유 식별자로 파일명 생성
       - 메일 제목, 본문, 수신자(To/CC/BCC), 발송 일시, 기타 헤더 저장
       - 특수 문자는 JSON 이스케이프 처리

  1-2) 메일 첨부 파일 로깅
       - 첨부 파일별 별도 폴더에 원본 파일로 저장
       - 첨부 파일 메타정보(이름, 크기, MIME타입 등)는 메일 JSON에 포함
       - 각 첨부 파일도 개별 GUID로 식별

  1-3) SQLite DB 저장 (선택)
       - USE_SQLITE 매크로 정의 시 활성화
       - mail_logs 테이블: 메일 본문 정보
       - mail_attachments 테이블: 첨부 파일 정보
       - SQL 쿼리로 메일 발송 이력 조회 가능

  2)   메일 발송 차단
       - block_policy.json에서 정규표현식 및 차단 기준 건수 설정
       - 메일 본문(text + html)에서 패턴 매칭
       - 기준 건수 이상 검출 시 SMTP 세션 차단
       - 차단된 메일도 JSON으로 로깅 (blocked=true)

[ 파일 구조 ]
  SmtpMailMonitor.cpp    - 메인 소스 (EventHandler, 로깅, 차단 로직)
  SmtpParser.h           - SMTP 프로토콜 파서 & MIME 메시지 디코더
  Base64Decoder.h        - Base64/Quoted-Printable/RFC2047 디코더
  GuidUtil.h             - Windows GUID 생성 유틸리티
  JsonWriter.h           - 경량 JSON 직렬화 라이브러리
  block_policy.json      - 차단 정책 설정 파일
  stdafx.h / stdafx.cpp  - 미리 컴파일된 헤더

[ 빌드 방법 ]
  1. Visual Studio에서 SmtpMailMonitor.sln 열기
  2. 기본 빌드: 그대로 빌드 (SQLite 없이)
  3. SQLite 포함 빌드:
     a. https://www.sqlite.org/download.html 에서 sqlite3.c, sqlite3.h 다운로드
     b. 프로젝트 폴더에 복사
     c. vcxproj에서 USE_SQLITE 관련 주석 해제
     d. 빌드

[ 실행 방법 ]
  SmtpMailMonitor.exe [옵션]

  옵션:
    -log <경로>      메일 로그 저장 경로 (기본: .\mail_logs)
    -db <경로>       SQLite DB 파일 경로 (기본: .\mail_logs\mail_log.db)
    -policy <경로>   차단 정책 파일 경로 (기본: .\block_policy.json)

  주의: 관리자 권한으로 실행해야 합니다.
        sockfilter 드라이버가 사전 설치되어 있어야 합니다.

[ 로그 출력 예시 ]
  mail_logs/
    3F2504E0-4F89-11D3-9A0C-0305E82C3301/
      3F2504E0-4F89-11D3-9A0C-0305E82C3301_mailbody.json
      3F2504E0-4F89-11D3-9A0C-0305E82C3301_A1B2C3D4-E5F6-7890-ABCD-EF1234567890.docx
      3F2504E0-4F89-11D3-9A0C-0305E82C3301_B2C3D4E5-F6A7-8901-BCDE-F12345678901.pptx

[ JSON 파일 구조 예시 ]
  {
    "id": "3F2504E0-4F89-11D3-9A0C-0305E82C3301",
    "subject": "회의 자료 첨부",
    "from": "sender@example.com",
    "recipients": {
      "to": "receiver@example.com",
      "cc": "manager@example.com",
      "bcc": "",
      "smtp_rcpt_to": ["receiver@example.com", "manager@example.com"]
    },
    "date": "Wed, 01 Apr 2026 10:30:00 +0900",
    "send_timestamp": "2026-04-01T10:30:15+09:00",
    "body_plain_text": "메일 본문 내용...",
    "attachment_count": 2,
    "attachments": [
      {
        "id": "A1B2C3D4-...",
        "filename": "1.docx",
        "file_size": 15234,
        "content_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "saved_filename": "3F2504E0-..._A1B2C3D4-....docx"
      },
      ...
    ],
    "block_info": {
      "blocked": false
    }
  }

[ block_policy.json 설정 ]
  {
    "blocking_enabled": true,
    "rules": [
      {
        "name": "resident_registration_number",
        "description": "주민등록번호 패턴",
        "pattern": "\\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\\d|3[01])[-\\s]?[1-4]\\d{6}",
        "threshold": 2,      // 2건 이상이면 차단
        "enabled": true
      }
    ]
  }

[ SQLite 테이블 구조 ]
  mail_logs:
    - id, subject, mail_from, mail_to, cc, bcc
    - smtp_mail_from, date_header, send_timestamp, message_id
    - body_plain, body_html, reply_to, x_mailer, importance
    - raw_data_size, attachment_count
    - blocked, block_reason
    - source_ip, dest_ip, process_name, process_id
    - json_file_path, created_at

  mail_attachments:
    - id, mail_id, filename, content_type
    - file_size, saved_path, content_encoding, created_at

[ SQL 조회 예시 ]
  -- 최근 발송 메일 조회
  SELECT id, subject, mail_from, mail_to, send_timestamp, blocked
  FROM mail_logs ORDER BY created_at DESC LIMIT 20;

  -- 차단된 메일만 조회
  SELECT * FROM mail_logs WHERE blocked = 1;

  -- 특정 메일의 첨부파일 조회
  SELECT * FROM mail_attachments WHERE mail_id = '3F2504E0-...';

  -- 일자별 메일 발송 통계
  SELECT date(send_timestamp) as dt, COUNT(*) as cnt,
         SUM(CASE WHEN blocked=1 THEN 1 ELSE 0 END) as blocked_cnt
  FROM mail_logs GROUP BY dt ORDER BY dt DESC;
================================================================================
