# sentry-host-agent

Windows 호스트 에이전트 — 클립보드·메일·웹·USB 매체 통제를 통한 정보 유출 방지.

## 구조

```
sentry-host-agent/
├── clipboard_ctrl/     # [1단계] 클립보드 제어 (Python)
├── network_hook/       # Outlook·SMTP·HTTP(S) 업로드 통제
├── usb_minifilter/     # 유저모드 USB 반출 탐지·사후 삭제
├── core_comm/          # 공통 서버 통신 및 이벤트 로깅
├── config/             # settings.yaml, regex_patterns.json
├── tests/
├── main_agent.py       # 에이전트 진입점
└── requirements.txt
```

## 빠른 시작

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python main_agent.py
```

USB FileGuard는 잘못된 드라이브 기준이 내장 파일을 삭제하는 일을 막기 위해 자동 초기화하지 않습니다. 첫 실행 전에 이동식 저장장치를 모두 제거하고 관리자 PowerShell에서 다음을 실행하세요.

```powershell
.\install\setup_agent.ps1
```

설치 스크립트가 `config\internal_drives.local.json`을 생성합니다. 이 파일은 PC마다 다르며 Git에 올라가지 않습니다. 파일이 없거나 잘못되면 FileGuard는 모니터를 시작하지 않고 재설치 안내를 출력합니다.

## 발표 시연 사전 점검

Windows PC에서 AI 서버와 원격 대시보드를 먼저 실행한 뒤 다음을 실행합니다.

```powershell
python scripts\demo_preflight.py
```

사전 점검은 설정을 수정하지 않는 읽기 전용 도구입니다. 다음을 확인합니다.

- `ai_base_url`이 mock이 아닌 실제 AI로 설정되었고 모델이 준비되었는지
- `dashboard_url`이 `127.0.0.1`이 아닌 다른 PC에서 접속 가능한 주소이며 `/health`가 응답하는지
- `dashboard_token`이 비어 있지 않고 `send_immediately: true`인지
- 로컬 USB 드라이브 기준, pywin32, Outlook, mitmproxy CA와 시스템 프록시 상태
- `CLIPBOARD`, `USB_COPY`, `EMAIL_ATTACHMENT`, `WEB_UPLOAD`, `CLOUD_DRIVE` 시연 준비 여부

토큰 값은 화면에 출력하지 않습니다. 웹 서버에 변경을 남기지 않기 위해 토큰이 서버 값과 일치하는지는 실제 테스트 이벤트 한 건으로 최종 확인해야 합니다.

## 시연 채널 범위

| 채널 | 현재 방식 |
|---|---|
| `CLIPBOARD` | 위험 프로세스에서 Ctrl+V 클립보드 붙여넣기 검사 |
| `USB_COPY` | USB에 복사된 파일을 검사하고 AI `block`이면 사후 삭제 |
| `EMAIL_ATTACHMENT` | Outlook 외부 발송 직전의 본문·첨부파일 검사 |
| `WEB_UPLOAD` | 설정된 웹메일 도메인의 HTTPS 전송 검사 |
| `CLOUD_DRIVE` | 설정된 Google Drive·MYBOX·OneDrive·Dropbox·Box 업로드 검사 |
| `MESSENGER` | 독립 메신저 훅이 아니라 Discord·KakaoTalk·Slack 등의 Ctrl+V를 `CLIPBOARD`로 검사 |
| `PRINT` | **현재 미지원** — 출력 시연 완료로 표기하지 않음 |

## 테스트

```bash
pytest tests/
```
