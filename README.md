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

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\install\setup_agent.ps1 -PythonExe .\.venv\Scripts\python.exe
```

`setup_agent.ps1`은 Windows PowerShell 5.1에서 실행할 수 있으며, 선택한 Python의 필수 런타임·파일 추출 모듈을 먼저 검증합니다. 모듈이 없거나 깨졌으면 시스템 Python에 자동 설치하지 않고 위와 같이 프로젝트 전용 venv에 `requirements.txt`를 설치하도록 안내한 뒤 안전하게 중단합니다.

발표용 기본 설치는 현재 사용자 전용 `SentryUserAgent`만 제한 권한·`pythonw.exe`로 등록하며, 배터리에서도 시작·유지합니다. SMTP·HTTP용 LocalSystem 서비스는 기본 설치하지 않습니다. 시스템 채널이 꼭 필요할 때만 관리자 전용 `Program Files` 배포본과 Python을 준비한 뒤 `-InstallSystemService`를 명시하세요. 사용자 쓰기 가능한 Desktop checkout을 LocalSystem으로 실행하지 않습니다.

USB FileGuard는 잘못된 드라이브 기준이 내장 파일을 삭제하는 일을 막기 위해 자동 초기화하지 않습니다. 첫 실행 전에 이동식 저장장치를 모두 제거하고 관리자 PowerShell에서 다음을 실행하세요.

```powershell
.\install\setup_agent.ps1 -PythonExe .\.venv\Scripts\python.exe
```

설치 스크립트가 `config\internal_drives.local.json`을 생성합니다. 이 파일은 PC마다 다르며 Git에 올라가지 않습니다. 파일이 없거나 잘못되면 FileGuard는 모니터를 시작하지 않고 재설치 안내를 출력합니다.

Windows가 `FIXED`로 인식하는 외장 SSD는 내장 드라이브와 자동 구분할 수 없으므로 기준 생성 전에 USB·외장 저장장치를 모두 제거해야 합니다. 기준 생성 뒤 내장 드라이브를 추가·제거하거나 드라이브 문자를 바꿨다면 FileGuard를 다시 사용하기 전에 외장 저장장치를 제거하고 `setup_agent.ps1`을 재실행해 기준을 갱신하세요.

실행 계층은 다음과 같이 분리됩니다.

- 선택 설치 Windows 서비스 `SentryDLPService`: SMTP·HTTP 시스템 채널
- 예약 작업 `SentryUserAgent`: Clipboard·Outlook·FileGuard·WebProxy 사용자 채널

`settings.yaml`이나 `channel_policy.json`을 바꾼 뒤에는 해당 실행 계층을 다시 시작해야 합니다. 다섯 발표 시나리오는 사용자 채널이므로 다음 명령으로 예약 작업을 재시작하고 `logs\user_agent.log`에서 채널 시작 상태를 확인합니다.

```powershell
Stop-ScheduledTask -TaskName SentryUserAgent
Start-ScheduledTask -TaskName SentryUserAgent
```

## 발표 시연 사전 점검

Windows PC에서 AI 서버와 원격 대시보드를 먼저 실행한 뒤 다음을 실행합니다.

```powershell
.\.venv\Scripts\python.exe scripts\demo_preflight.py
```

사전 점검은 설정을 수정하지 않는 읽기 전용 도구입니다. 다음을 확인합니다.

- `ai_base_url`이 mock이 아닌 실제 AI로 설정되었고 응답 모델이 정확히 `koelectra-dlp-v7`인지
- `dashboard_url`이 `127.0.0.1`이 아닌 다른 PC에서 접속 가능한 주소이며 `/health`가 응답하는지
- `dashboard_token`이 Web R009의 보호된 `/api/v1/agent-check`에서 실제로 승인되고 `send_immediately: true`인지
- 실행 중인 `SentryUserAgent`, 로컬 USB 드라이브 기준, pywin32, Outlook, 구조화 파일 추출 모듈
- mitmproxy CA·시스템 프록시·실제 로컬 TCP 리스너와 Outbound UDP/443 QUIC 차단 규칙
- `CLIPBOARD`, `USB_COPY`, `EMAIL_ATTACHMENT`, `WEB_UPLOAD`, `CLOUD_DRIVE` 시연 준비 여부

토큰 값은 화면에 출력하지 않습니다. 사전 점검은 로그를 생성하지 않는 Web R009의 `/api/v1/agent-check`로 서버 값과의 일치까지 확인합니다. 이 경로가 없는 이전 Web 버전이나 잘못된 토큰은 시연 준비 실패로 처리합니다.

사전 점검의 `exit 0`은 설정과 로컬 실행 조건이 준비됐다는 뜻일 뿐, 실제 Windows 훅·AI 판정·대시보드 기록을 연결한 E2E 완료 증거가 아닙니다. 발표 전에는 각 채널의 실제 동작과 동일한 `event_id`의 대시보드 기록을 별도로 확인하세요.

실시간 대시보드 전송은 채널 조치를 막지 않는 백그라운드 작업에서 최대 3회 짧게 재시도합니다. 모두 실패한 이벤트는 자동 재전송되지 않고 로컬 JSONL에만 남습니다. 네트워크 복구 후 다음 명령으로 활성 로컬 로그를 명시적으로 재전송하고, `attempted`와 `successful_posts`가 같은지 확인하세요. Web은 안정적인 `event_id`를 중복 저장하지 않습니다.

```powershell
.\.venv\Scripts\python.exe scripts\flush_dashboard_logs.py
```

사전 점검은 현재 사용자 CA·레지스트리 프록시뿐 아니라 `channel_policy.json`의 포트가 실제로 리스닝 중인지, `SentryDLP - Block QUIC UDP 443` 규칙이 활성 Outbound UDP/443 차단인지 확인합니다. 그래도 실제 브라우저 chunk 업로드가 프록시를 통과하고 차단되는지는 발표 전 별도 E2E가 필요합니다.

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

WebProxy의 AI `block`은 HTTP 451 응답 생성이 확정된 뒤에만 `BLOCKED`로 기록합니다. 응답 생성에 실패하면 원 요청의 실제 차단을 확인할 수 없으므로 `WARNED`와 실패 사유를 기록합니다.

USB `BLOCKED`는 복사 전 차단이 아니라 USB 대상 파일을 검사한 뒤 `os.remove` 삭제가 실제로 성공한 사후 조치 결과입니다. 삭제 직전이나 삭제 중 파일이 없어졌더라도 삭제 성공을 확인할 수 없으므로 `WARNED`로 기록합니다. 권한·잠금 등의 삭제 실패도 `WARNED`로 기록하고 `decision_reason`에 실패 사유와 실제 차단 미확인 상태를 남깁니다. 시연에서는 원본이 아닌 USB 대상 파일이 실제로 사라졌는지도 직접 확인하세요.

FileGuard는 같은 경로의 add·write·rename 이벤트가 겹치면 진행 중인 검사 하나만 유지합니다. 파일 크기와 수정 시간이 0.25초 간격으로 5회 연속 같을 때만 검사하고, 분석 전의 크기·수정시간·생성시간·장치·파일 ID 지문을 삭제 직전에 다시 확인합니다. 지문이 다르면 다른 파일을 삭제하지 않고 `WARNED`로 기록합니다. 15초 안에 안정되지 않거나 안정화 중 파일이 사라지면 분석 이벤트가 생성되기 전이므로 검사·삭제하지 않고 Host 진단 로그만 남기는 한계가 있습니다.

## 테스트

```bash
pytest tests/
```
