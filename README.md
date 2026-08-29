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

웹메일·클라우드 업로드 시연을 할 때만 관리자 PowerShell에서 HTTPS 프록시를 별도로 설정합니다. 선택한 프로젝트 `.venv`에 `mitmproxy`가 없으면 전역 설치하지 않고 중단합니다.

```powershell
.\install\setup_proxy.ps1 -PythonExe .\.venv\Scripts\python.exe
```

시연 후에는 프록시·CA·QUIC 방화벽 규칙을 원복합니다.

```powershell
.\install\remove_proxy.ps1
```

`setup_agent.ps1`은 Windows PowerShell 5.1에서 실행할 수 있으며, 선택한 Python의 필수 런타임·파일 추출 모듈을 먼저 검증합니다. 모듈이 없거나 깨졌으면 시스템 Python에 자동 설치하지 않고 위와 같이 프로젝트 전용 venv에 `requirements.txt`를 설치하도록 안내한 뒤 안전하게 중단합니다. 설치 기본값은 예약 작업을 **비활성 상태로 등록만** 합니다. 기본 mock AI·loopback 대시보드 설정으로 호스트 제어가 먼저 시작되는 것을 막기 위한 조치입니다.

발표용 기본 설치는 관리자 권한을 요구하지 않고 현재 사용자 전용
`SentryUserAgent`만 제한 권한·`pythonw.exe`로 등록합니다. 배터리에서도
무기한 시작·유지하고 중복 실행은 거부합니다. 고정 작업 이름과 사용자별
HKCU·Outlook·클립보드에 의존하므로 한 대의 시연 PC에서는 지정한 Windows
계정 하나만 지원합니다. 다른 계정이 동시에 설치·실행한 것으로 완료 처리하지
마세요. SMTP·HTTP용 LocalSystem 서비스는 이번 발표 범위와 이 설치기에서
제외했습니다. `sentry_service.py`는 기존 실험 코드일 뿐 발표 설치 절차가
아니며, 별도 보호 배포·쓰기 상태 분리·Windows 서비스 검증 없이 관리자
서비스로 등록하지 마세요.

USB FileGuard는 내장 디스크 오인 삭제를 막기 위해 Windows `GetDriveType`이 `DRIVE_REMOVABLE`로 보고한 USB 매체만 감시합니다. `DRIVE_FIXED`로 보고되는 외장 SSD는 내장 디스크와 안전하게 구분할 장치 식별이 없으므로 이번 시연 범위에서 제외합니다. USB 시연은 반드시 Windows가 `Removable`로 표시하는 플래시 드라이브를 사용하세요.

발표 설치의 실행 계층은 하나입니다.

- 현재 계정 예약 작업 `SentryUserAgent`: Clipboard·Outlook·FileGuard·WebProxy
  사용자 채널
- SMTP·HTTP 시스템 채널: 이번 발표 설치 범위에서 제외

추적되는 `settings.yaml`에는 공용 기본값만 둡니다. 실제 URL과 토큰은 Git에서 제외되는 `config/settings.local.yaml`에 넣고 `channel_policy.json`을 확인한 뒤, 첫 실행에서는 작업을 활성화하고 시작합니다. `AI_API_TOKEN`·`AGENT_API_TOKEN` 환경변수가 있으면 local YAML보다 우선합니다. 이후 설정을 바꿨을 때도 같은 작업을 재시작하고 `logs\user_agent.log`에서 채널 시작 상태를 확인하세요.

```yaml
# config/settings.local.yaml (.gitignore 적용)
server:
  ai_base_url: "https://<AI_TUNNEL>.trycloudflare.com"
  ai_token: "<AI_API_TOKEN>"
  dashboard_url: "http://<WEB_LAN_IP>:8000"
  dashboard_token: "<AGENT_API_TOKEN>"
```

토큰 실값은 추적되는 `config/settings.yaml`·Git·문서·발표 화면에 남기지 않습니다. `settings.local.yaml`은 각 시연 PC에서만 만들며 공유할 때도 보안 채널을 사용합니다.

Host가 AI로 보내는 `snippet`은 AI 요청 계약과 같은 최대 4,000자로 강제 제한합니다. 로컬 설정에서 `0`이나 4,000 초과 값을 넣어도 절대 상한을 넘지 않으며, `matched_patterns`는 최대 100개·각 100자, `user_id`는 100자, 앱 메타데이터 문자열은 500자로 제한합니다.

```powershell
Enable-ScheduledTask -TaskName SentryUserAgent
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
- `AI_API_TOKEN` 또는 local `ai_token`이 32자 이상 ASCII이고 AI 서버의 보호된 `/api/v1/agent-check`에서 Bearer 토큰으로 승인되는지
- `dashboard_url`이 `127.0.0.1`이 아닌 다른 PC에서 접속 가능한 주소이며 `/health`가 응답하는지
- `AGENT_API_TOKEN` 또는 local `dashboard_token`이 32자 이상 ASCII이고 Web의 보호된 `/api/v1/agent-check`에서 실제로 승인되며 `send_immediately: true`인지
- 현재 사용자·현재 프로젝트의 `pythonw.exe`·스크립트·작업 디렉터리로 실행 중인 `SentryUserAgent`, pywin32, Outlook, 구조화 파일 추출 모듈
- mitmproxy CA·시스템 프록시·현재 Agent 프로세스가 소유한 로컬 TCP 리스너와 Outbound UDP/443 QUIC 차단 규칙
- `CLIPBOARD`, `USB_COPY`, `EMAIL_ATTACHMENT`, `WEB_UPLOAD`, `CLOUD_DRIVE` 시연 준비 여부

토큰 값은 화면에 출력하지 않습니다. 사전 점검은 로그를 생성하지 않는 AI와 Web의 `/api/v1/agent-check`로 각 토큰 일치까지 확인합니다. 이 경로가 없는 이전 버전이나 잘못된 토큰은 시연 준비 실패로 처리합니다.

사전 점검의 `exit 0`은 설정과 로컬 실행 조건이 준비됐다는 뜻일 뿐, 실제 Windows 훅·AI 판정·대시보드 기록을 연결한 E2E 완료 증거가 아닙니다. 발표 전에는 각 채널의 실제 동작과 동일한 `event_id`의 대시보드 기록을 별도로 확인하세요.

### 서버 파이프라인 실연동 확인

실제 AI·Web URL과 토큰을 `settings.local.yaml` 또는 환경변수에 설정한 뒤 합성 마커 1건을 전송합니다. 이 도구는 발표 증거용이므로 Web 대시보드 인증이 반드시 활성화되어 있어야 합니다. Web 서버와 같은 `DASHBOARD_VIEWER_USERNAME`과 `DASHBOARD_VIEWER_PASSWORD`를 둘 다 설정하세요. 두 값은 ASCII여야 하고 username에 `:`을 넣을 수 없으며 password는 16자 이상이어야 합니다. 누락되거나 형식이 다르면 네트워크 요청 전 `WEB_CONFIG_INVALID`로 중단합니다. 이 명령은 Web에 시험 로그 1건을 실제로 저장하므로 발표용 서버에서만 실행하세요.

```powershell
.\.venv\Scripts\python.exe scripts\verify_live_pipeline.py
```

검증 경로는 `Bearer 인증 AI health → 인증·DB 준비 Web health → 실제 AI POST 및 koelectra-dlp-v7/event_id 응답 → Host JSONL 기록 → Web POST 영수증 → Basic 인증 GET 재조회`입니다. AI health는 `status=running`, `engine=koelectra-dlp-v7`, `auth_required=true`, 단일 checkpoint SHA-256과 `0 <= review < block <= 1`인 threshold를 요구합니다. Web health는 `status=ok`, `database_status=ok`, `dashboard_auth_enabled=true`여야 합니다. 성공 출력과 JSONL 증거에는 동일한 `event_id`, checkpoint SHA-256, 두 threshold, OOD 결합 여부, 모델·조치 결과, `ai_rtt_ms`, `event_to_jsonl_ms`, `web_ack_ms`, `evidence_path`, `evidence_sha256` 등 안전한 검증값만 포함하고 토큰·마커 원문은 출력하지 않습니다. 어느 단계든 계약이 다르거나 HTTP·저장·재조회가 실패하면 non-zero로 종료합니다.

AI Model 담당이 생성한 blind OOD aggregate 결과까지 같은 실행 checkpoint에 묶으려면 `--ood-result`를 지정합니다. JSON의 `gate=blind_ood_final_v1`, `status=passed`, `model_version=koelectra-dlp-v7`, `quality_passed=true`, checkpoint SHA-256, block/review threshold가 실제 evaluator 계약 및 현재 AI health와 일치해야 합니다. 기록된 F1·Recall과 사전 고정 합격선도 유한한 0~1 값인지, 두 합격선이 각각 0.90 이상인지, 두 지표가 각 합격선을 실제로 충족했는지 다시 검증해야 통과합니다.

```powershell
.\.venv\Scripts\python.exe scripts\verify_live_pipeline.py --ood-result "C:\evidence\ood_eval_result_v7.json"
```

미지정 성공 결과는 `ood_bound=false`이며 서버 파이프라인 연결만 증명합니다. 지정 결과가 유효하면 `ood_bound=true`와 원본 aggregate 파일의 `ood_result_sha256`을 출력·JSONL에 기록합니다. OOD 파일의 원문이나 경로는 출력하지 않습니다.

JSONL 증거는 기본 `logs/server-pipeline-evidence/YYYY-MM-DD/<event_id>/events.jsonl`에 보존됩니다. 다른 루트가 필요하면 `--evidence-root <directory>`를 사용하세요. 상대 경로는 프로젝트 루트 기준입니다. JSONL이 생성되면 성공·Web 단계 실패 결과에 파일의 SHA-256을 `evidence_sha256`으로 표시하므로, 후속 검토 전에 변경 여부를 확인할 수 있습니다. 도구는 기존 `event_id` 폴더를 덮어쓰거나 지우지 않고, 성공·Web 실패 모두 보존된 경로를 결과에 표시합니다. 서버 복구 후에는 명령을 다시 실행해 새 `event_id`로 검증하고, 기존 증거는 자동 재전송·삭제되지 않습니다. 삭제가 필요하면 조원 확인 및 사용자 승인 후 출력된 해당 `<event_id>` 폴더 하나만 수동으로 삭제하세요.

출력의 `scope=SERVER_PIPELINE`, `windows_hook_e2e=false`가 범위입니다. `ood_bound=true`도 해당 서버의 품질 결과와 연결됐다는 뜻일 뿐 Windows 훅 검증으로 범위를 넓히지 않습니다. 이 검사는 macOS에서도 서버 공통 경로를 검증할 수 있지만 Clipboard·USB·Outlook·WebProxy 등 Windows 훅과 실제 사용자 조치를 시험하지 않습니다. 따라서 5개 발표 채널의 Windows Host→AI→Web E2E 증거로 대체하면 안 됩니다.

실시간 대시보드 전송은 채널 조치를 막지 않는 백그라운드 작업에서 최대 3회 짧게 재시도합니다. 모두 실패한 이벤트는 자동 재전송되지 않고 로컬 JSONL에만 남습니다. 네트워크 복구 후 다음 명령으로 활성·회전 로컬 로그(`events*.jsonl`)를 명시적으로 재전송하고, `attempted`와 `successful_posts`가 같은지 확인하세요. `successful_posts`는 Web 저장 응답의 동일한 `event_id`, 양의 `log_id`, boolean `duplicate`까지 검증한 건수입니다. Web은 안정적인 `event_id`를 중복 저장하지 않습니다.

신규로 생성되는 `logs/events*.jsonl`은 검사 원문과 `text_preview`를 저장하지 않고 `text_sha256`만 기록합니다. 호환성을 위해 `logging.text_preview_len` 설정은 계속 받지만 신규 로그 내용에는 영향을 주지 않습니다. 이전 버전이 생성한 JSONL에는 원문 미리보기가 남아 있을 수 있으며, 이런 기존 로그도 재전송은 가능하지만 자동 수정·삭제되지 않습니다. 로그는 계속 Git에서 제외하고, 시연에는 가상 데이터만 사용하세요.

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

USB `BLOCKED`는 복사 전 차단이 아니라 USB 대상 파일을 하나의 Windows 핸들로 읽고 AI가 `block`을 반환한 뒤, 같은 핸들에 `FileDispositionInfo` 삭제 예약을 설정하고 핸들을 정상적으로 닫은 사후 조치 결과입니다. 삭제 예약·핸들 닫기 실패나 분석 후 핸들 지문 변경은 `WARNED`로 기록하고 `decision_reason`에 실제 차단 미확인 상태를 남깁니다. delete-on-close의 실제 파일 소멸은 파일시스템과 다른 열린 핸들의 영향을 받을 수 있으므로, 시연에서는 원본이 아닌 USB 대상 파일이 실제로 사라졌는지도 직접 확인하세요.

FileGuard는 같은 경로의 add·write·rename 이벤트가 겹치면 진행 중인 검사 하나만 유지합니다. 파일 크기와 수정 시간이 0.25초 간격으로 5회 연속 같을 때만 검사합니다. 이후 읽기·삭제 권한과 읽기 공유만 허용한 단일 핸들을 열어 쓰기·이름 변경을 막고, 볼륨 일련번호·디렉터리/reparse 속성·파일 ID·크기·시간 지문을 확인한 뒤 그 핸들에서 읽습니다. AI 판정 뒤 같은 핸들 지문이 다르면 다른 대상을 삭제하지 않고 `WARNED`로 기록합니다. 15초 안에 안정되지 않거나 핸들 검증 전에 파일이 사라지면 분석 이벤트가 생성되기 전이므로 검사·삭제하지 않고 Host 진단 로그만 남기는 한계가 있습니다.

## 테스트

```bash
pytest tests/
```
