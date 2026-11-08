# 앱 내부 WireGuard / 프록시 — Spotify 9.1.90

`WIREGUARD=1`로 빌드하면 두 UI의 Mod Settings에 **앱 내부 WireGuard·프록시**가 생깁니다.
기본 빌드에는 엔진·설정 화면·훅이 들어가지 않습니다. 사용은 기본적으로 꺼져 있고 **iOS 17 이상**에서 켤 수 있습니다.

## 적용 범위

Spotify의 `NSURLSession` 설정과 세션 생성에 프록시를 적용합니다. 9.1.90 메인 실행파일의
`nw_connection_create`, `getaddrinfo`, `connect`, `sendto`, `sendmsg` import도 실행파일 범위에서 교체합니다.
`Network.framework` TCP에는 전용 privacy context의 프록시를 설정하고, BSD TCP의 이름 조회는 터널 DNS,
연결은 로컬 인증 SOCKS5를 거칩니다. Go 엔진과 시스템 프레임워크의 소켓은 교체하지 않습니다.

```text
Spotify URLSession → 인증된 127.0.0.1 SOCKS5 → gVisor TCP/IP → wireguard-go → 사용자의 WireGuard 서버
```

WireGuard 대신 외부 HTTP CONNECT, HTTPS CONNECT, SOCKS5 서버를 선택할 수도 있습니다.
HTTPS 프록시는 시스템 신뢰 저장소로 인증서를 검증합니다. TLS 검증을 끄거나 Spotify 인증서를 바꾸지 않습니다.

시스템 VPN, Network Extension, TUN, 라우팅 테이블을 사용하지 않습니다.
프록시가 적용된 요청은 터널/서버가 실패해도 직접 연결로 전환하지 않습니다.
**앱 전체의 모든 소켓을 차단하는 VPN이나 킬 스위치는 아닙니다.** 메인 실행파일의 위 import를 거치지 않는
네트워크 경로, 별도 프로세스의 AVURLAsset·웹 로그인·백그라운드 전송, WebSocket의 로컬 주소 예외,
다른 Spotify Connect 기기의 재생은 보장 범위 밖입니다. 실기기에서 각 경로를 별도로 측정해야 합니다.
메인 실행파일의 원격 UDP/QUIC는 현재 WireGuard 엔진에 UDP 릴레이가 없어 직접 전송을 차단합니다.
로컬 루프백·링크 로컬·멀티캐스트는 Connect 검색을 위해 로컬 경로에 남습니다.
BSD `connect`의 논블로킹 소켓도 SOCKS 연결을 완료할 때까지 호출 스레드에서 기다린 후 원래 플래그를 복원하므로,
실기기에서 지연과 재생 상태를 확인해야 합니다. 외부 프록시 모드의 BSD TCP는 현재 연결을 차단하며,
`Network.framework` TCP와 `NSURLSession`은 설정된 외부 프록시를 사용합니다.

CFNetwork의 로컬 주소 예외가 HTTP 요청을 직접 보내는 것을 막기 위해 숫자 IP URL과
`localhost`/`.local` 호스트의 HTTP(S) 요청은 차단합니다. Spotify의 호스트 이름 URL을 사용해야 합니다.

YTMusic의 Google/Cronet/Envoy enum 패치와 FFmpeg 환경변수는 적용하지 않습니다.
Spotify의 아래 클래스는 응답·오류·수신 바이트를 관측합니다. 클래스가 없거나 메서드 ABI가 다르면
해당 관측 훅만 건너뛰고 진단에 표시합니다. 기존 delegate 및 광고/개인정보 훅은 그대로 호출합니다.

| 실행파일 | 확인한 클래스 | 확인한 메서드 |
| --- | --- | --- |
| Spotify | SPTCoreURLSessionDataDelegate | `URLSession:task:didCompleteWithError:`, `URLSession:dataTask:didReceiveData:` |
| Spotify | _TtC26Connectivity_HttpClientKit20HttpClientURLSession | 위와 같음 |
| SpotifyShared | SPTDataLoaderService | 위와 같음 |

기준 IPA: Spotify **9.1.90 / 919002269**, arm64, iOS 최소 16.1.
메인 UUID: `fbce22c17e1b3e0d9be866ff9291943e`.
SpotifyShared UUID: `2e074234cfc63f0e9255c9881824167a`. 두 실행파일의 `cryptid=0` 확인.
정적 클래스 존재는 실제 재생 성공의 증거가 아닙니다.

## 빌드

Go 버전은 `WireGuard/go.mod`에 고정되어 있습니다. Xcode, Theos 및 기존 vitrine 빌드 도구가 필요합니다.

```sh
make release IPA=/path/to/Spotify-9.1.90.ipa WIREGUARD=1
```

GitHub Actions의 **Build IPA from your own Spotify IPA**에서 이 브랜치를 선택하고
**enable_wireguard**를 켜도 됩니다. 파이프라인은 입력 IPA의 버전·UUID·암호화·클래스/선택자를
`scripts/spotify-transport-scan.py`로 확인한 다음 기존 플래그 추출과 빌드를 진행합니다.
검증되지 않은 다른 IPA는 입력 검사에서 중단됩니다. 완성된 IPA는 사용자의 인증서로 재서명해야 합니다.

트윅만 빌드할 때는 먼저 실제 IPA로 `make flags IPA=...`를 실행합니다.

```sh
THEOS=/path/to/theos gmake -C tweak package WIREGUARD=1
```

`PIXIE=1`은 기존의 독립적인 선택 옵션입니다. 이 변경은 Pixie의 패치 오프셋·검증 조건을 바꾸지 않습니다.
기준 9.1.90 UUID는 Pixie 조건과 일치하지만, 두 기능을 함께 쓰는 실제 다운로드는 별도 실기기 확인이 필요합니다.

## 사용

1. Mod Settings → 앱 내부 WireGuard·프록시.
2. `.conf`를 파일/클립보드로 가져오거나 외부 프록시 설정을 저장합니다.
3. 사용을 켜고 Spotify를 완전히 종료한 뒤 다시 엽니다.
4. 국가·출구 IP와 연결 진단을 확인합니다.
5. 캐시되지 않은 곡 재생, 탐색, 다음 곡, 잠금 화면 재생을 시험합니다.
6. 장애 직후 진단을 복사합니다. `spotify.received-bytes`, HTTP 상태, 터널 바이트와 핸드셰이크를 함께 확인합니다.

지원 프로필은 단일 `[Peer]`, IPv4 기본 경로 `AllowedIPs=0.0.0.0/0`, 숫자 IP의 DNS 서버가 있는
표준 WireGuard 설정입니다. 스크립트 필드는 거부합니다. 터널 대상의 DNS는 터널 안에서 조회하지만,
WireGuard Endpoint 자체가 호스트 이름이면 접속 전에 기기의 DNS를 사용합니다.

프로필과 프록시 비밀번호는 `Vitrine.WireGuard` Keychain 서비스에 기기 전용으로 저장합니다.
프로필 가져오기는 최대 64 KB이며 임시 복사본을 지웁니다. 클립보드에서 가져온 키도 지웁니다.
일반 설정은 `spotifyglass.wireguard`에 저장합니다. 진단은 요청 본문·URL·인증 헤더를 보관하지 않고
키·토큰·주소를 추가 마스킹합니다. 출구 IP 확인 화면에는 사용자가 요청한 전체 IP가 표시됩니다.

## 검증

```sh
(cd WireGuard && go mod verify && go test -race ./...)
python3 harness/wireguard/run_macos.py --out /tmp/wireguard-results.json # 저장소 루트에서 실행
harness/wireguard/build-settings.sh
scripts/check-layers.sh
python3 scripts/check-strings.py
```

- Go: 프로필 파서, 인증 SOCKS5/CONNECT, 실제 루프백 WireGuard 피어, DNS·HTTPS·206, 재연결, 정보 마스킹.
- macOS: 실제 Foundation/Network.framework로 터널과 외부 프록시를 통과하는 요청, 직접 연결로의 전환 차단,
  테스트 피어로의 네이티브 `getaddrinfo`·`connect`·`nw_connection_create` TCP 연결,
  죽은 피어·잘못된 설정·잘못된 비밀번호·신뢰할 수 없는 인증서 처리. Spotify delegate fixture의 전달과 ABI 검사.
- UIKit fixture: 실제 설정 화면/번역과 가짜 엔진 상태로 연결 종류 전환·비밀번호 보안 입력·다크 스타일 확인.
- iOS arm64: 실제 9.1.90에서 추출한 플래그 테이블로 전체 트윅 빌드.

**아직 실기기에서 입증하지 않은 항목:** 실제 Spotify 서버에서의 재생/로그인/다운로드,
Wi-Fi↔셀룰러 전환, 잠금 화면 장시간 재생, 다른 네트워크 경로의 우회 여부, 실제 WireGuard 제공자.
CI의 flag table은 빌드 검사 전용 fixture이며 CI의 트윅을 배포용으로 사용하지 않습니다.

원본과 라이선스: [WireGuard/UPSTREAM.md](../WireGuard/UPSTREAM.md).
