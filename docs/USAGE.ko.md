# SimpleSNIProxy — 사용자 및 개발자 가이드 (한국어)

> 영문판: [`USAGE.en.md`](USAGE.en.md)

작고 외부 의존성이 없는 Go 기반의 **투명 SNI / HTTP-Host 프록시** 입니다.
IPv6 / DNS64 / Happy Eyeballs 와 같은 최신 네트워킹 기능을 갖췄으며,
평문 SNI / HTTP-Host 검열을 우회하기 위한 DPI 회피 메커니즘이 내장되어
있습니다.

---

## 목차

1. [기능 개요](#기능-개요)
2. [동작 원리](#동작-원리)
3. [빠른 시작](#빠른-시작)
4. [전체 플래그 일람](#전체-플래그-일람)
5. [DPI 회피 / SNI 우회 메커니즘](#dpi-회피--sni-우회-메커니즘)
6. [IPv6, DNS64, 듀얼 스택](#ipv6-dns64-듀얼-스택)
7. [SSRF / 오픈 프록시 방지](#ssrf--오픈-프록시-방지)
8. [운영 시 주의사항](#운영-시-주의사항)
9. [아키텍처 및 코드 구성](#아키텍처-및-코드-구성)
10. [테스트](#테스트)
11. [문제 해결](#문제-해결)
12. [제약사항 및 위협 모델](#제약사항-및-위협-모델)
13. [라이선스 및 크레딧](#라이선스-및-크레딧)

---

## 기능 개요

클라이언트가 프록시로 TCP 연결을 열면:

* **HTTP 포트** (기본 `:80`) 에서는 요청 라인과 헤더를 파싱해 `Host:` 값을
  추출하고, 해당 호스트로 다이얼한 뒤 두 TCP 스트림을 양방향으로 중계합니다.
  필요하면 Host 헤더를 변형(case 랜덤화 + 공백)하고, 각 헤더를 별도 TCP
  세그먼트로 쪼개 보내 DPI 매칭을 회피합니다.
* **HTTPS 포트** (기본 `:443`) 에서는 TLS ClientHello 를 파싱해 SNI
  호스트네임을 얻고, 해당 호스트로 다이얼한 후 캡처한 ClientHello 를
  (옵션에 따라 SNI 호스트네임 한가운데서 잘라서) 다시 전송한 뒤 양방향
  중계합니다.

프록시는 TLS 를 복호화하지 않습니다. 평문 SNI / Host 만 보고 라우팅하는
순수 L4 터널입니다.

## 동작 원리

```
            ┌──────────────────────────────────────────────────────┐
            │                  SimpleSNIProxy                      │
 client ───►│  accept │ parse SNI/Host │ dial backend │ bridge     │───► origin
            │             ▲                  │                     │
            │             │                  ▼                     │
            │     우회용 변형:        SSRF 가드, IPv6+DNS64         │
            │     • TLS 프래그먼트    리졸버, Happy Eyeballs        │
            │     • Host 대소문자                                   │
            │     • 헤더라인별 분할                                 │
            └──────────────────────────────────────────────────────┘
```

* 백엔드 다이얼은 사용자 지정 리졸버를 사용하며, A 레코드만 있고 AAAA 가
  없으면 DNS64 `/96` 합성으로 IPv6 주소를 만들어 연결할 수 있습니다.
* 해석된 IP 는 SSRF 차단 목록과 비교됩니다. 사설/루프백/링크로컬/멀티캐스트/
  CGNAT/예약 영역은 기본적으로 거부합니다.
* 양방향 복사는 슬라이딩 아이들 타임아웃과 TCP half-close 를 사용해
  대용량 전송 도중 한쪽이 갑자기 종료되지 않도록 합니다.

## 빠른 시작

```sh
# 빌드
git clone https://github.com/ziozzang/SimpleSNIProxy
cd SimpleSNIProxy
go build -o sniproxy .

# 기본 포트(80/443) 실행 — root 또는 CAP_NET_BIND_SERVICE 필요
sudo ./sniproxy

# 테스트용 고포트
./sniproxy -http 8080 -https 8443
```

Docker:

```sh
docker build -t sniproxy .
docker run -d --name sniproxy --restart=always \
  -p 80:80 -p 443:443 sniproxy

# 사용자 지정 DNS + DNS64 (NAT64 환경의 IPv6-only 호스트)
docker run -d --name sniproxy \
  -p 80:80 -p 443:443 sniproxy \
  -dns 2606:4700:4700::1111 -dns64 64:ff9b::/96
```

OS DNS 변경 없이 동작 확인:

```sh
curl --resolve example.com:8443:127.0.0.1 \
     --resolve example.com:8080:127.0.0.1 \
     -v https://example.com:8443/
```

## 전체 플래그 일람

| 플래그 | 기본값 | 설명 |
|---|---|---|
| `-bind` | `::,0.0.0.0` | 콤마로 구분된 바인딩 주소. 듀얼 스택을 위해 IPv6/IPv4 리스너를 따로 생성합니다. |
| `-http` | `80` | HTTP 포트 (`0` = 비활성화). |
| `-https` | `443` | HTTPS/SNI 포트 (`0` = 비활성화). |
| `-dial-timeout` | `10s` | 백엔드 다이얼 총 타임아웃. |
| `-idle-timeout` | `5m` | 양방향 중계의 슬라이딩 아이들 타임아웃. |
| `-hello-timeout` | `10s` | 최초 Host 헤더 / ClientHello 읽기 데드라인. |
| `-dns` | *(시스템)* | 사용자 지정 DNS 서버. 예: `1.1.1.1`, `8.8.8.8:53`, `2606:4700:4700::1111`. |
| `-dns64` | *(끔)* | DNS64 NAT64 프리픽스. **`/96` 만 지원.** 예: `64:ff9b::/96`. |
| `-prefer-ipv6` | `true` | IPv6 주소를 IPv4 보다 먼저 시도. |
| `-happy-eyeballs-delay` | `250ms` | 다음 후보 주소 다이얼 시작 지연. |
| `-allow-private` | `false` | 사설/루프백/링크로컬 등 차단 주소로의 프록시 허용. **위험 — SSRF 섹션 참조.** |
| `-tls-frag` | `true` | 캡처한 TLS ClientHello 를 여러 TCP write 로 쪼개 전송. |
| `-tls-frag-offset` | `0` | 분할 바이트 오프셋. `0` 이면 SNI 호스트네임 한가운데에서 분할. |
| `-tls-frag-delay` | `5ms` | TLS 프래그먼트 간 지연. |
| `-http-mutate-host` | `true` | `Host` 헤더 이름의 대소문자를 랜덤화하고 콜론 뒤 공백을 늘림. |
| `-http-frag` | `true` | 요청 라인 / 헤더를 한 줄씩 별도 write 로 전송. |
| `-http-frag-delay` | `5ms` | HTTP 프래그먼트 간 지연. |
| `-v` | `false` | 디버그 로그. |

## DPI 회피 / SNI 우회 메커니즘

평문 SNI 는 검열의 가장 쉬운 표적입니다. 단순한 DPI 장비 대다수는 흐름의
첫 패킷에서 호스트네임 문자열을 한 세그먼트 안에서 찾습니다. 본 프록시는
이 두 가정을 깨뜨립니다.

1. **호스트네임이 한 패킷 안에 연속으로 존재한다** → 여러 write 로 분할.
2. **호스트네임이 알려진 고정 오프셋에 있다** → 호스트네임 자체의 한가운데서
   분할.

### TLS 프래그먼트

파싱 후 프록시는 캡처한 ClientHello 안에서 SNI 호스트네임이 시작하는
정확한 바이트 오프셋을 알고 있습니다. 기본 동작은 `HostnameStart +
HostnameLen/2` 위치에서 두 번의 `Write()` 호출로 나눕니다:

```
[ TLS 헤더 ][ ClientHello … server_name="exam │ ple.com" … ]
   ─────── write #1 ───────                   ── write #2 ──
```

`TCP_NODELAY` 와 `-tls-frag-delay` 의 짧은 지연이 결합되면 두 페이로드는
일반적으로 서로 다른 TCP 세그먼트로 전송됩니다. 단일 패킷 패턴 매칭에
의존하는 DPI 는 완전한 호스트네임을 보지 못합니다.

`-tls-frag-offset N` 으로 임의 위치에서 자를 수도 있습니다 (캡처된 레코드
시작점 기준 바이트 오프셋). 검열 장비가 고정된 prefix 만 본다는 사실이
알려진 경우 유용합니다.

### HTTP Host 변형

* **헤더 이름 대소문자 랜덤화**: `Host:` → 예) `hOSt:`. RFC 9110 에 따라
  헤더 이름은 대소문자 구분이 없으므로 모든 표준 준수 서버가 받아들입니다.
* **콜론 뒤 공백 추가** (RFC 가 허용하는 OWS).
* **줄 단위 분할 전송**: 요청 라인 / 각 헤더 / 종료 빈 줄을 각각 별도
  `Write()` 로 보내고, 사이에 `-http-frag-delay` 만큼 대기합니다.

### 본 프록시가 **막을 수 없는** 검열

* TCP 스트림 재조립을 수행하는 고급 DPI 는 어차피 전체 핸드셰이크/요청을
  볼 수 있으므로 본 도구의 회피가 통하지 않습니다.
* `GET http://example.com/...` 형태의 **absolute-form** HTTP 요청 라인은
  Host 가 변형되어도 요청 라인 자체에서 호스트네임이 노출됩니다 (이 도구는
  요청 라인을 다시 쓰지 않습니다).
* **Encrypted ClientHello (ECH)** 는 평문 SNI 자체가 없으므로 라우팅이
  불가능합니다. 해당 흐름은 로그를 남기고 깨끗하게 종료됩니다.
* TLS 레코드 재인코딩이나 ClientHello 패딩은 수행하지 않습니다.

## IPv6, DNS64, 듀얼 스택

### 듀얼 스택 리스닝

`-bind ::,0.0.0.0` 은 OS 의 V6ONLY 기본값에 의존하지 않고 명시적으로 두
개의 리스너를 만듭니다 (`tcp6` 의 `[::]`, `tcp4` 의 `0.0.0.0`). Linux,
macOS, BSD, Windows 어디서든 동일하게 동작합니다.

IPv6 만: `-bind ::`. IPv4 만: `-bind 0.0.0.0`.

### 사용자 지정 리졸버

`-dns 1.1.1.1` (또는 `[2606:4700:4700::1111]:53` 등) 을 주면 해당 서버로
직접 질의하는 `*net.Resolver{PreferGo:true}` 가 설치됩니다. IPv6 리터럴은
자동으로 대괄호로 감싸지고, 포트가 빠지면 `53` 이 추가됩니다.

### DNS64 합성 (`-dns64 64:ff9b::/96`)

리졸버는 매번 A 와 AAAA 를 모두 조회합니다. AAAA 가 비어 있고 A 만 있는
경우 `/96` DNS64 프리픽스가 설정되어 있으면 RFC 6052 에 따라 IPv4 32 비트를
프리픽스의 하위 32 비트에 끼워넣어 AAAA 를 합성합니다. 이로써 IPv6-only
호스트가 NAT64 게이트웨이를 통해 IPv4-only 오리진에 도달할 수 있습니다.
OS 차원의 DNS64 리졸버를 별도 구성하지 않아도 됩니다.

`/96` 외의 프리픽스 길이는 **시작 시점에 거부**합니다.

### Happy Eyeballs

여러 주소가 반환되면 선호 순서대로 다이얼을 시작하되, 각 시도는
`-happy-eyeballs-delay` 만큼 시차를 두고 동시에 진행됩니다. 첫 성공이
승리하고 나머지는 취소됩니다. 따라서 IPv6 가 black-hole 인 환경에서도
지연 없이 동작하며 IPv6 우선 정책을 유지할 수 있습니다.

## SSRF / 오픈 프록시 방지

프록시는 클라이언트가 보낸 호스트네임을 그대로 따라가기 때문에, 보호 없이
공개망에 노출하면 LAN 내부 자원을 노리는 SSRF 의 발판이 됩니다. 본 도구는
DNS 해석 후 모든 후보 IP 를 다음 목록과 비교합니다:

* loopback (`127.0.0.0/8`, `::1`)
* unspecified (`0.0.0.0`, `::`)
* private (`10/8`, `172.16/12`, `192.168/16`, `fc00::/7`)
* link-local (`169.254/16`, `fe80::/10`)
* multicast (`224/4`, `ff00::/8`)
* CGNAT (`100.64/10`)
* benchmark (`198.18/15`)
* 문서용 (`192.0.2/24`, `198.51.100/24`, `203.0.113/24`)
* 프로토콜 할당 (`192.0.0/24`)
* 예약 (`240/4`)

해석된 모든 주소가 차단 대상이면 다이얼이 실패하고 요청은 폐기됩니다.
신뢰된 사내 환경 등에서 의도적으로 우회하려면 `-allow-private` 을 켭니다.

## 운영 시 주의사항

* 1024 이하 포트를 바인딩하려면 root 또는 Linux 의 `setcap
  cap_net_bind_service=+ep ./sniproxy` 가 필요합니다.
* 기본 Docker 이미지는 `nonroot` 사용자로 실행됩니다. 호스트 포트로
  매핑(`-p 80:80`)하거나 앞단에 별도의 리버스 프록시를 둡니다.
* 로그는 `log/slog` 의 텍스트 포맷으로 stderr 에 출력됩니다.
* SIGINT/SIGTERM 시 우아한 종료가 진행됩니다. 리스너가 닫히고 진행 중인
  연결은 최대 10 초 안에 정리됩니다.
* 단일 연결의 오류로 데몬이 죽지 않습니다 (이전 버전의 `log.Fatal` 은
  모두 제거됨).

## 아키텍처 및 코드 구성

```
main.go        진입점, 리스너 와이어링, 우아한 종료
config.go      플래그 정의 및 검증
dial.go        리졸버, DNS64 /96 합성, Happy Eyeballs, SSRF 필터
tls.go         경계 검사된 ClientHello 파서 + 프래그먼트 라이터
proxy.go       HTTP / HTTPS 핸들러, Host 헤더 변형
pipe.go        슬라이딩 아이들 타임아웃 + half-close 양방향 복사
proxy_test.go  단위 + E2E 테스트
```

각 파일은 작은 타입 인터페이스(`Config`, `Dialer`, `Proxy`,
`ClientHello`)로만 결합되어 있어 독립적으로 이해할 수 있습니다.

## 테스트

```sh
go test ./...
go test -v -run TestEndToEnd ./...
go test -race ./...
```

테스트가 검증하는 항목:

* TLS ClientHello 파서: SNI 추출, 호스트네임 오프셋 계산, 비-TLS 와
  잘린 레코드 거부. 실제 ClientHello 는 `crypto/tls` 가 `net.Pipe` 위에
  생성한 바이트를 그대로 캡처해 파서에 다시 먹입니다.
* `WriteFragmented` 가 와이어 상에서 실제로 두 번의 read 로 나뉘어 도착함.
* `mutateHostHeader` 결과가 여전히 `Host:` 로 파싱되며 값은 동일하지만
  바이트열 자체는 달라짐.
* DNS64 합성 산수 (`64:ff9b::/96` + `192.0.2.33` → `64:ff9b::c000:221`).
* SSRF 가드: 14개 대표 주소에 대한 허용/차단 판정.
* DNS 서버 문자열 정규화 (IPv4 / IPv6 / 포트 유무).
* `PipeConns` 의 양방향 복사 + TCP half-close.
* 실제 백엔드를 띄워 HTTP 를 프록시 통과시키는 E2E 테스트: 백엔드가 받은
  바이트에서 Host 헤더가 실제로 변형되었지만 의미적으로 유효함을 검증.
* `Host: 127.0.0.1` 요청이 SSRF 가드에 의해 차단되어 응답이 없음을 검증.

## 문제 해결

| 증상 | 원인 |
|---|---|
| `:80`/`:443` 에서 `bind: permission denied` | root 또는 `CAP_NET_BIND_SERVICE` 필요. |
| `bind: address already in use` | 이미 다른 HTTP/HTTPS 서버가 그 포트를 사용 중. |
| `dial backend failed: … private/special; refusing` | 백엔드가 차단 영역으로 해석됨. 의도적이라면 `-allow-private`. |
| `no SNI in ClientHello (ECH or anonymous?)` | 클라이언트가 ECH 사용 또는 SNI 미포함 — 라우팅 불가. |
| 실 검열 환경에서 우회가 안 됨 | `TCP_NODELAY` 가 적용되는 환경인지 확인 (앞단 터널이 세그먼트를 합치지 않는지). 필요하면 `-tls-frag-delay` 를 `30ms` 정도로 늘려 보세요. |

## 제약사항 및 위협 모델

* **DPI 회피는 best-effort 입니다.** TCP 스트림을 재조립하는 고급 검열에는
  통하지 않습니다. 본 도구는 단일 패킷 매칭형 검열을 가정합니다.
* **평문 SNI 가 필요합니다.** ECH 는 라우팅할 수 없습니다.
* **클라이언트 인증이 없습니다.** 방화벽 / ACL / 인증 프록시를 앞에 두세요.
* **TLS 바이트는 변경 없이 그대로 전달**됩니다. 본 프록시는 평문 애플리케이션
  데이터를 절대 보지 않습니다.
* **단일 TLS 레코드** 안에 ClientHello 가 모두 들어 있어야 합니다 (실제
  세계의 모든 클라이언트가 그렇게 동작합니다).

## 라이선스 및 크레딧

* 원본 SNI 파서: Giles Thomas 의
  [`stupid-proxy`](https://github.com/gpjt/stupid-proxy/) 기반.
* 원본 SimpleSNIProxy: Jioh L. Jung (`ziozzang@gmail.com`).
* 라이선스: [`LICENSE`](../LICENSE) 참고.
