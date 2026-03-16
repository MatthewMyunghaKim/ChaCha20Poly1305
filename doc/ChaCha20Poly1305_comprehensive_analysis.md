# ChaCha20-Poly1305 AEAD 하드웨어 구현 종합 분석 문서

## 문서 정보

| 항목 | 내용 |
|------|------|
| 프로젝트명 | ChaCha20-Poly1305 AEAD FPGA 구현 |
| 저작권 | 2023 BrightAI BV |
| 라이선스 | BSD 3-Clause License |
| 대상 플랫폼 | FPGA (Xilinx 계열 최적화) |
| 준거 표준 | RFC 7539 (IETF ChaCha20-Poly1305) |
| 호환 프로토콜 | WireGuard VPN |

---

## 목차

1. [개요](#1-개요)
2. [저장소 구조](#2-저장소-구조)
3. [전체 아키텍처](#3-전체-아키텍처)
4. [패키지 정의 및 데이터 타입](#4-패키지-정의-및-데이터-타입)
5. [ChaCha20 암호화 엔진](#5-chacha20-암호화-엔진)
6. [Poly1305 MAC 구현](#6-poly1305-mac-구현)
7. [곱셈기 및 모듈러 리덕션](#7-곱셈기-및-모듈러-리덕션)
8. [AEAD 래퍼 및 최상위 인터페이스](#8-aead-래퍼-및-최상위-인터페이스)
9. [암호화/복호화 데이터 흐름](#9-암호화복호화-데이터-흐름)
10. [WireGuard 통합](#10-wireguard-통합)
11. [파이프라인 지연 및 처리량 분석](#11-파이프라인-지연-및-처리량-분석)
12. [DSP 최적화 구현 (src_dsp_opt)](#12-dsp-최적화-구현-src_dsp_opt)
13. [검증 및 테스트벤치](#13-검증-및-테스트벤치)
14. [바이트 순서 및 데이터 정렬](#14-바이트-순서-및-데이터-정렬)
15. [상태 머신 및 제어 로직](#15-상태-머신-및-제어-로직)
16. [모듈 인스턴스화 계층 구조](#16-모듈-인스턴스화-계층-구조)
17. [자원 사용량 추정](#17-자원-사용량-추정)
18. [설계 결정 사항 및 최적화 기법](#18-설계-결정-사항-및-최적화-기법)
19. [표준 준수 사항](#19-표준-준수-사항)
20. [최근 변경 이력](#20-최근-변경-이력)

---

## 1. 개요

본 저장소는 **ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data)** 암호화 알고리즘의 완전한 하드웨어 구현체를 포함하고 있다. VHDL로 작성되었으며, FPGA 타깃 구현을 목표로 설계되었다.

### 1.1 설계 목표

- **RFC 7539** 표준을 충실히 따르는 ChaCha20-Poly1305 AEAD 하드웨어 구현
- **WireGuard VPN** 프로토콜과의 호환성 확보
- **AXI Stream** 프로토콜 기반 128비트 데이터 스트리밍 인터페이스 제공
- **완전 파이프라인 설계**를 통한 고처리량 (High Throughput) 달성
- 암호화(Encryption)와 복호화(Decryption) 모두 지원
- MAC(Message Authentication Code) 태그 생성 및 검증 기능 포함

### 1.2 주요 특징

| 특징 | 상세 |
|------|------|
| 데이터 폭 | 128비트 (AXI Stream) |
| 키 크기 | 256비트 |
| 논스(Nonce) 크기 | 96비트 |
| 카운터 크기 | 32비트 |
| MAC 태그 크기 | 128비트 |
| 파이프라인 깊이 | 165+ 클럭 사이클 |
| 정상 상태 처리량 | 128비트/클럭 (초기 지연 이후) |
| 구현 버전 | 기본(src/) 및 DSP 최적화(src_dsp_opt/) |

### 1.3 동작 원리 요약

**암호화 경로:**
- ChaCha20이 256비트 키, 96비트 논스, 32비트 카운터로부터 키스트림(Keystream)을 생성
- 평문(Plaintext)과 키스트림의 XOR 연산으로 암호문(Ciphertext) 생성
- ChaCha20의 첫 번째 블록(카운터=0)에서 Poly1305용 r, s 값 추출
- Poly1305가 암호문에 대한 128비트 MAC 태그 생성

**복호화 경로:**
- 동일한 키스트림 생성 후 암호문과 XOR하여 평문 복원
- 수신된 MAC 태그와 계산된 태그 비교로 무결성 검증

---

## 2. 저장소 구조

```
ChaCha20Poly1305/
├── LICENSE                          # BSD 3-Clause 라이선스
├── .gitlab-ci.yml                   # CI/CD 설정 (GHDL 테스트)
├── .gitignore                       # VHDL/시뮬레이션 산출물 제외
│
├── src/                             # 기본(Baseline) 구현
│   ├── AEAD_ChaCha_Poly.vhd         # AEAD 코어 엔진 (ChaCha20 + Poly1305 통합)
│   ├── AEAD_encryption_wrapper.vhd  # 암호화 최상위 래퍼
│   ├── AEAD_decryption_wrapper.vhd  # 복호화 최상위 래퍼
│   ├── AEAD_decryption.vhd          # 복호화 코어 (태그 검증 포함)
│   ├── ChaCha20.vhd                 # ChaCha20 기본 (비파이프라인)
│   ├── ChaCha20_128.vhd             # ChaCha20 128비트 스트리밍 버전
│   ├── ChaCha_int.vhd               # ChaCha20 내부 파이프라인
│   ├── half_round.vhd               # 하프 라운드 (컬럼+대각선)
│   ├── col_round.vhd                # 컬럼 라운드 (4개 병렬 QR)
│   ├── diag_round.vhd               # 대각선 라운드 (4개 병렬 QR)
│   ├── q_round.vhd                  # 쿼터 라운드 (기본 연산 단위)
│   ├── Poly1305.vhd                 # Poly1305 MAC 기본 구현
│   ├── Poly_1305_pipe.vhd           # Poly1305 파이프라인 누적기
│   ├── Poly_1305_pipe_top.vhd       # Poly1305 파이프라인 최상위
│   ├── r_power_n.vhd                # r^n mod p 연산
│   ├── mul_136.vhd                  # 136비트 곱셈기
│   ├── mul_144.vhd                  # 136×136→272비트 곱셈기
│   ├── mul_72.vhd                   # 68×68→136비트 곱셈기
│   ├── mul_36.vhd                   # 34×34→68비트 곱셈기
│   ├── mult_gen_0.vhd               # 17×17→34비트 원시 곱셈기
│   ├── mul136_mod_red.vhd           # 곱셈 + 모듈러 리덕션
│   ├── mul_red_pipeline.vhd         # 다중 블록 곱셈 파이프라인
│   ├── mod_red_1305.vhd             # mod 2^130-5 리덕션
│   ├── WG_header_adder.vhd          # WireGuard 헤더 삽입
│   └── bus_pkg.vhd                  # 기본 패키지 (타입 정의)
│
├── src_dsp_opt/                     # DSP 최적화 구현 (_kar 접미사)
│   ├── AEAD_encryptor_kar.vhd       # 최적화된 AEAD 코어
│   ├── AEAD_encryption_wrapper_kar.vhd  # 최적화된 암호화 래퍼
│   ├── AEAD_decryption_wrapper_kar.vhd  # 최적화된 복호화 래퍼
│   ├── AEAD_decryption_kar.vhd      # 최적화된 복호화 코어
│   ├── Poly_1305_pipe_kar.vhd       # 최적화된 Poly1305 파이프라인
│   ├── Poly_1305_pipe_top_kar.vhd   # 최적화된 Poly1305 최상위
│   ├── r_pow_n_kar.vhd              # 최적화된 r^n 연산
│   ├── mul_136_kar.vhd              # 최적화된 136비트 곱셈기
│   ├── mul_68_kar.vhd               # 최적화된 68비트 곱셈기
│   └── bus_pkg1.vhd                 # 확장 패키지 (추가 타입 정의)
│
└── cocotb/                          # 테스트벤치 (cocotb 프레임워크)
    ├── AEAD_encryption_wrapper/     # 암호화 테스트
    │   ├── test_AEAD_encryption_wrapper.py
    │   ├── test_AEAD_encryption_wrapper_kar.py
    │   ├── Makefile
    │   └── README.md
    ├── AEAD_decryption_wrapper/     # 복호화 테스트
    │   ├── test_AEAD_decryption_wrapper.py
    │   ├── test_AEAD_decryption_wrapper_kar.py
    │   └── Makefile
    ├── ChaCha20_Poly1305_enc_dec.py # 참조 구현 (PyCryptodome)
    ├── BitMonitor.py                # 신호 레벨 모니터링
    └── AxiStreamClockedMonitor.py   # AXI Stream 프로토콜 모니터링
```

---

## 3. 전체 아키텍처

### 3.1 최상위 블록 다이어그램

```
┌─────────────────────────────────────────────────────────────────────┐
│                  AEAD_encryption_wrapper / AEAD_decryption_wrapper  │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                    AEAD_ChaCha_Poly                           │  │
│  │                                                               │  │
│  │  ┌─────────────────────┐    ┌──────────────────────────────┐ │  │
│  │  │    ChaCha20_128     │    │     Poly_1305_pipe_top       │ │  │
│  │  │                     │    │                              │ │  │
│  │  │  Key (256b) ────┐   │    │  ┌──────────┐               │ │  │
│  │  │  Nonce (96b) ───┤   │    │  │r_power_n │               │ │  │
│  │  │  Counter (32b) ─┤   │    │  │  r^n 계산 │               │ │  │
│  │  │                 ▼   │    │  └────┬─────┘               │ │  │
│  │  │  ┌───────────────┐  │    │       ▼                      │ │  │
│  │  │  │  ChaCha_int   │  │    │  ┌──────────────────┐       │ │  │
│  │  │  │  (10 라운드)   │  │    │  │ Poly_1305_pipe   │       │ │  │
│  │  │  │               │  │    │  │ (누적+태그 계산)   │       │ │  │
│  │  │  │  half_round×10│  │    │  └────────┬─────────┘       │ │  │
│  │  │  └───────┬───────┘  │    │           │                  │ │  │
│  │  │          │          │    │           ▼                  │ │  │
│  │  │   Keystream 출력 ───┼────┼──→ MAC 태그 (128b)          │ │  │
│  │  │   r, s 출력 ────────┼────┼──→ 인증 매개변수             │ │  │
│  │  └─────────────────────┘    └──────────────────────────────┘ │  │
│  │                                                               │  │
│  │  Plaintext ──XOR──→ Ciphertext                               │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
│  ┌───────────────────────┐                                         │
│  │  WG_header_adder      │  ← WireGuard 헤더 삽입 (선택사항)       │
│  └───────────────────────┘                                         │
└─────────────────────────────────────────────────────────────────────┘
```

### 3.2 AXI Stream 프로토콜

본 설계는 **AXI Stream** 프로토콜을 채택하여 128비트 데이터 스트리밍을 지원한다:

| 신호 | 폭 | 방향 | 설명 |
|------|----|------|------|
| `tdata` | 128비트 | 소스→싱크 | 데이터 페이로드 (16바이트, ChaCha20 블록의 1/4) |
| `tvalid` | 1비트 | 소스→싱크 | 데이터 유효 표시 |
| `tlast` | 1비트 | 소스→싱크 | 패킷의 마지막 데이터 표시 |
| `tready` | 1비트 | 싱크→소스 | 다운스트림 준비 완료 표시 |

**핸드셰이킹 규칙:**
- 데이터 전송은 `tvalid = 1` **그리고** `tready = 1`일 때만 발생
- `tlast = 1`로 현재 패킷의 마지막 전송을 표시
- 본 설계에서 `tready`는 항상 `1`로 설정 (배압 없음)

### 3.3 암호화 데이터 흐름

```
입력: 평문(128b), 키(256b), 논스(96b), n_in(7b)

[파이프라인 스테이지 0]
  │
  ▼
ChaCha20_128: 키스트림 및 r,s 값 생성
  입력: 키, 논스, 카운터
  출력: r_out, s_out, keystream_out
  지연: 79 클럭
  │
  ▼
[파이프라인 스테이지 80]
  │
  ▼
XOR: 평문 ⊕ 키스트림 = 암호문
  지연: 1 클럭
  │
  ▼
[파이프라인 스테이지 81]
  │
  ▼
Poly_1305_pipe_top: MAC 태그 계산
  입력: 암호문 블록, r, s, n_in
  지연: 164 클럭
  │
  ▼
[파이프라인 스테이지 245]
  │
  ▼
출력: 암호문(ciphertext_out), 태그(tag_out)
```

### 3.4 복호화 데이터 흐름

```
입력: 암호문(128b) + MAC 태그(128b), 키(256b), 논스(96b)

[파이프라인 스테이지 0]
  │
  ▼
ChaCha20_128: 키스트림 생성 (암호화와 동일)
  │
  ▼
XOR: 암호문 ⊕ 키스트림 = 평문
  │
  ├─→ 평문 출력
  │
  ▼
Poly_1305_pipe_top: MAC 태그 계산
  │
  ▼
태그 비교: 계산된 태그 vs 수신된 태그
  │
  ├─→ tag_valid = 1: 인증 성공
  └─→ tag_valid = 0: 인증 실패 (데이터 변조 감지)
```

---

## 4. 패키지 정의 및 데이터 타입

### 4.1 bus_pkg1.vhd - 주요 패키지

설계 전반에서 사용되는 핵심 타입들을 정의한다:

#### 4.1.1 ChaCha20 상태 타입

```vhdl
type type_1 is array (0 to 15) of unsigned(31 downto 0);
```

- **용도:** ChaCha20의 512비트 상태를 표현 (16개의 32비트 워드)
- **구성:** 상수(4워드) + 키(8워드) + 카운터(1워드) + 논스(3워드)
- **사용처:** `ChaCha20_128`, `ChaCha_int`, `q_round` 등 모든 ChaCha20 관련 모듈

#### 4.1.2 시프트 레지스터 타입

```vhdl
type type_shreg_ciptext is array (277 downto 0) of unsigned(127 downto 0);
-- 278개의 128비트 워드를 저장하는 시프트 레지스터
-- Poly1305 처리를 위한 암호문 버퍼링에 사용

type type_shreg_plaintext is array (199 downto 0) of unsigned(127 downto 0);
-- 200개의 128비트 워드를 저장하는 시프트 레지스터
-- 복호화된 평문 저장에 사용

type type_shreg_S_poly_top is array (164 downto 0) of unsigned(127 downto 0);
-- 165클럭 지연 라인: Poly1305 키 's' 파라미터용
-- 깊은 파이프라인의 s 값 동기화에 필수

type type_shreg_blck_poly_top is array (164 downto 0) of unsigned(128 downto 0);
-- 165클럭 지연 라인: Poly1305 암호문 블록용
-- 129비트 = 128비트 데이터 + 1비트 제어 플래그

type type_shreg_n_cnt_aead is array (81 downto 0) of unsigned(6 downto 0);
-- 82클럭 시프트 레지스터: 블록 카운트용 (최대 93블록, RFC 7539 제한)

type type_shreg_tvalid_aead is array (83 downto 0) of STD_LOGIC;
type type_shreg_tlast_aead is array (83 downto 0) of STD_LOGIC;
-- 제어 신호 지연 라인
```

**설계 의도:** 165클럭에 달하는 시프트 레지스터는 Poly1305 파이프라인의 깊은 지연을 보상하기 위한 것이다. 각 데이터와 제어 신호가 올바른 타이밍에 도착하도록 보장한다.

---

## 5. ChaCha20 암호화 엔진

### 5.1 ChaCha20 알고리즘 개요

ChaCha20은 Daniel J. Bernstein이 설계한 스트림 암호로, 다음과 같은 특성을 가진다:

- **상태:** 512비트 (16 × 32비트 워드)
- **라운드:** 20라운드 (10 더블 라운드)
- **키 크기:** 256비트
- **논스 크기:** 96비트
- **카운터:** 32비트

**초기 상태 매트릭스:**

```
┌──────────┬──────────┬──────────┬──────────┐
│ 0x61707865│ 0x3320646e│ 0x79622d32│ 0x6b206574│  ← 상수 ("expand 32-byte k")
├──────────┼──────────┼──────────┼──────────┤
│  Key[0]  │  Key[1]  │  Key[2]  │  Key[3]  │  ← 256비트 키 (상위)
├──────────┼──────────┼──────────┼──────────┤
│  Key[4]  │  Key[5]  │  Key[6]  │  Key[7]  │  ← 256비트 키 (하위)
├──────────┼──────────┼──────────┼──────────┤
│ Counter  │ Nonce[0] │ Nonce[1] │ Nonce[2] │  ← 카운터 + 96비트 논스
└──────────┴──────────┴──────────┴──────────┘
```

### 5.2 ChaCha20_128.vhd - 128비트 스트리밍 버전

AXI Stream 인터페이스에 최적화된 주력 구현체이다.

#### 5.2.1 포트 정의

```vhdl
entity ChaCha20_128 is
port(
    clk               : in  STD_LOGIC;                      -- 시스템 클럭
    axi_tdata_in      : in  unsigned(127 downto 0);         -- 128비트 평문 입력
    axi_tvalid_in     : in  STD_LOGIC;                      -- 입력 유효
    axi_tlast_in      : in  STD_LOGIC;                      -- 입력 마지막 블록
    axi_tdata_in_key  : in  unsigned(255 downto 0);         -- 256비트 키
    axi_tdata_in_nonce: in  unsigned(95 downto 0);          -- 96비트 논스
    axi_tlast_in_nonce: in  STD_LOGIC;                      -- 논스 입력 완료
    counter_in        : in  unsigned(31 downto 0);          -- 32비트 카운터
    axi_tdata_out     : out unsigned(127 downto 0);         -- 128비트 암호문 출력
    axi_tvalid_out    : out STD_LOGIC;                      -- 출력 유효
    axi_tlast_out     : out STD_LOGIC;                      -- 출력 마지막 블록
    r_out             : out unsigned(127 downto 0);         -- Poly1305 r 파라미터
    s_out             : out unsigned(127 downto 0);         -- Poly1305 s 파라미터
    r_valid           : out STD_LOGIC                       -- r,s 유효
);
end entity;
```

#### 5.2.2 초기 상태 설정 (조합 로직)

```vhdl
input(0)  <= x"61707865";                                    -- 상수
input(1)  <= x"3320646e";                                    -- 상수
input(2)  <= x"79622d32";                                    -- 상수
input(3)  <= x"6b206574";                                    -- 상수
input(4)  <= order(axi_tdata_in_key(255 downto 224));       -- 키 워드 0 (바이트 역순)
input(5)  <= order(axi_tdata_in_key(223 downto 192));       -- 키 워드 1
...
input(11) <= order(axi_tdata_in_key(31 downto 0));          -- 키 워드 7
input(12) <= counter_in;                                     -- 카운터
input(13) <= order(axi_tdata_in_nonce(95 downto 64));       -- 논스 워드 0
input(14) <= order(axi_tdata_in_nonce(63 downto 32));       -- 논스 워드 1
input(15) <= order(axi_tdata_in_nonce(31 downto 0));        -- 논스 워드 2
```

#### 5.2.3 키스트림 생성 및 XOR

```vhdl
-- ChaCha20 내부 파이프라인 인스턴스화
u1: ChaCha_int port map(clk, input, key_output);

-- 키스트림 출력 (79클럭 지연 후)
-- 4개의 128비트 청크로 512비트 키스트림을 순차 출력
axi_tdata_out <= plaintext_shreg(81) XOR keystream_128bit;
```

#### 5.2.4 카운터 관리

```vhdl
process(clk)
begin
    if rising_edge(clk) then
        if axi_tlast_in_nonce = '1' then
            counter1 <= x"00000001";   -- 메시지 시작 시 카운터 1로 초기화
            cnt_valid <= 0;
        elsif axi_tvalid_in = '1' then
            if cnt_valid = 3 then
                counter1 <= counter1 + 1;  -- 4번째 128비트 전송마다 카운터 증가
                cnt_valid <= 0;            -- (512비트 = 1 ChaCha20 블록 완성)
            else
                cnt_valid <= cnt_valid + 1;
            end if;
        end if;
    end if;
end process;
```

**설명:** ChaCha20은 512비트(64바이트) 블록 단위로 키스트림을 생성한다. 128비트 AXI Stream 인터페이스에서는 4번의 전송이 하나의 ChaCha20 블록을 구성하므로, 매 4번째 전송마다 카운터를 1 증가시킨다.

#### 5.2.5 r, s 값 추출

```vhdl
r_out <= key_output(0) & key_output(1) & key_output(2) & key_output(3);
s_out <= key_output(4) & key_output(5) & key_output(6) & key_output(7);
```

- **r:** ChaCha20 첫 번째 블록(카운터=0)의 처음 128비트
- **s:** ChaCha20 첫 번째 블록(카운터=0)의 다음 128비트
- 이 값들은 Poly1305 MAC 계산에 사용되며, **r은 클램핑(clamping)** 처리 후 사용

### 5.3 ChaCha_int.vhd - 내부 파이프라인

ChaCha20의 핵심 암호화 파이프라인으로, 10개의 하프 라운드를 직렬로 연결한다.

#### 5.3.1 구조

```
입력(512비트) → [하프라운드 0] → [하프라운드 1] → ... → [하프라운드 9] → 출력(512비트)
                   ↑                                          ↑
              컬럼+대각선                                 컬럼+대각선
              4클럭/라운드                               4클럭/라운드
```

#### 5.3.2 파이프라인 깊이

- 각 하프 라운드 = 컬럼 라운드(4클럭) + 대각선 라운드(4클럭) = **8클럭**
- 그러나 q_round 내부에서 4스테이지로 구현되므로
- **총 파이프라인: 10 하프라운드 × 8클럭 = 80클럭** (정확한 값은 구현에 따라 약간 상이)

### 5.4 q_round.vhd - 쿼터 라운드

ChaCha20의 기본 연산 단위로, 4개의 32비트 워드(a, b, c, d)에 대해 작동한다.

#### 5.4.1 알고리즘

```
스테이지 1: a ← a + b;   d ← (d ⊕ a) <<< 16
스테이지 2: c ← c + d;   b ← (b ⊕ c) <<< 12
스테이지 3: a ← a + b;   d ← (d ⊕ a) <<<  8
스테이지 4: c ← c + d;   b ← (b ⊕ c) <<<  7
```

#### 5.4.2 VHDL 파이프라인 구현

```vhdl
-- 스테이지 1
process(clk)
begin
    if rising_edge(clk) then
        a_1 <= a_in + b_in;
        b_1 <= b_in;
        c_1 <= c_in;
        d_1 <= rotate_left((d_in xor (a_in + b_in)), 16);
    end if;
end process;

-- 스테이지 2
process(clk)
begin
    if rising_edge(clk) then
        a_2 <= a_1;
        b_2 <= rotate_left((b_1 xor (c_1 + d_1)), 12);
        c_2 <= c_1 + d_1;
        d_2 <= d_1;
    end if;
end process;

-- 스테이지 3, 4도 동일한 패턴
```

**핵심:** 각 스테이지는 1클럭에 완료되며, 가산(+)과 XOR(⊕) 및 순환 시프트(<<<)만 사용한다. 곱셈이 없어 FPGA에서 매우 효율적이다.

### 5.5 col_round.vhd - 컬럼 라운드

4개의 독립적인 쿼터 라운드를 **병렬로** 실행한다:

```
컬럼 0: q_round(state[0],  state[4],  state[8],  state[12])
컬럼 1: q_round(state[1],  state[5],  state[9],  state[13])
컬럼 2: q_round(state[2],  state[6],  state[10], state[14])
컬럼 3: q_round(state[3],  state[7],  state[11], state[15])
```

### 5.6 diag_round.vhd - 대각선 라운드

4개의 독립적인 쿼터 라운드를 **병렬로** 실행한다:

```
대각선 0: q_round(state[0],  state[5],  state[10], state[15])
대각선 1: q_round(state[1],  state[6],  state[11], state[12])
대각선 2: q_round(state[2],  state[7],  state[8],  state[13])
대각선 3: q_round(state[3],  state[4],  state[9],  state[14])
```

### 5.7 half_round.vhd - 하프 라운드

컬럼 라운드와 대각선 라운드를 직렬로 연결한다:

```vhdl
u1: col_round  port map(clk, data_in,        data_col_diag);  -- 컬럼 라운드
u2: diag_round port map(clk, data_col_diag,   data_out);       -- 대각선 라운드
```

**지연:** 컬럼 라운드(4클럭) + 대각선 라운드(4클럭) = **8클럭**

---

## 6. Poly1305 MAC 구현

### 6.1 Poly1305 알고리즘 개요

Poly1305는 Daniel J. Bernstein이 설계한 일회용(One-time) 메시지 인증 코드이다.

**수학적 정의:**

```
tag = ((c₁ × r^n + c₂ × r^(n-1) + ... + cₙ × r¹) mod p) + s
```

여기서:
- **p = 2^130 - 5** (소수 모듈러스)
- **r:** 128비트 비밀 키 (클램핑 적용)
- **s:** 128비트 일회용 패드 (ChaCha20에서 생성)
- **cᵢ:** 16바이트 메시지 블록에 0x01을 추가한 129비트 값
- **n:** 메시지 블록 수

### 6.2 r 클램핑 (Clamping)

RFC 7539에 따라 r 값의 특정 비트를 마스킹한다:

```vhdl
r_ordered <= r AND x"0ffffffc0ffffffc0ffffffc0fffffff";
```

**클램핑 규칙:**
- r의 비트 [3:0], [7:4]의 상위 비트, [35:32]의 상위 비트 등을 0으로 마스킹
- 이는 보안 강화를 위한 RFC 7539의 필수 요구사항

### 6.3 Poly_1305_pipe_top.vhd - 최상위 파이프라인

#### 6.3.1 포트 정의

```vhdl
entity Poly_1305_pipe_top is
port(
    clk      : in  STD_LOGIC;
    Blck     : in  unsigned(128 downto 0);    -- 129비트 블록 (128b 데이터 + 1b 제어)
    r        : in  unsigned(127 downto 0);    -- 127비트 r 파라미터 (클램핑됨)
    s        : in  unsigned(127 downto 0);    -- 127비트 일회용 패드
    n_in     : in  unsigned(6 downto 0);      -- 6비트 블록 카운트 (최대 93)
    tvalid   : in  STD_LOGIC;                 -- 입력 유효
    tlast    : in  STD_LOGIC;                 -- 마지막 블록
    tag_out  : out unsigned(127 downto 0);    -- 128비트 MAC 태그 출력
    tag_valid: out STD_LOGIC                  -- 태그 유효
);
end entity;
```

#### 6.3.2 내부 구조

```
입력 (r, s, 블록, n)
     │
     ▼
┌──────────────┐
│  r_power_n   │  ← r^n mod p 사전 계산
│  (108+ 클럭)  │
└──────┬───────┘
       │ r^n
       ▼
┌──────────────────┐
│ Poly_1305_pipe   │  ← 파이프라인 누적
│ (26+ 클럭)        │
│                  │
│ acc = Σ(cᵢ×r^i) │
│ tag = acc + s    │
└──────┬───────────┘
       │
       ▼
   MAC 태그 출력 (128비트)
```

#### 6.3.3 처리 과정

```vhdl
process(clk)
begin
    if rising_edge(clk) then
        if tlast = '1' then
            first <= '1';           -- 다음 패킷을 위해 리셋
        else
            if first = '1' and tvalid = '1' then
                first <= '0';       -- 첫 블록 수신 시 n_in과 r 캡처
                n_cnt <= n_in;      -- 블록 카운터 초기화
                r_in_reg <= r;      -- r 값 레지스터에 저장
            end if;
        end if;

        -- 후속 블록마다 n_cnt 감소
        if tvalid = '1' and first = '0' then
            n_cnt <= n_cnt - 1;
        end if;
    end if;
end process;
```

#### 6.3.4 시프트 레지스터 지연

```vhdl
shreg_s (165 클럭):      s 값을 태그 가산 스테이지까지 지연
shreg_blck (165 클럭):   암호문 블록을 파이프라인 끝까지 지연
shreg_tvalid_top (165):  tvalid 제어 신호 전파
shreg_tlast_top (165):   tlast 제어 신호 전파
```

### 6.4 r_power_n.vhd - r^n mod p 연산

이진 거듭제곱법(Binary Exponentiation)을 사용하여 r의 거듭제곱을 효율적으로 계산한다.

#### 6.4.1 사전 계산

```
r¹  = r (클램핑된 원본)
r²  = r × r mod p
r⁴  = r² × r² mod p
r⁸  = r⁴ × r⁴ mod p
r¹⁶ = r⁸ × r⁸ mod p
r³² = r¹⁶ × r¹⁶ mod p
r⁶⁴ = r³² × r³² mod p
```

6개의 병렬 곱셈기가 각 r^(2^i) 값을 계산한다. 각 곱셈기는 `mul136_mod_red`를 사용하며 18클럭의 고정 지연을 가진다.

#### 6.4.2 이진 조합

n의 2진수 표현에 따라 적절한 거듭제곱을 선택하여 곱한다:

```vhdl
-- n의 각 비트에 따라 해당 거듭제곱 선택 또는 1 선택
if n_val(6) = '1' then pipe_A_in <= r64; else pipe_A_in <= 1; end if;
if n_val(5) = '1' then pipe_B_in <= r32; else pipe_B_in <= 1; end if;
if n_val(4) = '1' then pipe_C_in <= r16; else pipe_C_in <= 1; end if;
if n_val(3) = '1' then pipe_D_in <= r8;  else pipe_D_in <= 1; end if;
if n_val(2) = '1' then pipe_E_in <= r4;  else pipe_E_in <= 1; end if;
if n_val(1) = '1' then pipe_F_in <= r2;  else pipe_F_in <= 1; end if;

-- 최종 결과: r^n = 선택된 거듭제곱들의 곱
```

#### 6.4.3 시프트 레지스터

```vhdl
shreg_r1 (108 클럭):   r 값 지연
shreg_r2~r32 (가변):   r^(2^i) 값을 정렬 위해 지연
shreg_n (108 클럭):    n 값 지연
```

### 6.5 Poly_1305_pipe.vhd - 파이프라인 누적기

#### 6.5.1 핵심 연산

```
acc ← (acc + (block × r^n)) mod p
```

각 블록을 r^n과 곱한 후 누적기에 더한다. 모든 블록 처리 후 s를 더하여 최종 태그를 생성한다.

#### 6.5.2 누적 프로세스

```vhdl
process(clk)
begin
    if rising_edge(clk) then
        if shreg_tvalid(18) = '1' then
            if shreg_tlast(18) = '1' then
                acc <= (others => '0');  -- 패킷 종료 시 누적기 리셋
            else
                acc <= acc + mul_result;  -- block × r^n 결과 누적
            end if;
        end if;
    end if;
end process;
```

#### 6.5.3 최종 태그 계산

```vhdl
process(clk)
begin
    if rising_edge(clk) then
        if shreg_tlast(25) = '1' then
            -- 모듈러 리덕션 결과에 s를 더하여 최종 태그 생성
            tag <= (mod_red_out + shreg_s2(5)) mod 2^128;
            tag_valid <= '1';
        end if;
    end if;
end process;
```

---

## 7. 곱셈기 및 모듈러 리덕션

### 7.1 곱셈기 계층 구조

본 설계는 **카라추바(Karatsuba) 분해법**을 사용한 계층적 곱셈기 구조를 채택한다:

```
mul136_mod_red (136비트 곱셈 + 모듈러 리덕션)
  ├── mul_144 (136×136 → 272비트)
  │     ├── mul_72 (68×68 → 136비트) × 4 병렬
  │     │     ├── mul_36 (34×34 → 68비트) × 4 병렬
  │     │     │     └── mult_gen_0 (17×17 → 34비트) × 4 병렬
  │     │     └── 시프트/가산 로직
  │     └── 시프트/가산 로직
  └── mod_red_1305 (mod 2^130-5 리덕션)
```

### 7.2 mult_gen_0.vhd - 원시 곱셈기 (17×17)

FPGA의 네이티브 DSP 블록에 매핑되는 최하위 곱셈기:

```vhdl
-- 3-스테이지 파이프라인
process(CLK)
begin
    if rising_edge(CLK) then
        sum0 <= A * B;      -- 스테이지 1: 곱셈
        sum1 <= sum0;       -- 스테이지 2: 레지스터
        sum2 <= sum1;       -- 스테이지 3: 레지스터
        P <= sum2;          -- 출력
    end if;
end process;
```

- **입력:** A(17비트), B(17비트)
- **출력:** P(34비트)
- **지연:** 3클럭

### 7.3 mul_36.vhd - 34×34비트 곱셈기

카라추바 분해를 적용한 곱셈기:

```
A = A1 × 2^17 + A0  (34비트를 17비트 두 부분으로 분할)
B = B1 × 2^17 + B0

A × B = A1×B1 × 2^34 + (A0×B1 + A1×B0) × 2^17 + A0×B0
```

- 4개의 `mult_gen_0` 인스턴스를 **병렬로** 사용
- **지연:** 4클럭 (mult_gen_0 3클럭 + 재조합 1클럭)

### 7.4 mul_72.vhd - 68×68비트 곱셈기

동일한 카라추바 패턴:

```
A = A1 × 2^34 + A0  (68비트를 34비트 두 부분으로 분할)
B = B1 × 2^34 + B0

4개의 mul_36 인스턴스 병렬 사용
```

- **지연:** 6클럭

### 7.5 mul_144.vhd - 136×136비트 곱셈기

최상위 카라추바 곱셈기:

```
A = A1 × 2^68 + A0  (136비트를 68비트 두 부분으로 분할)
B = B1 × 2^68 + B0

4개의 mul_72 인스턴스 병렬 사용
```

- **입력:** 136비트 × 136비트
- **출력:** 272비트
- **지연:** 8클럭

### 7.6 총 곱셈기 지연

| 레벨 | 모듈 | 개별 지연 | 누적 지연 |
|------|------|-----------|-----------|
| 1 | mult_gen_0 (17×17) | 3클럭 | 3클럭 |
| 2 | mul_36 (34×34) | 1클럭 추가 | 4클럭 |
| 3 | mul_72 (68×68) | 2클럭 추가 | 6클럭 |
| 4 | mul_144 (136×136) | 2클럭 추가 | 8클럭 |

### 7.7 mod_red_1305.vhd - 모듈러 리덕션

**목적:** 261비트 곱셈 결과를 130비트로 축소 (mod 2^130 - 5)

**알고리즘 원리:**

```
p = 2^130 - 5 이므로:
x mod p ≡ x mod (2^130 - 5)

x = x_high × 2^130 + x_low 로 분할하면:
x mod p ≡ (x_high × 5 + x_low) mod p
  (왜냐하면 2^130 ≡ 5 (mod p))
```

#### 7.7.1 5-스테이지 파이프라인 구현

```vhdl
-- 스테이지 1: 상위 비트 추출
data_in_1 <= data_in(260 downto 130);          -- 상위 131비트
data_in_2 <= data_in(260 downto 130) & "00";   -- 상위 비트 × 4

-- 스테이지 2: 5배 계산 (×4 + ×1 = ×5)
A_1 <= data_in(129 downto 0);                  -- 하위 130비트
B_1 <= data_in_2 + data_in_1;                  -- 상위 × 5

-- 스테이지 3: 가산
A_2 <= B_1(129 downto 0);
B_2 <= B_1(134 downto 130) * 5;               -- 오버플로우 × 5

-- 스테이지 4: 최종 가산
A_3 <= A_2 + B_2;
B_3 <= A_3(130) * 5;                          -- 캐리 × 5

-- 스테이지 5: 결과
result <= A_3 + B_3;                           -- 최종 130비트 결과
```

- **지연:** 5클럭
- **핵심:** 2^130 ≡ 5 (mod p) 성질을 이용하여, 나눗셈 없이 곱셈과 가산만으로 리덕션 수행

### 7.8 mul136_mod_red.vhd - 곱셈+리덕션 결합

```vhdl
u1: mul_144    port map(clk, A_in, B_in, mul_result);   -- 8클럭
u2: mod_red_1305 port map(clk, mul_result, data_out);   -- 5클럭
-- 총 지연: 약 10~13클럭
```

### 7.9 mul_red_pipeline.vhd - 다중 블록 곱셈 파이프라인

3쌍의 곱셈을 캐스케이드하여 r^n 계산에 사용:

```
u1: A_in × B_in → u1_out         │
u2: C_in × D_in → u2_out         │ 병렬 실행
u3: E_in × F_in → u3_out         │

u4: u1_out × u2_out → u4_out     (u3_out은 시프트 레지스터로 지연)
u5: u4_out × shreg_u3 → 최종 출력
```

---

## 8. AEAD 래퍼 및 최상위 인터페이스

### 8.1 AEAD_ChaCha_Poly.vhd - AEAD 코어 엔진

ChaCha20과 Poly1305를 통합하는 핵심 엔진이다.

#### 8.1.1 포트 정의

```vhdl
entity AEAD_ChaCha_Poly is
port(
    clk                   : in  STD_LOGIC;
    axi_tdata_in_msg      : in  unsigned(127 downto 0);   -- 평문/암호문 데이터
    axi_tvalid_in_msg     : in  STD_LOGIC;                -- 데이터 유효
    axi_tlast_in_msg      : in  STD_LOGIC;                -- 마지막 데이터
    axi_tdata_in_key      : in  unsigned(255 downto 0);   -- 256비트 키
    axi_tdata_in_nonce    : in  unsigned(95 downto 0);    -- 96비트 논스
    axi_tlast_in_nonce    : in  STD_LOGIC;                -- 논스 완료 신호
    n_in                  : in  unsigned(6 downto 0);     -- 블록 카운트
    axi_tdata_out         : out unsigned(127 downto 0);   -- 출력 데이터
    axi_tvalid_out        : out STD_LOGIC;                -- 출력 유효
    axi_tlast_out         : out STD_LOGIC;                -- 출력 마지막
    tag_out               : out unsigned(127 downto 0);   -- MAC 태그
    tag_valid             : out STD_LOGIC                  -- 태그 유효
);
end entity;
```

#### 8.1.2 내부 구조

```vhdl
-- ChaCha20 인스턴스
u1: ChaCha20_128 port map(
    clk, plaintext, tvalid, tlast,
    key, nonce, nonce_last, counter,
    chacha_out, chacha_tvalid, chacha_tlast,
    r_out, s_out, r_valid
);

-- Poly1305 인스턴스
u2: Poly_1305_pipe_top port map(
    clk, Blck, r_ordered, s_ordered,
    n_in, poly_tvalid, poly_tlast,
    tag_out, tag_valid
);
```

#### 8.1.3 r 클램핑 처리

```vhdl
r_ordered <= r AND x"0ffffffc0ffffffc0ffffffc0fffffff";
s_ordered <= s;  -- s는 클램핑 없음
```

#### 8.1.4 Poly1305 블록 구성

```vhdl
-- 일반 데이터 블록
Blck <= '1' & ChaCha_data_out;  -- 제어 비트 '1' + 128비트 데이터 = 129비트

-- 마지막 블록 (길이 정보 포함)
if axi_tlast_in_poly1 = '1' then
    Blck <= '1' & x"00...00" & n_bytes_high & n_bytes_low & x"000000000000";
end if;
```

**129비트 블록의 의미:** Poly1305에서 각 16바이트 블록에 0x01 바이트를 추가하는 것을 하드웨어적으로 구현한 것이다. 최상위 비트 '1'이 이 역할을 한다.

#### 8.1.5 카운터 관리

```vhdl
process(clk)
begin
    if rising_edge(clk) then
        if axi_tlast_in_nonce = '1' then
            counter1 <= x"00000001";  -- 메시지 시작
        elsif axi_tvalid_in_msg = '1' then
            if cnt_valid = 3 then
                counter1 <= counter1 + 1;  -- 512비트 블록 완성
                cnt_valid <= 0;
            else
                cnt_valid <= cnt_valid + 1;
            end if;
        end if;
    end if;
end process;
```

### 8.2 AEAD_encryption_wrapper.vhd - 암호화 래퍼

최상위 암호화 인터페이스로, 외부 시스템과의 연결을 담당한다.

#### 8.2.1 포트 정의

```vhdl
entity AEAD_encryption_wrapper is
port(
    clk           : in  STD_LOGIC;
    rst           : in  STD_LOGIC;
    sink_tdata    : in  unsigned(127 downto 0);   -- 128비트 입력 데이터
    sink_tvalid   : in  STD_LOGIC;                -- 입력 유효
    sink_tlast    : in  STD_LOGIC;                -- 입력 마지막
    sink_tready   : out STD_LOGIC;                -- 준비 완료 (항상 '1')
    in_key        : in  unsigned(255 downto 0);   -- 256비트 외부 키
    source_tdata  : out unsigned(127 downto 0);   -- 128비트 암호문 출력
    source_tvalid : out STD_LOGIC;                -- 출력 유효
    source_tlast  : out STD_LOGIC;                -- 출력 마지막
    source_tready : in  STD_LOGIC;                -- 다운스트림 준비
    header_out    : out unsigned(127 downto 0)    -- WireGuard 헤더
);
end entity;
```

#### 8.2.2 패킷 처리 상태

```vhdl
-- active_packet = 0: 첫 번째 데이터는 키/논스 설정
-- active_packet = 1: 이후 데이터는 평문

process(clk)
begin
    if rising_edge(clk) then
        if sink_tvalid = '1' and active_packet = '0' then
            -- 첫 번째 128비트에서 논스와 블록 카운트 추출
            nonce <= x"00000000" & sink_tdata(63 downto 0);   -- 하위 64비트가 논스
            n_in  <= sink_tdata(106 downto 100);              -- 블록 카운트
            active_packet <= '1';
        elsif sink_tlast = '1' then
            active_packet <= '0';                             -- 패킷 종료
        end if;
    end if;
end process;
```

#### 8.2.3 헤더 구성 (WireGuard용)

```vhdl
header <= x"000000" & ('0' & n_in) & Im & nonce(63 downto 0);
```

278클럭 시프트 레지스터를 통해 암호문 출력과 타이밍 정렬된다.

### 8.3 AEAD_decryption_wrapper.vhd - 복호화 래퍼

암호화 래퍼와 유사하나, 추가적인 태그 검증 기능을 포함한다.

#### 8.3.1 추가 출력

```vhdl
tag_valid : out STD_LOGIC;  -- '1': 계산된 MAC = 수신된 MAC (인증 성공)
tag_pulse : out STD_LOGIC;  -- MAC 비교 완료 시 단일 펄스 출력
```

#### 8.3.2 태그 검증 로직 (AEAD_decryption.vhd 내부)

```vhdl
process(clk)
begin
    if rising_edge(clk) then
        if tag_pulse_internal = '1' then
            if shreg_ciptext(277) = tag_out then
                tag_valid <= '1';   -- 태그 일치: 인증 성공
            else
                tag_valid <= '0';   -- 태그 불일치: 데이터 변조 감지
            end if;
        end if;
    end if;
end process;
```

**핵심:** `tag_valid`는 `tag_pulse` 동안에만 어서트된다. 이는 최근 커밋(e0c8ffc)에서 디버깅 편의를 위해 변경된 사항이다.

### 8.4 AEAD_decryption.vhd - 복호화 코어

암호문 복호화 및 태그 검증을 수행하는 핵심 모듈이다.

#### 8.4.1 시프트 레지스터

```vhdl
shreg_ciptext  (278 클럭): 전체 암호문 저장 (태그 비교용)
shreg_plaintext (200 클럭): 복호화된 평문 저장
shreg_tvalid_aead (84 클럭): tvalid 제어 신호
shreg_tlast_aead (84 클럭): tlast 제어 신호
```

#### 8.4.2 암호문/태그 분리

```vhdl
-- 실제 데이터 블록만 ChaCha20에 전달 (태그는 제외)
if (cnt_valid_chacha <= (n_in-1) or n_in=0) and axi_tvalid_in_ciptext='1' then
    axi_tvalid_in_chacha1 <= '1';  -- 데이터 블록 → ChaCha20
else
    axi_tvalid_in_chacha1 <= '0';  -- 태그 블록 → ChaCha20에 전달하지 않음
end if;
```

#### 8.4.3 출력 게이팅

```vhdl
-- n_in 개의 블록만 평문으로 출력 (나머지는 마스킹)
if (cnt_valid_out <= n_shift_dec(193)-1) and axi_tvalid_poly_out='1' then
    axi_tvalid_out <= '1';   -- 유효한 평문 출력
else
    axi_tvalid_out <= '0';   -- 출력 억제
end if;
```

---

## 9. 암호화/복호화 데이터 흐름

### 9.1 암호화 패킷 처리 순서

```
시간 →

[T0] 키/논스 수신
     sink_tvalid=1, active_packet=0
     → 256비트 키 로드, 논스/n_in 추출
     → ChaCha20 카운터=0으로 r,s 생성 시작

[T1] 평문 블록 0 수신
     sink_tvalid=1, active_packet=1
     → ChaCha20 카운터=1로 키스트림 생성 시작
     → 평문 시프트 레지스터에 진입

[T2~Tn] 평문 블록 1~(n-1) 수신
     → 연속적인 128비트 블록 처리
     → 4블록마다 ChaCha20 카운터 증가

[Tn] 마지막 평문 블록
     sink_tlast=1
     → 파이프라인 플러시 시작

[T0+79] 첫 번째 암호문 블록 출력
     source_tvalid=1
     → 평문⊕키스트림 결과 출력

[T0+79~T0+79+n] 암호문 블록 순차 출력

[T0+245] MAC 태그 출력
     → Poly1305 계산 완료
     → 태그가 마지막 블록으로 출력
     source_tlast=1
```

### 9.2 복호화 패킷 처리 순서

```
시간 →

[T0] 키/논스 수신 (암호화와 동일)

[T1~Tn] 암호문 블록 수신
     → ChaCha20 키스트림 생성
     → 암호문⊕키스트림 = 평문 복원
     → 동시에 Poly1305에 암호문 전달

[Tn+1] MAC 태그 수신 (마지막 128비트)
     → 시프트 레지스터에 저장

[T0+79~] 평문 블록 출력

[T0+245] 태그 비교
     tag_pulse=1
     → 계산된 태그 vs 수신된 태그 비교
     → tag_valid=1 (성공) 또는 tag_valid=0 (실패)
```

### 9.3 블록 카운트 관리 상세

```
n_in (입력) = "128비트 블록 수 - 1"

예시: 48바이트 평문 = 3개의 128비트 블록 → n_in = 2

ChaCha20 카운터 변화:
  블록 0,1,2,3 → 카운터 = 1  (512비트 = 4 × 128비트)
  블록 4,5,6,7 → 카운터 = 2
  ...

Poly1305 블록 카운트 (내부):
  n_cnt = n_in → n_in-1 → ... → 0 (매 블록마다 감소)
  n_cnt 값에 따라 r^n_cnt 계산
```

---

## 10. WireGuard 통합

### 10.1 WG_header_adder.vhd

WireGuard 패킷 프레임에 필요한 헤더를 암호화된 페이로드 앞에 삽입한다.

#### 10.1.1 WireGuard 헤더 형식

```
바이트 0:     메시지 타입 (0x04 = 전송 데이터 메시지)
바이트 1-3:   예약 (0x000000)
바이트 4-7:   수신자 인덱스 (32비트)
바이트 8-15:  카운터 (64비트, 리틀 엔디안)
```

128비트로 구성:
```
[127:120] = 0x04 (메시지 타입)
[119:96]  = 0x000000 (예약)
[95:0]    = header_in(103:0) (수신자 인덱스 + 카운터)
```

#### 10.1.2 동작

```vhdl
process(clk)
begin
    if rising_edge(clk) then
        if sink_tvalid = '1' and active_packet = '0' then
            -- 패킷 첫 블록: WireGuard 헤더 삽입
            source_tdata  <= x"04" & x"000000" & header_in(103 downto 0);
            source_tvalid <= '1';
            source_tlast  <= '0';
            active_packet <= '1';
        else
            -- 후속 블록: 1클럭 지연된 원본 데이터 전달
            source_tdata  <= msg_shift;
            source_tvalid <= valid_shift;
            source_tlast  <= last_shift;
        end if;
    end if;
end process;
```

**효과:** 암호화된 페이로드 앞에 128비트(16바이트) WireGuard 헤더가 1블록 추가된다.

---

## 11. 파이프라인 지연 및 처리량 분석

### 11.1 구성 요소별 지연

| 구성 요소 | 지연 (클럭) | 용도 |
|-----------|------------|------|
| ChaCha20_int (내부 파이프라인) | 10 | 10 하프 라운드 (각 1클럭) |
| ChaCha20 키스트림 경로 | 79 | 출력 동기화 및 키 생성 |
| ChaCha20 평문 경로 | 81 | 키스트림과 평문 정렬 |
| r^n 연산 | 108+ | 6개 2의 거듭제곱 + 조합 파이프라인 |
| Poly1305 파이프라인 | 26 | 블록 누적 (block×r + acc) |
| 최종 MAC 계산 | 25 | 모듈러 리덕션 + s 가산 |
| **AEAD 총 지연** | **165+** | 전체 패킷 암/복호화 |

### 11.2 처리량

#### 11.2.1 이론적 최대 처리량

```
데이터 폭: 128비트/클럭
@ 250 MHz: 128비트 × 250M = 32 Gbps = 4 GB/s
```

#### 11.2.2 실효 처리량

```
첫 번째 출력: 165+ 클럭 후
이후 출력: 매 클럭 1블록 (정상 상태)

N 블록 메시지의 처리 시간:
  총 클럭 = 165 + (N-1) = 164 + N

효율: N / (164 + N)
  N=10:   5.7%
  N=100:  37.9%
  N=1000: 85.9%
  N→∞:   100% (이론적 한계)
```

### 11.3 블록 배칭 (Batching)

```
블록 1: 출력 시점 = T + 165 클럭
블록 2: 출력 시점 = T + 166 클럭 (+1 추가)
블록 3: 출력 시점 = T + 167 클럭 (+1 추가)
...
블록 N: 출력 시점 = T + 165 + (N-1) 클럭

→ 정상 상태 처리량: 1블록/클럭 (초기 지연 이후)
```

### 11.4 250 MHz 동작 시 지연 시간

```
AEAD 초기 지연: 165 클럭 × 4 ns = 660 ns
1500바이트 패킷 (94 블록): 660 + 93 × 4 = 1032 ns ≈ 1.03 μs
```

---

## 12. DSP 최적화 구현 (src_dsp_opt)

### 12.1 개요

`src_dsp_opt/` 디렉터리는 FPGA DSP 블록을 적극 활용하도록 최적화된 구현을 포함한다. 파일명에 `_kar` 접미사가 붙어있으며, 이는 **Karatsuba 최적화**를 의미한다.

### 12.2 주요 차이점

| 항목 | 기본 구현 (src/) | DSP 최적화 (src_dsp_opt/) |
|------|------------------|--------------------------|
| 곱셈기 구조 | 범용 로직 기반 | DSP48 블록 매핑 최적화 |
| 면적 효율 | LUT 집중 사용 | DSP 블록으로 LUT 절감 |
| 클럭 속도 | 중간 | 잠재적으로 더 높은 Fmax |
| 접미사 | 없음 | `_kar` |

### 12.3 최적화 파일 목록

| 파일 | 기본 구현 대응 | 최적화 내용 |
|------|---------------|------------|
| `mul_136_kar.vhd` | `mul_136.vhd` | DSP 최적화 136비트 곱셈기 |
| `mul_68_kar.vhd` | `mul_72.vhd` | DSP 최적화 68비트 곱셈기 |
| `Poly_1305_pipe_kar.vhd` | `Poly_1305_pipe.vhd` | 최적화 Poly1305 누적기 |
| `Poly_1305_pipe_top_kar.vhd` | `Poly_1305_pipe_top.vhd` | 최적화 Poly1305 최상위 |
| `r_pow_n_kar.vhd` | `r_power_n.vhd` | 최적화 r^n 연산 |
| `AEAD_encryptor_kar.vhd` | `AEAD_ChaCha_Poly.vhd` | 최적화 AEAD 코어 |
| `AEAD_encryption_wrapper_kar.vhd` | `AEAD_encryption_wrapper.vhd` | 최적화 암호화 래퍼 |
| `AEAD_decryption_wrapper_kar.vhd` | `AEAD_decryption_wrapper.vhd` | 최적화 복호화 래퍼 |
| `AEAD_decryption_kar.vhd` | `AEAD_decryption.vhd` | 최적화 복호화 코어 |
| `bus_pkg1.vhd` | `bus_pkg.vhd` | 확장 타입 패키지 |

### 12.4 bus_pkg1.vhd 확장 타입

```vhdl
-- 기본 bus_pkg.vhd의 모든 타입을 포함하고 추가로:

type type_shreg_S_poly_top is array (164 downto 0) of unsigned(127 downto 0);
-- 165클럭 s 파라미터 지연 라인 (DSP 최적화 파이프라인 매칭)

type type_shreg_blck_poly_top is array (164 downto 0) of unsigned(128 downto 0);
-- 165클럭 블록 지연 라인 (129비트)
```

---

## 13. 검증 및 테스트벤치

### 13.1 테스트 인프라

| 항목 | 도구 |
|------|------|
| 시뮬레이터 | GHDL (오픈소스 VHDL 시뮬레이터) |
| 테스트 프레임워크 | cocotb (Python 기반 하드웨어 테스트) |
| 참조 구현 | PyCryptodome (ChaCha20_Poly1305) |
| 프로토콜 | AXI Stream (16바이트 레인, 128비트) |
| CI/CD | GitLab CI (.gitlab-ci.yml) |
| 클럭 주기 | 4 ps (250 MHz 등가) |

### 13.2 암호화 테스트 케이스

`test_AEAD_encryption_wrapper_kar.py` 에서 정의:

| # | 테스트명 | 설명 |
|---|---------|------|
| 1 | 기본 기능 테스트 | RFC 7539 표준 테스트 벡터 검증 |
| 2 | 외부 검증 | PyCryptodome 참조 구현과 결과 대조 |
| 3 | 제로 키 테스트 | 256비트 전체가 0인 키로 동작 검증 |
| 4 | 제로 데이터 테스트 | 128바이트 전체가 0인 평문 암호화 |
| 5 | 실패 상태 테스트 | 빈 입력에 대한 의도적 실패 검증 |
| 6 | 랜덤 시드 테스트 | 가변 길이 데이터와 랜덤 키로 다양한 시나리오 검증 |

### 13.3 복호화 테스트 케이스

`test_AEAD_decryption_wrapper_kar.py` 에서 정의:

암호화 테스트와 유사한 구성이며, 추가적으로:
- `tag_valid` 출력 검증 (인증 성공/실패 확인)
- `tag_pulse` 동기화 검증
- MAC 불일치 검출 테스트

### 13.4 모니터 유틸리티

#### 13.4.1 BitMonitor.py

```python
# 개별 신호의 클럭별 추적
class BitMonitor:
    def __init__(self, signal, callback):
        self.signal = signal
        self.callback = callback
    # 매 클럭 에지에서 신호 값을 callback에 전달
```

- 사이클 정확(Cycle-accurate) 검증에 사용
- 개별 제어 신호(tvalid, tlast 등) 모니터링

#### 13.4.2 AxiStreamClockedMonitor.py

```python
# AXI Stream 프로토콜 레벨 모니터링
class AxiStreamClockedMonitor:
    # tdata, tvalid, tlast, tready 신호 추적
    # 트랜잭션 단위 콜백 제공
```

- 프로토콜 규정 준수 검증
- 데이터 무결성 확인

### 13.5 참조 구현 (ChaCha20_Poly1305_enc_dec.py)

```python
from Cryptodome.Cipher import ChaCha20_Poly1305

def our_encryptor(key, counter, plain_text, auth_text):
    """PyCryptodome 기반 암호화"""
    cipher = ChaCha20_Poly1305.new(key=key, nonce=counter)
    cipher.update(auth_text)
    cipher_text, digest = cipher.encrypt_and_digest(plain_text)
    return cipher_text, digest

def our_decryptor(key, counter, cipher_text, auth_text, digest):
    """PyCryptodome 기반 복호화"""
    cipher = ChaCha20_Poly1305.new(key=key, nonce=counter)
    cipher.update(auth_text)
    plain_text = cipher.decrypt_and_verify(cipher_text, digest)
    return plain_text
```

이 참조 구현은 하드웨어 출력의 정확성을 검증하는 **골든 레퍼런스(Golden Reference)**로 사용된다.

### 13.6 Makefile 설정

```makefile
SIM = ghdl                           # GHDL 시뮬레이터 사용
TOPLEVEL_LANG = vhdl                 # VHDL 언어
TOPLEVEL = aead_encryption_wrapper   # 최상위 엔티티
MODULE = test_AEAD_encryption_wrapper # 테스트 모듈

VHDL_SOURCES = $(PWD)/../../src_dsp_opt/bus_pkg1.vhd  \
               $(PWD)/../../src/q_round.vhd            \
               $(PWD)/../../src/col_round.vhd          \
               ...
```

---

## 14. 바이트 순서 및 데이터 정렬

### 14.1 리틀 엔디안 바이트 순서 변환

ChaCha20은 리틀 엔디안 바이트 순서를 사용한다. VHDL에서 `order` 함수로 변환:

```vhdl
function order(a : unsigned(31 downto 0)) return unsigned is
    variable b : unsigned(31 downto 0);
begin
    b := a(7 downto 0) & a(15 downto 8) & a(23 downto 16) & a(31 downto 24);
    return b;
end function;
```

**적용 대상:**
- 키 워드: `order(key((255-i*32) downto (224-i*32)))` (i = 0..7)
- 논스 워드: `order(nonce(...))`
- 암호문 출력: 바이트 스왑 적용

### 14.2 128비트 블록 구성

```
input_128bit[127:0] = |byte[15]|...|byte[1]|byte[0]|

ChaCha20에서 4 × 32비트 워드로 해석:
  word[3] = bytes[15:12]  (최상위)
  word[2] = bytes[11:8]
  word[1] = bytes[7:4]
  word[0] = bytes[3:0]   (최하위)
```

### 14.3 512비트 ChaCha20 블록과 128비트 AXI 전송 매핑

```
ChaCha20 블록 (512비트):
  word[0] ~ word[15]

AXI 전송 0: word[0]  & word[1]  & word[2]  & word[3]   (128비트)
AXI 전송 1: word[4]  & word[5]  & word[6]  & word[7]   (128비트)
AXI 전송 2: word[8]  & word[9]  & word[10] & word[11]  (128비트)
AXI 전송 3: word[12] & word[13] & word[14] & word[15]  (128비트)
```

---

## 15. 상태 머신 및 제어 로직

### 15.1 암시적 상태 머신

본 설계는 명시적 FSM(Finite State Machine) 대신 **암시적 상태**를 사용한다. 상태는 다음 신호들로 결정된다:

| 신호 | 역할 |
|------|------|
| `active_packet` | 패킷 설정(0) vs 페이로드(1) 구분 |
| `cnt_valid` | 512비트 블록 내 128비트 위치 추적 (0~3) |
| `first` (Poly1305) | 첫 블록 수신 여부 |
| 시프트 레지스터 | 파이프라인 상태 유지 |

### 15.2 Poly_1305_pipe_top 상태 전이

```
                ┌────────────┐
                │ first = 1  │  ← 초기 상태 / 패킷 완료 후
                │ (대기 중)   │
                └─────┬──────┘
                      │ tvalid = 1
                      ▼
                ┌────────────┐
                │ first = 0  │  ← n_in, r 캡처 완료
                │ (처리 중)   │
                │ n_cnt 감소  │
                └─────┬──────┘
                      │ tlast = 1
                      ▼
                ┌────────────┐
                │ first = 1  │  ← 태그 출력, 리셋
                │ (완료)      │
                └────────────┘
```

### 15.3 AXI Stream 핸드셰이킹

```vhdl
-- 데이터 전송 조건
if tvalid = '1' and tready = '1' then
    -- 이 사이클에 데이터 전송 발생
    if tlast = '1' then
        -- 현재 패킷의 마지막 데이터
        -- 다음 전송에서 새 패킷 시작
    end if;
end if;
```

### 15.4 패킷 경계 처리

**암호화:**

```
패킷 N 시작:  sink_tvalid=1, active_packet=0
              → 키, 논스, n_in 설정

              sink_tvalid=1, active_packet=1
              → 평문 블록 0 ~ n_in-1

              sink_tlast=1, active_packet=1
              → 마지막 평문 블록, 태그 출력 트리거

              → 출력: 암호문 + 태그 (source_tlast=1)
```

**복호화:**

```
유사한 구조이나, 입력이 암호문이고 출력이 평문
마지막 128비트가 MAC 태그
tag_pulse에서 태그 비교 수행
```

---

## 16. 모듈 인스턴스화 계층 구조

```
AEAD_encryption_wrapper (또는 AEAD_encryption_wrapper_kar)
  └── AEAD_ChaCha_Poly (또는 AEAD_encryptor_kar)
      ├── ChaCha20_128
      │   └── ChaCha_int
      │       └── half_round × 10 (직렬 파이프라인)
      │           ├── col_round
      │           │   └── q_round × 4 (병렬)
      │           └── diag_round
      │               └── q_round × 4 (병렬)
      └── Poly_1305_pipe_top (또는 Poly_1305_pipe_top_kar)
          ├── r_power_n (또는 r_pow_n_kar)
          │   ├── mul136_mod_red × 6 (r^2, r^4, ..., r^64 계산)
          │   │   ├── mul_144
          │   │   │   ├── mul_72 × 4 (병렬)
          │   │   │   │   └── mul_36 × 4 (병렬)
          │   │   │   │       └── mult_gen_0 × 4 (병렬)
          │   │   │   └── 시프터/가산기
          │   │   └── mod_red_1305
          │   └── mul_red_pipeline
          │       ├── mul136_mod_red × 3 (병렬)
          │       └── 시프트 레지스터
          └── Poly_1305_pipe (또는 Poly_1305_pipe_kar)
              ├── mul136_mod_red
              │   ├── mul_144
              │   └── mod_red_1305
              └── 시프트 레지스터/누적기

AEAD_decryption_wrapper (또는 AEAD_decryption_wrapper_kar)
  └── AEAD_decryption (또는 AEAD_decryption_kar)
      ├── AEAD_ChaCha_Poly (또는 AEAD_encryptor_kar) [동일 모듈 재사용]
      └── 태그 비교 로직
```

### 16.1 총 하드웨어 인스턴스 수 추정

| 모듈 | 인스턴스 수 | 비고 |
|------|-----------|------|
| q_round | 80 | 10 하프라운드 × 8 (컬럼4+대각4) |
| mult_gen_0 | ~384 | 곱셈기 트리 전체 |
| mod_red_1305 | ~10 | r^n 계산 + Poly1305 파이프라인 |
| mul136_mod_red | ~10 | 곱셈+리덕션 조합 |

---

## 17. 자원 사용량 추정

### 17.1 주요 자원 기여 요소

| 구성 요소 | 추정 LUT 수 | 설명 |
|-----------|------------|------|
| ChaCha20_int 파이프라인 | ~100K | 16워드 상태, 10라운드 |
| Poly1305 곱셈기 트리 | ~150K | 카라추바 계층 구조 |
| 시프트 레지스터 (165클럭 × 127비트) | ~20K | 파이프라인 지연 보상 |
| 제어 로직 | ~5K | 상태 관리, 카운터 |
| **추정 총계** | **~275K** | src_dsp_opt 버전 기준 |

### 17.2 DSP48 블록 사용량 (Xilinx 추정)

| 항목 | 추정 DSP 수 |
|------|------------|
| 17×17 곱셈기 (mult_gen_0) | 각 1 DSP48 |
| 곱셈기 트리 6레벨 | ~96 DSP |
| **전체 설계** | **~200-300 DSP** |

DSP 블록 사용으로 LUT 소모량이 크게 감소한다.

### 17.3 블록 RAM 사용

시프트 레지스터가 충분히 깊으면 합성기가 자동으로 블록 RAM으로 매핑할 수 있다:
- `shreg_ciptext` (278 × 128비트 = ~4.4 KB): BRAM 매핑 가능
- `shreg_plaintext` (200 × 128비트 = ~3.2 KB): BRAM 매핑 가능
- 기타 짧은 시프트 레지스터: SRL (Shift Register LUT)로 매핑

---

## 18. 설계 결정 사항 및 최적화 기법

### 18.1 완전 파이프라인 아키텍처

**결정:** 모든 연산을 완전히 파이프라인화하여 매 클럭 사이클마다 새로운 데이터를 수용할 수 있도록 설계

**이유:**
- 고처리량 요구사항 (WireGuard의 고속 네트워크 트래픽 처리)
- FPGA에서 파이프라인은 자연스러운 최적화 기법
- 정상 상태에서 128비트/클럭의 일정한 처리량 달성

**트레이드오프:**
- 초기 지연(165+ 클럭)이 크지만, 긴 패킷에서는 무시할 수 있는 수준
- 면적 증가 (시프트 레지스터 비용)

### 18.2 카라추바(Karatsuba) 곱셈

**결정:** 큰 곱셈(136비트)을 계층적으로 분해

**이유:**
- 직접 136×136 곱셈은 FPGA에서 비효율적
- 카라추바 분해로 더 작은 단위의 곱셈으로 분해
- 17비트 단위로 분해하면 FPGA DSP48 블록에 최적 매핑

**효과:**
- 17×17 → 34×34 → 68×68 → 136×136 순서로 구성
- 각 레벨에서 4개의 하위 곱셈기를 병렬 사용
- DSP48 블록의 효율적 활용

### 18.3 모듈러 리덕션 최적화

**결정:** 2^130 ≡ 5 (mod p) 성질을 이용한 빠른 리덕션

**이유:**
- 범용 나눗셈은 FPGA에서 매우 비쌈
- p = 2^130 - 5의 특수한 형태를 활용
- 곱셈과 가산만으로 5단계에 리덕션 완료

### 18.4 이진 거듭제곱법

**결정:** r^n을 r, r², r⁴, ..., r⁶⁴의 조합으로 계산

**이유:**
- 순차적 곱셈 (r × r × ... × r)은 n번의 곱셈 필요
- 이진 거듭제곱은 최대 log₂(n)번의 곱셈으로 축소
- 사전 계산 + 선택 구조로 고정 지연 달성

### 18.5 128비트 AXI Stream 인터페이스

**결정:** 128비트(16바이트) 데이터 폭 채택

**이유:**
- ChaCha20 블록(512비트)의 1/4에 해당하여 자연스러운 분할
- 일반적인 FPGA 데이터 경로 폭과 호환
- 가변 길이 메시지를 아키텍처 변경 없이 처리 가능
- 4회 전송마다 카운터 자동 증가

---

## 19. 표준 준수 사항

### 19.1 RFC 7539 준수

본 설계는 RFC 7539 "ChaCha20 and Poly1305 for IETF Protocols"를 충실히 구현한다:

| 요구사항 | 구현 현황 |
|---------|----------|
| ChaCha20: 20라운드 스트림 암호 | 10 더블 라운드 (= 20 라운드) 구현 |
| 256비트 키 | 256비트 키 입력 포트 제공 |
| 96비트 논스 | 96비트 논스 입력 포트 제공 |
| 32비트 카운터 | 32비트 카운터 내부 관리 |
| r 클램핑 | `r AND 0x0ffffffc0ffffffc0ffffffc0fffffff` 적용 |
| Poly1305: p = 2^130-5 | mod_red_1305에서 구현 |
| 카운터 0에서 r,s 추출 | ChaCha20_128에서 첫 블록으로 생성 |
| 128비트 MAC 태그 | 128비트 태그 출력 |

### 19.2 WireGuard 호환성

| 요구사항 | 구현 현황 |
|---------|----------|
| 32바이트 키 처리 | 256비트 키 입력 지원 |
| 12바이트 논스 처리 | 96비트 논스 입력 지원 |
| MAC 우선 인증 | 복호화 시 태그 검증 후 평문 출력 |
| 패킷 프레이밍 | WG_header_adder로 헤더 삽입 |
| 메시지 타입 0x04 | 헤더에 포함 |

### 19.3 AEAD 의미론

| 동작 | 입력 | 출력 |
|------|------|------|
| 암호화 | 평문 + 키 + 논스 | 암호문 + 태그 |
| 복호화 | 암호문 + 태그 + 키 + 논스 | 평문 (태그 유효 시) |

---

## 20. 최근 변경 이력

### 20.1 커밋 히스토리

| 커밋 해시 | 변경 내용 |
|-----------|----------|
| `7e75c09` | 라이선스를 BSD로 변경 |
| `e0c8ffc` | `AEAD_decryption_kar.vhd`: `tag_valid`를 `tag_pulse` 동안에만 어서트하도록 변경 (디버깅 용이) |
| `cb505ae` | 최상위 래퍼에 `tag_pulse` 재도입 |
| `51a42e4` | `tag_pulse` 재도입 (4a0e51ca에서 제거되었던 것 복원) |
| `b2d52eb` | 소스의 1클럭 'U'(미정의) 상태 해결 |

### 20.2 최근 작업 초점

1. **복호화 태그 검증 견고성 향상:** `tag_valid` 신호가 `tag_pulse` 기간에만 활성화되도록 개선하여 디버깅과 외부 로직 연동이 용이해짐
2. **태그 출력 동기화:** `tag_pulse` 신호의 정확한 타이밍 보장
3. **클럭 도메인 정렬:** 초기화 시 'U'(미정의) 상태 제거로 시뮬레이션 신뢰성 향상

---

## 부록 A: 약어 및 용어 정리

| 약어/용어 | 정의 |
|-----------|------|
| AEAD | Authenticated Encryption with Associated Data (연관 데이터를 포함한 인증 암호화) |
| AXI | Advanced eXtensible Interface (고급 확장 인터페이스) |
| BRAM | Block RAM (FPGA 내장 블록 메모리) |
| ChaCha20 | 20라운드 ChaCha 스트림 암호 |
| DSP48 | Xilinx FPGA의 디지털 신호 처리 블록 |
| FPGA | Field-Programmable Gate Array (현장 프로그래머블 게이트 어레이) |
| FSM | Finite State Machine (유한 상태 머신) |
| GHDL | GNU VHDL 시뮬레이터 |
| Karatsuba | Anatolii Karatsuba가 고안한 빠른 곱셈 알고리즘 |
| LUT | Look-Up Table (FPGA 기본 로직 요소) |
| MAC | Message Authentication Code (메시지 인증 코드) |
| Poly1305 | Daniel J. Bernstein의 일회용 인증자 |
| QR | Quarter Round (쿼터 라운드, ChaCha20 기본 연산) |
| RFC | Request for Comments (IETF 표준 문서) |
| SRL | Shift Register LUT (시프트 레지스터 LUT) |
| VHDL | VHSIC Hardware Description Language (하드웨어 기술 언어) |
| WireGuard | 최신 VPN 프로토콜 |
| XOR | Exclusive OR (배타적 논리합) |

## 부록 B: 신호 타이밍 다이어그램

### B.1 암호화 타이밍

```
클럭     : _|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_...._|‾|_|‾|_|‾|
          T0  T1  T2  T3  T4  T5  T6  T7  T8     T79 T80 T81

sink_tvalid :  ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾__________
sink_tdata  :  |설정|PT0|PT1|PT2|PT3|...|PTn|
sink_tlast  :  ________________________________‾‾__________

           ... (79클럭 파이프라인 지연) ...

src_tvalid  :  __________________________‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
src_tdata   :                            |CT0|CT1|...|CTn|TAG|
src_tlast   :  ________________________________________________‾‾

PT = 평문 블록, CT = 암호문 블록, TAG = MAC 태그
```

### B.2 복호화 타이밍

```
클럭     : _|‾|_|‾|_|‾|_|‾|_...._|‾|_|‾|_|‾|
          T0  T1  T2  T3       T79+n T80+n

sink_tdata  :  |설정|CT0|CT1|...|CTn|TAG|
sink_tlast  :  ____________________________‾‾

           ... (파이프라인 지연) ...

src_tdata   :                |PT0|PT1|...|PTn|
tag_pulse   :  ________________________________________‾‾____
tag_valid   :  ________________________________________‾‾____
                                                     (1=성공)
```

## 부록 C: 주요 수학적 배경

### C.1 ChaCha20 쿼터 라운드

4개의 32비트 워드 (a, b, c, d)에 대한 연산:

```
a ← a + b;   d ← (d ⊕ a) <<< 16
c ← c + d;   b ← (b ⊕ c) <<< 12
a ← a + b;   d ← (d ⊕ a) <<<  8
c ← c + d;   b ← (b ⊕ c) <<<  7
```

- 덧셈(+): mod 2^32 가산
- XOR(⊕): 비트별 배타적 논리합
- 순환 시프트(<<<): 왼쪽 순환 시프트

### C.2 Poly1305 MAC 계산

```
tag = ((Σ_{i=1}^{n} c_i × r^{n-i+1}) mod p) + s   (mod 2^128)
```

여기서:
- c_i = msg_block_i || 0x01  (16바이트 블록에 0x01 바이트 추가, 129비트)
- r = 128비트 키 (클램핑 적용)
- s = 128비트 일회용 패드
- p = 2^130 - 5
- 최종 결과는 128비트로 절삭 (mod 2^128)

### C.3 모듈러 리덕션 원리

p = 2^130 - 5에서:

```
2^130 ≡ 5 (mod p)

따라서 임의의 x = x_H × 2^130 + x_L에 대해:
x mod p = (x_H × 5 + x_L) mod p

여전히 130비트를 초과할 수 있으므로 반복 적용:
결과가 130비트 이내가 될 때까지 반복
(실제로는 최대 2회 반복으로 충분)
```

---

*본 문서는 ChaCha20-Poly1305 AEAD FPGA 구현체의 종합 기술 분석서이다.*
*모든 구현 세부사항은 저장소의 소스 코드를 기준으로 작성되었다.*
