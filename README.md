연구실 내부망용 TCP/IP 기반 실시간 메시징·장비 상태 모니터링 토이 프로젝트 (LocalOps)
======================================================================
1. 프로젝트 개요


LocalOps는 연구실 내부 네트워크(LAN) 환경에서 사용자 간 메시지 전달, 시스템 알림, 장비 상태 확인을 하나의 경량 통신 서비스로 구성해 보기 위해 개발한 연구실용 토이 프로젝트입니다.

본 프로젝트의 목적은 상용 메신저나 운영 관제 솔루션을 대체하는 것이 아니라, Python의 Low-Level Socket API를 기반으로 TCP 통신을 직접 구현하고, TCP Byte Stream의 특성, Application Layer Protocol 설계, TLS 암호화, 멀티클라이언트 처리, Heartbeat 기반 연결 상태 확인, WebSocket Gateway, HTTP API 및 장비 Agent를 하나의 흐름으로 연결해 보는 데 있습니다.

 2. 개발 배경
 
초기 목표는 Python의 socket 모듈만을 이용해 간단한 TCP 채팅 서버와 클라이언트를 구현하는 것이었습니다.

처음에는 단순히 문자열을 send()와 recv()로 주고받는 구조에서 시작했지만, 구현 과정에서 다음과 같은 실제 네트워크 프로그래밍 문제를 확인했습니다.

1) TCP는 메시지 단위가 아니라 Byte Stream 기반으로 동작한다.
2) 하나의 send()가 하나의 recv()와 반드시 대응하지 않는다.
3) 여러 클라이언트를 동시에 처리하려면 동시성 제어가 필요하다.
4) Client 종료 시 송수신 Thread와 Socket을 정상적으로 정리해야 한다.
5) TCP 연결이 존재한다는 사실만으로 상대 Application이 정상인지 알기 어렵다.
6) 평문 TCP Payload는 Wireshark에서 그대로 확인할 수 있으므로 암호화가 필요하다.
7) CLI 기반 프로그램만으로는 실제 사용자 관점에서 접근성이 떨어진다.

이 문제들을 하나씩 해결하면서 프로젝트를 다음 구조로 확장했습니다.

1:1 TCP Socket
    ↓
Multi-Client Chat
    ↓
JOIN / MESSAGE / QUIT Protocol
    ↓
Length-Prefix Framing
    ↓
JSON Application Protocol
    ↓
Graceful Shutdown
    ↓
Direct Message / User Management
    ↓
PING / PONG Heartbeat
    ↓
TLS
    ↓
User Authentication / SQLite
    ↓
Room / Channel
    ↓
Device Agent / Device Monitoring
    ↓
WebSocket Gateway / Web UI
    ↓
External HTTP Alert API


 3. 프로젝트 목표
 
- Python Low-Level Socket API를 이용한 TCP 통신 직접 구현
- TCP Byte Stream 특성을 고려한 메시지 프레이밍 구현
- JSON 기반 Application Layer Protocol 설계
- 멀티클라이언트 서버 구조 구현
- TLS를 이용한 TCP Payload 암호화
- 사용자 인증 및 세션 관리
- Room 기반 메시지 라우팅
- 1:1 Direct Message 구현
- PING/PONG Heartbeat 기반 연결 상태 확인
- 연구실 PC 또는 실험 장비의 Online/Offline 상태 확인
- 외부 프로그램에서 Alert를 발생시킬 수 있는 HTTP API 구성
- WebSocket Gateway를 통한 브라우저 기반 인터페이스 제공
- Wireshark를 이용한 패킷 수준 검증

본 프로젝트는 연구실 환경에서 네트워크 및 서버 동작 원리를 학습하기 위한 토이 프로젝트이며, 상용 서비스 수준의 보안성·가용성·확장성을 보장하는 것을 목표로 하지 않습니다.


 4. 주요 기능
 
4.1 실시간 메시징
여러 사용자가 동시에 서버에 접속하여 메시지를 주고받을 수 있습니다.
기본 메시지는 현재 참여 중인 Room 내부 사용자에게 전달됩니다.

4.2 Direct Message
특정 사용자에게만 1:1 메시지를 전달할 수 있습니다.

CLI 예시:
/msg Bob Hello

Server는 현재 접속 중인 사용자 세션에서 Bob을 검색한 뒤 Bob의 Socket으로만 메시지를 전달합니다. Client가 sender 값을 직접 지정하지 않고, Server가 실제 연결 Socket과 Session을 기반으로 발신자를 결정합니다.

4.3 User Management
현재 접속 중인 사용자를 Server가 관리하며 /users 명령으로 목록을 조회할 수 있습니다.

4.4 Room / Channel
사용자는 /rooms, /join ops 등의 명령을 통해 Room을 조회하거나 이동할 수 있습니다. 각 메시지는 현재 Room 내부 사용자에게만 Broadcast됩니다.

4.5 User Authentication
사용자 계정은 SQLite에 저장합니다. 비밀번호는 평문으로 저장하지 않고 PBKDF2-HMAC-SHA256 기반 Password Hashing을 적용합니다.

Password
    ↓
Random Salt
    ↓
PBKDF2-HMAC-SHA256
    ↓
Password Hash
    ↓
SQLite

4.6 TLS
기존 TCP 통신에서는 JSON Payload가 평문으로 전송되지만, TLS 적용 후에는 Application Data가 암호화되어 전송됩니다.

Application
    ↓
JSON
    ↓
Length-Prefix Framing
    ↓
TLS
    ↓
TCP
    ↓
IP

현재 프로젝트에서는 로컬 개발 및 테스트를 위해 Self-Signed Certificate를 사용합니다. 실제 외부 서비스 환경에서는 CA가 발급한 인증서와 Hostname Verification을 적용해야 합니다.

4.7 Heartbeat
Server는 일정 시간마다 Client 또는 Device에 PING을 전송하고, Client는 PONG을 반환합니다(마작 퐁 아님). 일정 시간 동안 PONG이 도착하지 않으면 해당 연결을 비정상 상태로 판단하고 Session을 제거합니다.

4.8 Device Monitoring
agent.py를 실행한 연구실 PC 또는 장비는 Device Agent로 Server에 접속합니다.

전달 가능한 정보 예시:
- Device ID
- Hostname
- Operating System
- Python Version
- Online / Offline 상태
- 마지막 상태 확인 시각
- 추가 Metadata

Device가 Heartbeat에 응답하지 않을 경우 Server는 해당 Device를 Offline으로 변경하고 상태 변경 이벤트를 전달할 수 있습니다.

4.9 External Alert API
외부 프로그램은 HTTP API를 통해 LocalOps에 Alert를 전달할 수 있습니다.

연결 가능한 예:
- 연구 데이터 분석 Script
- Backup Script
- Batch Job
- 서버 상태 점검 프로그램
- 실험 자동화 Script

Alert 예시:
{
    "source": "backup-job",
    "level": "warning",
    "message": "Backup exceeded expected runtime."
}

4.10 Web Interface
Browser에서 LocalOps를 사용할 수 있도록 WebSocket Gateway를 구성했습니다.

Browser
    |
    | WebSocket
    v
Web Gateway
    |
    | TLS / TCP
    v
Core TCP Server

4.11 Server Logging
서버 시작/종료, 사용자 등록/로그인, Room 이동, Message Routing, Direct Message, Alert, Device Online/Offline, Heartbeat Timeout, Protocol Error 등을 Rotating Log로 기록합니다.


 5. 시스템 아키텍처
 
  +-------------+
  | CLI Client  |
  +------+------+
         |
         | TLS / TCP
         |
  +------v-----------------------------------+
  |              Core TCP Server            |
  |                                          |
  |  - Length-Prefix Framing                 |
  |  - JSON Application Protocol             |
  |  - Authentication                        |
  |  - User Session Management               |
  |  - Room Management                       |
  |  - Message Routing                       |
  |  - Direct Message                        |
  |  - Heartbeat                             |
  |  - Device Monitoring                     |
  +------+------------------+----------------+
         |                  |
      SQLite             server.log

  +-------------+        +-------------+
  | Web Browser |------->| Web Gateway |
  +-------------+        +------+------+
       WebSocket                |
                                | TLS / TCP
                                +-------> Core TCP Server

  +--------------+
  | Device Agent |
  +------+-------+
         |
         | TLS / TCP
         +----------------------> Core TCP Server

  +------------------+
  | External Program |
  +---------+--------+
            |
            | HTTP API
            v
       Web Gateway
            |
            | TLS / TCP
            v
       Core TCP Server


 6. TCP Message Framing
 
TCP는 메시지 단위가 아니라 연속된 Byte Stream을 전달합니다.

Sender:
send("HELLO")
send("WORLD")

Receiver는 반드시 다음처럼 받는다는 보장이 없습니다.
recv() -> "HELLO"
recv() -> "WORLD"

다음과 같이 수신될 수도 있습니다.
recv() -> "HELLOWORLD"

또는:
recv() -> "HE"
recv() -> "LLOWOR"
recv() -> "LD"

따라서 LocalOps에서는 Application Message의 경계를 복원하기 위해 Length-Prefix Framing 방식을 사용합니다.

+----------------------+--------------------------------------+
| 4-byte Length Header | JSON Body                            |
+----------------------+--------------------------------------+
| Body Length          | Application Message                  |
+----------------------+--------------------------------------+

Python에서는 다음 개념을 사용합니다.

struct.pack("!I", len(body))

! : Network Byte Order (Big Endian)
I : Unsigned Integer, 4 Bytes

Receiver 처리 순서:

TCP Stream
    ↓
4 Byte Header 수신
    ↓
JSON Body Length 확인
    ↓
해당 Length만큼 recv_exact()
    ↓
UTF-8 Decode
    ↓
JSON Decode
    ↓
Python Dictionary


 7. Application Layer Protocol
 
LocalOps는 JSON 기반의 간단한 Application Layer Protocol을 사용합니다.

일반 메시지:
{
    "type": "message",
    "content": "Hello"
}

Direct Message:
{
    "type": "private_message",
    "target": "Bob",
    "content": "Check server-02."
}

Room 이동:
{
    "type": "join_room",
    "room": "ops"
}

Heartbeat:
{
    "type": "ping"
}

{
    "type": "pong"
}

Device Status:
{
    "type": "device_status",
    "status": "online"
}

Alert:
{
    "type": "alert",
    "source": "experiment-script",
    "level": "warning",
    "message": "Experiment process stopped."
}


 8. 주요 기술 스택
 
Language
- Python

Transport
- TCP Socket

Application Protocol
- JSON
- 4-byte Length-Prefix Framing

Security
- TLS
- PBKDF2 Password Hashing

Concurrency
- threading
- asyncio

Web Backend / Gateway
- FastAPI
- Uvicorn

Browser Communication
- WebSocket

Database
- SQLite

Monitoring
- PING / PONG Heartbeat
- Device Agent

Packet Analysis
- Wireshark

Environment Configuration
- python-dotenv


 9. 프로젝트 구조
 
localops/
|
|-- server.py
|   Core TCP/TLS Server
|
|-- client.py
|   CLI Client
|
|-- web_app.py
|   FastAPI WebSocket Gateway 및 HTTP API
|
|-- agent.py
|   Device Monitoring Agent
|
|-- static/
|   |-- index.html
|       Browser UI
|
|-- certs/
|   TLS Certificate / Private Key 저장
|
|-- data/
|   SQLite Database 저장
|
|-- logs/
|   Server Log 저장
|
|-- requirements.txt
|-- openssl.cnf
|-- .env.example
|-- .gitignore
|-- README.md


 10. 동작 예시
 
10.1 사용자 메시징

Alice
  |
  | "Hello"
  v
Server
  |
  +-----------------------> Bob


10.2 Direct Message

Alice
  |
  | /msg Bob Check this
  v
Client Command Parser
  |
  | JSON Private Message
  v
Server
  |
  | User Session Lookup
  v
Bob


10.3 Device Monitoring

PC-01 Agent
    |
    | PONG / Status
    v
Server
    |
    +----> PC-01 Online

PC-02 Agent
    X

Heartbeat Timeout
    |
    v
Server
    |
    +----> PC-02 Offline


10.4 External Alert

Experiment Script
       |
       | HTTP POST
       v
Web Gateway
       |
       | TLS / TCP
       v
Core Server
       |
       +-------------------> Researchers


 11. Wireshark를 이용한 검증
 
초기 TCP 버전에서는 Wireshark를 이용해 실제 Packet을 확인했습니다.

Display Filter:
tcp.port == 9000

TCP 3-Way Handshake:
Client -> Server : SYN
Server -> Client : SYN, ACK
Client -> Server : ACK

TLS 적용 전에는 다음과 같은 구조를 확인할 수 있습니다.

[4-byte Length]
{"type":"message","content":"hello"}

TLS 적용 후에는 JSON Payload가 평문으로 보이지 않고 TLS Application Data로 확인됩니다. 이를 통해 Application Layer의 JSON 데이터가 TLS 계층에서 암호화된 후 TCP를 통해 전달되는 것을 확인할 수 있습니다.


 12. Troubleshooting
 
12.1 TCP Message Boundary 문제

초기 구현에서는 sock.recv(1024)만으로 메시지를 처리했습니다.
하지만 TCP는 Message Boundary를 보장하지 않기 때문에 하나의 recv() 결과가
하나의 Application Message와 대응되지 않을 수 있습니다.

해결:
- JSON Body 앞에 4-byte Length Header 추가
- recv_exact() 구현
- Header에서 Body Length를 읽은 뒤 정확한 크기만큼 수신

12.2 Client 종료 시 Daemon Thread 문제

초기 Client에서는 Receive Thread에 daemon=True를 사용했습니다.

사용자가 /quit을 입력해 Main Thread가 종료되는 동안 Receive Thread가 stdout에
출력하려고 하면서 다음과 같은 종료 오류가 발생했습니다.

Fatal Python error:
_enter_buffered_busy
possibly due to daemon threads

해결:
1) daemon=True 제거
2) Application Layer QUIT 메시지 전송
3) socket.shutdown(socket.SHUT_WR)
4) Server가 Connection 종료
5) Receive Thread가 EOF 확인
6) thread.join()
7) socket.close()

12.3 연결 상태 확인 문제

TCP Socket이 연결되어 있다는 사실만으로 상대 Application이 정상적으로
동작하고 있는지는 확인하기 어렵습니다.

해결:
Server가 일정 주기로 PING을 전송하고 Client 또는 Device Agent가 PONG을
반환하도록 Heartbeat를 구현했습니다. 일정 시간 내 PONG이 없으면
Heartbeat Timeout으로 처리합니다.


 13. 개발 단계
 
Version 0.1
- 1:1 TCP Socket 통신

Version 0.2
- Multi-Client
- threading 기반 Client Handler

Version 0.3
- JOIN / MESSAGE / QUIT

Version 1.0
- JSON Protocol
- 4-byte Length-Prefix Framing
- recv_exact()
- Graceful Shutdown

Version 1.1
- /users
- Direct Message
- PING / PONG Heartbeat

Version 2.0
- TLS
- User Authentication
- SQLite
- Room / Channel
- Device Monitoring Agent
- WebSocket Gateway
- Browser UI
- HTTP Alert API
- Rotating Server Log


 14. 프로젝트의 성격과 한계
 
LocalOps는 연구실 내부 네트워크 환경에서 Socket Programming, Protocol Design,
TLS, WebSocket, Device Monitoring 등의 기술을 하나의 작은 시스템으로 연결해
보기 위한 연구실용 토이 프로젝트입니다.

현재 코드는 기능 검증과 학습을 위한 MVP 수준이며, 실제 상용 서비스 또는
인터넷 공개 서비스에 바로 사용하는 것을 전제로 하지 않습니다.

실제 운영 환경에 적용하려면 다음 항목을 추가로 고려해야 합니다.

- CA 기반 정식 TLS Certificate
- Hostname Verification
- HTTPS Reverse Proxy
- Rate Limiting
- Brute-Force Login Protection
- Account Lockout
- 사용자별 권한 및 Role-Based Access Control
- WebSocket Origin Policy
- API Key Rotation
- CSRF 등 Web Security 정책
- Database Migration
- 별도 Session Store
- 구조화된 Audit Log
- Metrics / Monitoring
- Automated Testing
- Load Testing
- Backup / Recovery
- Containerization
- Horizontal Scaling
- Message Broker 사용 검토


 15. 향후 개선 가능 항목
 
- Thread 기반 TCP Server를 asyncio 또는 selectors 기반 구조로 변경
- 다수 Client 접속 시 성능 비교
- Room 별 Message History 저장
- Device 상태 History 저장
- Research Experiment Job Monitoring
- 파일 전송 Protocol
- Alert Rule 설정
- 사용자 권한 관리
- Docker 기반 배포
- Prometheus / Grafana 연계
- MQTT 또는 AMQP와 자체 TCP Protocol 비교
- Web UI Dashboard 개선
- Unit Test / Integration Test 작성
- Packet Capture 기반 Protocol 분석 문서화

