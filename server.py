import hashlib
import hmac
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from dataclasses import dataclass, field
from pathlib import Path
import secrets
import socket
import sqlite3
import ssl
import struct
import threading
import time

from dotenv import load_dotenv


load_dotenv()


# =========================================================
# Configuration
# =========================================================

HOST = os.getenv("TCP_HOST", "0.0.0.0")
PORT = int(os.getenv("TCP_PORT", "9000"))

HEADER_SIZE = 4
MAX_MESSAGE_SIZE = 1024 * 1024

HEARTBEAT_INTERVAL = int(os.getenv("HEARTBEAT_INTERVAL", "5"))
HEARTBEAT_TIMEOUT = int(os.getenv("HEARTBEAT_TIMEOUT", "15"))

DB_FILE = Path(os.getenv("DB_FILE", "data/localops.db"))
LOG_FILE = Path(os.getenv("LOG_FILE", "logs/server.log"))

CERT_FILE = os.getenv("CERT_FILE", "certs/server.crt")
KEY_FILE = os.getenv("KEY_FILE", "certs/server.key")

SERVICE_API_KEY = os.getenv("SERVICE_API_KEY", "")
PBKDF2_ITERATIONS = 200_000

DEFAULT_ROOMS = {"general", "ops", "random"}


# =========================================================
# Logging
# =========================================================

LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger("localops")
logger.setLevel(logging.INFO)

formatter = logging.Formatter(
    "%(asctime)s | %(levelname)s | %(message)s"
)

file_handler = RotatingFileHandler(
    LOG_FILE,
    maxBytes=2 * 1024 * 1024,
    backupCount=3,
    encoding="utf-8"
)
file_handler.setFormatter(formatter)

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)

logger.addHandler(file_handler)
logger.addHandler(console_handler)


# =========================================================
# Database / Authentication
# =========================================================

DB_FILE.parent.mkdir(parents=True, exist_ok=True)


def init_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()


def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS
    )


def register_user(username, password):
    if len(username) < 3 or len(username) > 32:
        return False, "Username must be 3-32 characters."

    if len(password) < 8:
        return False, "Password must be at least 8 characters."

    salt = secrets.token_bytes(16)
    password_hash = hash_password(
        password,
        salt
    )

    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute(
                """
                INSERT INTO users (
                    username,
                    salt,
                    password_hash
                )
                VALUES (?, ?, ?)
                """,
                (
                    username,
                    salt,
                    password_hash
                )
            )
            conn.commit()

        return True, "Registration successful."

    except sqlite3.IntegrityError:
        return False, "Username already exists."


def verify_user(username, password):
    with sqlite3.connect(DB_FILE) as conn:
        row = conn.execute(
            """
            SELECT salt, password_hash
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

    if row is None:
        return False

    salt, stored_hash = row

    candidate_hash = hash_password(
        password,
        salt
    )

    return hmac.compare_digest(
        candidate_hash,
        stored_hash
    )


# =========================================================
# Session State
# =========================================================

@dataclass
class Session:
    sock: ssl.SSLSocket
    address: tuple
    authenticated: bool = False
    role: str = "guest"
    username: str | None = None
    room: str = "general"
    device_id: str | None = None
    last_pong: float = field(
        default_factory=time.monotonic
    )
    send_lock: threading.Lock = field(
        default_factory=threading.Lock
    )
    closed: bool = False


state_lock = threading.RLock()

sessions = {}
user_sessions = {}
devices = {}

rooms = set(DEFAULT_ROOMS)

client_threads = set()
threads_lock = threading.Lock()

server_stop_event = threading.Event()


# =========================================================
# Protocol Framing
# =========================================================

def recv_exact(sock, size):
    data = bytearray()

    while len(data) < size:
        chunk = sock.recv(
            size - len(data)
        )

        if not chunk:
            if not data:
                return None

            raise ConnectionError(
                "Connection closed during frame reception."
            )

        data.extend(chunk)

    return bytes(data)


def send_packet(session, packet):
    body = json.dumps(
        packet,
        ensure_ascii=False,
        separators=(",", ":")
    ).encode("utf-8")

    if len(body) > MAX_MESSAGE_SIZE:
        raise ValueError(
            "Message too large."
        )

    header = struct.pack(
        "!I",
        len(body)
    )

    with session.send_lock:
        if session.closed:
            raise OSError(
                "Session is already closed."
            )

        session.sock.sendall(
            header + body
        )


def receive_packet(session):
    header = recv_exact(
        session.sock,
        HEADER_SIZE
    )

    if header is None:
        return None

    body_length = struct.unpack(
        "!I",
        header
    )[0]

    if body_length <= 0:
        raise ValueError(
            "Invalid frame length."
        )

    if body_length > MAX_MESSAGE_SIZE:
        raise ValueError(
            "Frame exceeds maximum message size."
        )

    body = recv_exact(
        session.sock,
        body_length
    )

    if body is None:
        return None

    packet = json.loads(
        body.decode("utf-8")
    )

    if not isinstance(packet, dict):
        raise ValueError(
            "Packet must be a JSON object."
        )

    return packet


# =========================================================
# Broadcast / State Helpers
# =========================================================

def send_error(session, message):
    send_packet(
        session,
        {
            "type": "error",
            "message": message
        }
    )


def user_targets(room=None, exclude=None):
    with state_lock:
        result = []

        for session in user_sessions.values():
            if session.closed:
                continue

            if room is not None and session.room != room:
                continue

            if exclude is not None and session is exclude:
                continue

            result.append(
                session
            )

        return result


def safe_send(session, packet):
    try:
        send_packet(
            session,
            packet
        )
        return True

    except (
        OSError,
        ConnectionError,
        ssl.SSLError
    ):
        remove_session(
            session,
            reason="send failure"
        )
        return False


def broadcast_users(packet, room=None, exclude=None):
    for target in user_targets(
        room=room,
        exclude=exclude
    ):
        safe_send(
            target,
            packet
        )


def broadcast_device_status(device_id):
    with state_lock:
        info = dict(
            devices.get(
                device_id,
                {}
            )
        )

    if not info:
        return

    broadcast_users(
        {
            "type": "device_status",
            "device": info
        }
    )


def remove_session(session, reason="connection closed"):
    with state_lock:
        if session.closed:
            return

        session.closed = True

        sessions.pop(
            session.sock,
            None
        )

        username = session.username
        role = session.role
        room = session.room
        device_id = session.device_id

        if username:
            current = user_sessions.get(
                username
            )

            if current is session:
                user_sessions.pop(
                    username,
                    None
                )

        if device_id:
            info = devices.setdefault(
                device_id,
                {}
            )

            info["device_id"] = device_id
            info["status"] = "offline"
            info["last_seen"] = int(
                time.time()
            )

    try:
        session.sock.shutdown(
            socket.SHUT_RDWR
        )
    except OSError:
        pass

    try:
        session.sock.close()
    except OSError:
        pass

    if role == "user" and username:
        logger.info(
            "USER_DISCONNECTED username=%s room=%s reason=%s",
            username,
            room,
            reason
        )

        broadcast_users(
            {
                "type": "leave",
                "nickname": username,
                "room": room
            },
            room=room
        )

    elif role == "device" and device_id:
        logger.info(
            "DEVICE_OFFLINE device_id=%s reason=%s",
            device_id,
            reason
        )

        broadcast_device_status(
            device_id
        )


# =========================================================
# Authentication Handlers
# =========================================================

def handle_register(session, packet):
    username = str(
        packet.get(
            "username",
            ""
        )
    ).strip()

    password = str(
        packet.get(
            "password",
            ""
        )
    )

    ok, message = register_user(
        username,
        password
    )

    if ok:
        logger.info(
            "USER_REGISTERED username=%s",
            username
        )

        send_packet(
            session,
            {
                "type": "register_ok",
                "message": message
            }
        )
    else:
        send_error(
            session,
            message
        )


def handle_login(session, packet):
    username = str(
        packet.get(
            "username",
            ""
        )
    ).strip()

    password = str(
        packet.get(
            "password",
            ""
        )
    )

    if not verify_user(
        username,
        password
    ):
        send_error(
            session,
            "Invalid username or password."
        )
        return False

    with state_lock:
        existing = user_sessions.get(
            username
        )

        if existing and not existing.closed:
            send_error(
                session,
                "This user is already connected."
            )
            return False

        session.authenticated = True
        session.role = "user"
        session.username = username
        session.room = "general"
        session.last_pong = time.monotonic()

        user_sessions[username] = session
        rooms.add(
            "general"
        )

    logger.info(
        "USER_LOGIN username=%s address=%s",
        username,
        session.address
    )

    send_packet(
        session,
        {
            "type": "login_ok",
            "username": username,
            "room": session.room
        }
    )

    broadcast_users(
        {
            "type": "join",
            "nickname": username,
            "room": session.room
        },
        room=session.room,
        exclude=session
    )

    return True


def valid_service_key(candidate):
    if not SERVICE_API_KEY:
        return False

    return hmac.compare_digest(
        candidate,
        SERVICE_API_KEY
    )


def handle_service_auth(session, packet):
    api_key = str(
        packet.get(
            "api_key",
            ""
        )
    )

    if not valid_service_key(
        api_key
    ):
        send_error(
            session,
            "Invalid service API key."
        )
        return False

    session.authenticated = True
    session.role = "service"
    session.last_pong = time.monotonic()

    send_packet(
        session,
        {
            "type": "auth_ok",
            "role": "service"
        }
    )

    return True


def handle_device_auth(session, packet):
    api_key = str(
        packet.get(
            "api_key",
            ""
        )
    )

    device_id = str(
        packet.get(
            "device_id",
            ""
        )
    ).strip()

    if not valid_service_key(
        api_key
    ):
        send_error(
            session,
            "Invalid device API key."
        )
        return False

    if not device_id:
        send_error(
            session,
            "device_id is required."
        )
        return False

    with state_lock:
        session.authenticated = True
        session.role = "device"
        session.device_id = device_id
        session.last_pong = time.monotonic()

        devices[device_id] = {
            "device_id": device_id,
            "status": "online",
            "last_seen": int(
                time.time()
            ),
            "metadata": packet.get(
                "metadata",
                {}
            )
        }

    logger.info(
        "DEVICE_ONLINE device_id=%s address=%s",
        device_id,
        session.address
    )

    send_packet(
        session,
        {
            "type": "auth_ok",
            "role": "device",
            "device_id": device_id
        }
    )

    broadcast_device_status(
        device_id
    )

    return True


# =========================================================
# User Features
# =========================================================

def handle_message(session, packet):
    content = packet.get(
        "content",
        ""
    )

    if not isinstance(
        content,
        str
    ):
        send_error(
            session,
            "content must be a string."
        )
        return

    if not content.strip():
        return

    if len(content) > 4000:
        send_error(
            session,
            "Message is too long."
        )
        return

    logger.info(
        "ROOM_MESSAGE username=%s room=%s length=%d",
        session.username,
        session.room,
        len(content)
    )

    broadcast_users(
        {
            "type": "message",
            "sender": session.username,
            "room": session.room,
            "content": content
        },
        room=session.room,
        exclude=session
    )


def handle_private_message(session, packet):
    target_name = str(
        packet.get(
            "target",
            ""
        )
    ).strip()

    content = packet.get(
        "content",
        ""
    )

    if not target_name:
        send_error(
            session,
            "Target user is required."
        )
        return

    if not isinstance(
        content,
        str
    ) or not content.strip():
        send_error(
            session,
            "Message content is required."
        )
        return

    with state_lock:
        target = user_sessions.get(
            target_name
        )

    if target is None or target.closed:
        send_error(
            session,
            f"User '{target_name}' is not connected."
        )
        return

    logger.info(
        "PRIVATE_MESSAGE sender=%s target=%s length=%d",
        session.username,
        target_name,
        len(content)
    )

    if safe_send(
        target,
        {
            "type": "private_message",
            "sender": session.username,
            "content": content
        }
    ):
        send_packet(
            session,
            {
                "type": "private_message_sent",
                "target": target_name,
                "content": content
            }
        )


def handle_users(session):
    with state_lock:
        users = [
            {
                "username": item.username,
                "room": item.room
            }
            for item in user_sessions.values()
            if not item.closed
        ]

    send_packet(
        session,
        {
            "type": "users",
            "users": users
        }
    )


def valid_room_name(room):
    if not room:
        return False

    if len(room) > 32:
        return False

    return all(
        char.isalnum() or char in "-_"
        for char in room
    )


def handle_join_room(session, packet):
    new_room = str(
        packet.get(
            "room",
            ""
        )
    ).strip()

    if not valid_room_name(
        new_room
    ):
        send_error(
            session,
            "Room names may contain only letters, numbers, '-' and '_'."
        )
        return

    old_room = session.room

    if old_room == new_room:
        return

    broadcast_users(
        {
            "type": "leave",
            "nickname": session.username,
            "room": old_room
        },
        room=old_room,
        exclude=session
    )

    with state_lock:
        session.room = new_room
        rooms.add(
            new_room
        )

    logger.info(
        "ROOM_CHANGE username=%s from=%s to=%s",
        session.username,
        old_room,
        new_room
    )

    send_packet(
        session,
        {
            "type": "room_joined",
            "room": new_room
        }
    )

    broadcast_users(
        {
            "type": "join",
            "nickname": session.username,
            "room": new_room
        },
        room=new_room,
        exclude=session
    )


def handle_rooms(session):
    with state_lock:
        room_list = sorted(
            rooms
        )

    send_packet(
        session,
        {
            "type": "rooms",
            "rooms": room_list
        }
    )


def handle_devices(session):
    with state_lock:
        device_list = sorted(
            (
                dict(info)
                for info in devices.values()
            ),
            key=lambda item: item.get(
                "device_id",
                ""
            )
        )

    send_packet(
        session,
        {
            "type": "devices",
            "devices": device_list
        }
    )


# =========================================================
# Service / Device Features
# =========================================================

def handle_alert(session, packet):
    source = str(
        packet.get(
            "source",
            "external"
        )
    ).strip()

    level = str(
        packet.get(
            "level",
            "info"
        )
    ).strip().lower()

    message = str(
        packet.get(
            "message",
            ""
        )
    ).strip()

    if not message:
        send_error(
            session,
            "Alert message is required."
        )
        return

    if level not in {
        "info",
        "warning",
        "critical"
    }:
        level = "info"

    logger.warning(
        "ALERT source=%s level=%s message=%s",
        source,
        level,
        message
    )

    broadcast_users(
        {
            "type": "alert",
            "source": source,
            "level": level,
            "message": message,
            "timestamp": int(
                time.time()
            )
        }
    )

    send_packet(
        session,
        {
            "type": "alert_accepted"
        }
    )


def update_device_status(device_id, status, metadata=None):
    with state_lock:
        info = devices.setdefault(
            device_id,
            {
                "device_id": device_id
            }
        )

        info["status"] = status
        info["last_seen"] = int(
            time.time()
        )

        if metadata is not None:
            info["metadata"] = metadata

    broadcast_device_status(
        device_id
    )


def handle_device_status(session, packet):
    if session.role == "device":
        device_id = session.device_id

    else:
        device_id = str(
            packet.get(
                "device_id",
                ""
            )
        ).strip()

    if not device_id:
        send_error(
            session,
            "device_id is required."
        )
        return

    status = str(
        packet.get(
            "status",
            "online"
        )
    ).strip().lower()

    metadata = packet.get(
        "metadata"
    )

    update_device_status(
        device_id,
        status,
        metadata
    )

    logger.info(
        "DEVICE_STATUS device_id=%s status=%s",
        device_id,
        status
    )

    send_packet(
        session,
        {
            "type": "device_status_accepted",
            "device_id": device_id
        }
    )


# =========================================================
# Heartbeat
# =========================================================

def handle_pong(session):
    session.last_pong = time.monotonic()

    if session.role == "device" and session.device_id:
        with state_lock:
            info = devices.get(
                session.device_id
            )

            if info is not None:
                info["last_seen"] = int(
                    time.time()
                )
                info["status"] = "online"


def heartbeat_loop():
    while not server_stop_event.wait(
        HEARTBEAT_INTERVAL
    ):
        now = time.monotonic()

        with state_lock:
            snapshot = [
                session
                for session in sessions.values()
                if (
                    session.authenticated
                    and not session.closed
                )
            ]

        for session in snapshot:
            if (
                now - session.last_pong
                > HEARTBEAT_TIMEOUT
            ):
                logger.warning(
                    "HEARTBEAT_TIMEOUT role=%s user=%s device=%s",
                    session.role,
                    session.username,
                    session.device_id
                )

                remove_session(
                    session,
                    reason="heartbeat timeout"
                )
                continue

            safe_send(
                session,
                {
                    "type": "ping",
                    "timestamp": int(
                        time.time()
                    )
                }
            )


# =========================================================
# Session Dispatch
# =========================================================

def dispatch_packet(session, packet):
    message_type = packet.get(
        "type"
    )

    # Authentication is allowed before a session is authenticated.
    if not session.authenticated:
        if message_type == "register":
            handle_register(
                session,
                packet
            )
            return True

        if message_type == "login":
            return handle_login(
                session,
                packet
            )

        if message_type == "service_auth":
            return handle_service_auth(
                session,
                packet
            )

        if message_type == "device_auth":
            return handle_device_auth(
                session,
                packet
            )

        send_error(
            session,
            "Authenticate first."
        )
        return True

    if message_type == "pong":
        handle_pong(
            session
        )
        return True

    if message_type == "quit":
        return False

    # Normal user protocol.
    if session.role == "user":
        if message_type == "message":
            handle_message(
                session,
                packet
            )

        elif message_type == "private_message":
            handle_private_message(
                session,
                packet
            )

        elif message_type == "users":
            handle_users(
                session
            )

        elif message_type == "join_room":
            handle_join_room(
                session,
                packet
            )

        elif message_type == "rooms":
            handle_rooms(
                session
            )

        elif message_type == "devices":
            handle_devices(
                session
            )

        else:
            send_error(
                session,
                "Unknown user message type."
            )

        return True

    # HTTP gateway / external integrations.
    if session.role == "service":
        if message_type == "alert":
            handle_alert(
                session,
                packet
            )

        elif message_type == "device_status":
            handle_device_status(
                session,
                packet
            )

        else:
            send_error(
                session,
                "Unknown service message type."
            )

        return True

    # Persistent device agent.
    if session.role == "device":
        if message_type == "device_status":
            handle_device_status(
                session,
                packet
            )

        else:
            send_error(
                session,
                "Unknown device message type."
            )

        return True

    send_error(
        session,
        "Unknown session role."
    )

    return True


# =========================================================
# Connection Handler
# =========================================================

def handle_tls_connection(raw_socket, address, tls_context):
    session = None

    try:
        tls_socket = tls_context.wrap_socket(
            raw_socket,
            server_side=True
        )

        session = Session(
            sock=tls_socket,
            address=address
        )

        with state_lock:
            sessions[tls_socket] = session

        logger.info(
            "TLS_CONNECTED address=%s",
            address
        )

        while not server_stop_event.is_set():
            packet = receive_packet(
                session
            )

            if packet is None:
                break

            keep_open = dispatch_packet(
                session,
                packet
            )

            if not keep_open:
                break

    except ssl.SSLError as error:
        logger.warning(
            "TLS_ERROR address=%s error=%s",
            address,
            error
        )

    except (
        ConnectionResetError,
        ConnectionError,
        OSError
    ):
        pass

    except (
        json.JSONDecodeError,
        UnicodeDecodeError,
        ValueError
    ) as error:
        logger.warning(
            "PROTOCOL_ERROR address=%s error=%s",
            address,
            error
        )

    except Exception:
        logger.exception(
            "UNHANDLED_CLIENT_ERROR address=%s",
            address
        )

    finally:
        if session is not None:
            remove_session(
                session
            )
        else:
            try:
                raw_socket.close()
            except OSError:
                pass

        current = threading.current_thread()

        with threads_lock:
            client_threads.discard(
                current
            )


# =========================================================
# Server Startup
# =========================================================

def create_tls_context():
    context = ssl.SSLContext(
        ssl.PROTOCOL_TLS_SERVER
    )

    context.minimum_version = (
        ssl.TLSVersion.TLSv1_2
    )

    context.load_cert_chain(
        certfile=CERT_FILE,
        keyfile=KEY_FILE
    )

    return context


def start_server():
    if not SERVICE_API_KEY:
        raise RuntimeError(
            "SERVICE_API_KEY is not configured. "
            "Set it in .env before starting the server."
        )

    init_db()

    tls_context = create_tls_context()

    server_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server_socket.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server_socket.bind(
        (HOST, PORT)
    )

    server_socket.listen()

    heartbeat_thread = threading.Thread(
        target=heartbeat_loop,
        name="heartbeat-thread"
    )
    heartbeat_thread.start()

    logger.info(
        "SERVER_STARTED address=%s:%s",
        HOST,
        PORT
    )

    try:
        while True:
            raw_socket, address = (
                server_socket.accept()
            )

            thread = threading.Thread(
                target=handle_tls_connection,
                args=(
                    raw_socket,
                    address,
                    tls_context
                )
            )

            with threads_lock:
                client_threads.add(
                    thread
                )

            thread.start()

    except KeyboardInterrupt:
        logger.info(
            "SERVER_SHUTDOWN_REQUESTED"
        )

    finally:
        server_stop_event.set()

        try:
            server_socket.close()
        except OSError:
            pass

        with state_lock:
            current_sessions = list(
                sessions.values()
            )

        for session in current_sessions:
            if session.role == "user":
                try:
                    send_packet(
                        session,
                        {
                            "type": "system",
                            "message": "Server shutting down."
                        }
                    )
                except OSError:
                    pass

        for session in current_sessions:
            remove_session(
                session,
                reason="server shutdown"
            )

        heartbeat_thread.join(
            timeout=2
        )

        with threads_lock:
            threads = list(
                client_threads
            )

        for thread in threads:
            thread.join(
                timeout=2
            )

        logger.info(
            "SERVER_STOPPED"
        )


if __name__ == "__main__":
    start_server()
