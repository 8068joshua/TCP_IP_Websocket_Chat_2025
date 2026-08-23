import json
import os
import socket
import ssl
import struct
import threading

from dotenv import load_dotenv


load_dotenv()


# =========================================================
# Configuration
# =========================================================

HOST = os.getenv(
    "CORE_HOST",
    "127.0.0.1"
)
PORT = int(
    os.getenv(
        "CORE_PORT",
        "9000"
    )
)

CA_FILE = os.getenv(
    "CORE_CA_FILE",
    "certs/server.crt"
)

HEADER_SIZE = 4
MAX_MESSAGE_SIZE = 1024 * 1024

quitting = threading.Event()
send_lock = threading.Lock()


# =========================================================
# Protocol
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

        data.extend(
            chunk
        )

    return bytes(data)


def send_packet(sock, packet):
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

    with send_lock:
        sock.sendall(
            header + body
        )


def receive_packet(sock):
    header = recv_exact(
        sock,
        HEADER_SIZE
    )

    if header is None:
        return None

    body_length = struct.unpack(
        "!I",
        header
    )[0]

    if body_length <= 0 or body_length > MAX_MESSAGE_SIZE:
        raise ValueError(
            "Invalid frame length."
        )

    body = recv_exact(
        sock,
        body_length
    )

    if body is None:
        return None

    return json.loads(
        body.decode("utf-8")
    )


# =========================================================
# TLS
# =========================================================

def create_tls_socket():
    context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH,
        cafile=CA_FILE
    )

    # The certificate is pinned through CA_FILE.
    # For production, use a real hostname and enable hostname checking.
    context.check_hostname = False

    raw_socket = socket.create_connection(
        (HOST, PORT)
    )

    return context.wrap_socket(
        raw_socket,
        server_hostname=None
    )


# =========================================================
# Incoming Packets
# =========================================================

def print_packet(sock, packet):
    message_type = packet.get(
        "type"
    )

    if message_type == "ping":
        send_packet(
            sock,
            {
                "type": "pong"
            }
        )
        return

    if message_type == "message":
        print(
            f"\n[{packet.get('room')}] "
            f"{packet.get('sender')}: "
            f"{packet.get('content')}"
        )

    elif message_type == "private_message":
        print(
            f"\n[DM from {packet.get('sender')}] "
            f"{packet.get('content')}"
        )

    elif message_type == "private_message_sent":
        print(
            f"\n[DM to {packet.get('target')}] "
            f"{packet.get('content')}"
        )

    elif message_type == "users":
        print(
            "\n[ONLINE USERS]"
        )

        for user in packet.get(
            "users",
            []
        ):
            print(
                f" - {user.get('username')} "
                f"({user.get('room')})"
            )

    elif message_type == "rooms":
        print(
            "\n[ROOMS] "
            + ", ".join(
                packet.get(
                    "rooms",
                    []
                )
            )
        )

    elif message_type == "room_joined":
        print(
            f"\n[SYSTEM] Joined room: "
            f"{packet.get('room')}"
        )

    elif message_type == "join":
        print(
            f"\n[SYSTEM] "
            f"{packet.get('nickname')} joined "
            f"#{packet.get('room')}."
        )

    elif message_type == "leave":
        print(
            f"\n[SYSTEM] "
            f"{packet.get('nickname')} left "
            f"#{packet.get('room')}."
        )

    elif message_type == "devices":
        print(
            "\n[DEVICES]"
        )

        for device in packet.get(
            "devices",
            []
        ):
            print(
                f" - {device.get('device_id')}: "
                f"{device.get('status')} "
                f"(last_seen={device.get('last_seen')})"
            )

    elif message_type == "device_status":
        device = packet.get(
            "device",
            {}
        )

        print(
            f"\n[DEVICE] "
            f"{device.get('device_id')} -> "
            f"{device.get('status')}"
        )

    elif message_type == "alert":
        print(
            f"\n[ALERT/{packet.get('level')}] "
            f"{packet.get('source')}: "
            f"{packet.get('message')}"
        )

    elif message_type in {
        "system",
        "register_ok"
    }:
        print(
            f"\n[SYSTEM] "
            f"{packet.get('message', '')}"
        )

    elif message_type == "error":
        print(
            f"\n[ERROR] "
            f"{packet.get('message', '')}"
        )

    elif message_type == "login_ok":
        print(
            f"\n[SYSTEM] Login successful. "
            f"Current room: #{packet.get('room')}"
        )


def receive_loop(sock):
    try:
        while True:
            packet = receive_packet(
                sock
            )

            if packet is None:
                if not quitting.is_set():
                    print(
                        "\n[DISCONNECTED] Server closed connection."
                    )
                break

            print_packet(
                sock,
                packet
            )

    except (
        ConnectionError,
        OSError,
        ssl.SSLError
    ):
        if not quitting.is_set():
            print(
                "\n[ERROR] Server connection lost."
            )


# =========================================================
# CLI
# =========================================================

def authenticate(sock):
    while True:
        mode = input(
            "Choose [login/register]: "
        ).strip().lower()

        if mode not in {
            "login",
            "register"
        }:
            continue

        username = input(
            "Username: "
        ).strip()

        password = input(
            "Password: "
        )

        send_packet(
            sock,
            {
                "type": mode,
                "username": username,
                "password": password
            }
        )

        response = receive_packet(
            sock
        )

        if response is None:
            return False

        if response.get(
            "type"
        ) == "register_ok":
            print(
                "[SYSTEM] Registration complete. Please log in."
            )
            continue

        if response.get(
            "type"
        ) == "login_ok":
            print(
                f"[SYSTEM] Logged in as {username}."
            )
            return True

        print(
            "[ERROR] "
            + response.get(
                "message",
                "Authentication failed."
            )
        )


def command_loop(sock):
    print(
        "\nCommands:"
    )
    print(
        "  /users"
    )
    print(
        "  /rooms"
    )
    print(
        "  /join <room>"
    )
    print(
        "  /devices"
    )
    print(
        "  /msg <user> <message>"
    )
    print(
        "  /quit"
    )

    while True:
        try:
            text = input()

            if text == "/quit":
                quitting.set()

                send_packet(
                    sock,
                    {
                        "type": "quit"
                    }
                )

                try:
                    sock.shutdown(
                        socket.SHUT_WR
                    )
                except OSError:
                    pass

                break

            if text == "/users":
                send_packet(
                    sock,
                    {
                        "type": "users"
                    }
                )
                continue

            if text == "/rooms":
                send_packet(
                    sock,
                    {
                        "type": "rooms"
                    }
                )
                continue

            if text == "/devices":
                send_packet(
                    sock,
                    {
                        "type": "devices"
                    }
                )
                continue

            if text.startswith(
                "/join "
            ):
                room = text.split(
                    " ",
                    1
                )[1].strip()

                send_packet(
                    sock,
                    {
                        "type": "join_room",
                        "room": room
                    }
                )
                continue

            if text.startswith(
                "/msg "
            ):
                parts = text.split(
                    " ",
                    2
                )

                if len(parts) < 3:
                    print(
                        "[USAGE] /msg <user> <message>"
                    )
                    continue

                send_packet(
                    sock,
                    {
                        "type": "private_message",
                        "target": parts[1],
                        "content": parts[2]
                    }
                )
                continue

            if not text.strip():
                continue

            send_packet(
                sock,
                {
                    "type": "message",
                    "content": text
                }
            )

        except KeyboardInterrupt:
            quitting.set()

            try:
                send_packet(
                    sock,
                    {
                        "type": "quit"
                    }
                )
            except OSError:
                pass

            try:
                sock.shutdown(
                    socket.SHUT_WR
                )
            except OSError:
                pass

            break


def main():
    try:
        sock = create_tls_socket()

    except Exception as error:
        print(
            f"[ERROR] TLS connection failed: {error}"
        )
        return

    print(
        f"[CONNECTED] TLS -> {HOST}:{PORT}"
    )

    if not authenticate(
        sock
    ):
        sock.close()
        return

    receive_thread = threading.Thread(
        target=receive_loop,
        args=(sock,)
    )
    receive_thread.start()

    command_loop(
        sock
    )

    receive_thread.join()

    try:
        sock.close()
    except OSError:
        pass

    print(
        "[CLIENT] Connection closed."
    )


if __name__ == "__main__":
    main()
