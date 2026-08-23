import json
import os
import platform
import socket
import ssl
import struct
import threading
import time

from dotenv import load_dotenv


load_dotenv()


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

SERVICE_API_KEY = os.getenv(
    "SERVICE_API_KEY",
    ""
)

DEVICE_ID = os.getenv(
    "DEVICE_ID",
    socket.gethostname()
)

STATUS_INTERVAL = int(
    os.getenv(
        "DEVICE_STATUS_INTERVAL",
        "10"
    )
)

HEADER_SIZE = 4
MAX_MESSAGE_SIZE = 1024 * 1024

stop_event = threading.Event()
send_lock = threading.Lock()


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
                "Connection closed."
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

    length = struct.unpack(
        "!I",
        header
    )[0]

    if length <= 0 or length > MAX_MESSAGE_SIZE:
        raise ValueError(
            "Invalid frame length."
        )

    body = recv_exact(
        sock,
        length
    )

    if body is None:
        return None

    return json.loads(
        body.decode("utf-8")
    )


def create_tls_socket():
    context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH,
        cafile=CA_FILE
    )

    context.check_hostname = False

    raw_socket = socket.create_connection(
        (HOST, PORT)
    )

    return context.wrap_socket(
        raw_socket,
        server_hostname=None
    )


def metadata():
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": platform.python_version()
    }


def receive_loop(sock):
    try:
        while not stop_event.is_set():
            packet = receive_packet(
                sock
            )

            if packet is None:
                break

            if packet.get(
                "type"
            ) == "ping":
                send_packet(
                    sock,
                    {
                        "type": "pong"
                    }
                )

            elif packet.get(
                "type"
            ) == "error":
                print(
                    "[ERROR] "
                    + packet.get(
                        "message",
                        ""
                    )
                )

    finally:
        stop_event.set()


def main():
    if not SERVICE_API_KEY:
        print(
            "[ERROR] SERVICE_API_KEY is required."
        )
        return

    try:
        sock = create_tls_socket()

        send_packet(
            sock,
            {
                "type": "device_auth",
                "api_key": SERVICE_API_KEY,
                "device_id": DEVICE_ID,
                "metadata": metadata()
            }
        )

        response = receive_packet(
            sock
        )

        if (
            response is None
            or response.get("type") != "auth_ok"
        ):
            print(
                "[ERROR] Device authentication failed."
            )
            sock.close()
            return

        print(
            f"[DEVICE] {DEVICE_ID} connected."
        )

        receive_thread = threading.Thread(
            target=receive_loop,
            args=(sock,)
        )
        receive_thread.start()

        while not stop_event.wait(
            STATUS_INTERVAL
        ):
            send_packet(
                sock,
                {
                    "type": "device_status",
                    "status": "online",
                    "metadata": metadata()
                }
            )

    except KeyboardInterrupt:
        print(
            "\n[DEVICE] Stopping."
        )

    except Exception as error:
        print(
            f"[ERROR] {error}"
        )

    finally:
        stop_event.set()

        try:
            send_packet(
                sock,
                {
                    "type": "quit"
                }
            )
        except Exception:
            pass

        try:
            sock.close()
        except Exception:
            pass

        if "receive_thread" in locals():
            receive_thread.join(
                timeout=2
            )


if __name__ == "__main__":
    main()
