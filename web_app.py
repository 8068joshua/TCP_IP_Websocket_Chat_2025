import asyncio
import json
import os
from pathlib import Path
import ssl
import struct

from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel
import uvicorn


load_dotenv()


CORE_HOST = os.getenv(
    "CORE_HOST",
    "127.0.0.1"
)
CORE_PORT = int(
    os.getenv(
        "CORE_PORT",
        "9000"
    )
)
CORE_CA_FILE = os.getenv(
    "CORE_CA_FILE",
    "certs/server.crt"
)

SERVICE_API_KEY = os.getenv(
    "SERVICE_API_KEY",
    ""
)

WEB_HOST = os.getenv(
    "WEB_HOST",
    "0.0.0.0"
)
WEB_PORT = int(
    os.getenv(
        "WEB_PORT",
        "8080"
    )
)

HEADER_SIZE = 4
MAX_MESSAGE_SIZE = 1024 * 1024

BASE_DIR = Path(__file__).resolve().parent
INDEX_FILE = BASE_DIR / "static" / "index.html"

app = FastAPI(
    title="LocalOps Web Gateway"
)


# =========================================================
# Async TCP Framing
# =========================================================

def create_client_ssl_context():
    context = ssl.create_default_context(
        ssl.Purpose.SERVER_AUTH,
        cafile=CORE_CA_FILE
    )

    # Development certificate pinning.
    # Production: use a DNS name and hostname verification.
    context.check_hostname = False

    return context


async def open_core_connection():
    return await asyncio.open_connection(
        CORE_HOST,
        CORE_PORT,
        ssl=create_client_ssl_context(),
        server_hostname=None
    )


async def write_packet(writer, packet, lock=None):
    body = json.dumps(
        packet,
        ensure_ascii=False,
        separators=(",", ":")
    ).encode("utf-8")

    if len(body) > MAX_MESSAGE_SIZE:
        raise ValueError(
            "Message too large."
        )

    frame = struct.pack(
        "!I",
        len(body)
    ) + body

    if lock is None:
        writer.write(
            frame
        )
        await writer.drain()
        return

    async with lock:
        writer.write(
            frame
        )
        await writer.drain()


async def read_packet(reader):
    try:
        header = await reader.readexactly(
            HEADER_SIZE
        )
    except asyncio.IncompleteReadError:
        return None

    body_length = struct.unpack(
        "!I",
        header
    )[0]

    if body_length <= 0 or body_length > MAX_MESSAGE_SIZE:
        raise ValueError(
            "Invalid frame length."
        )

    body = await reader.readexactly(
        body_length
    )

    return json.loads(
        body.decode("utf-8")
    )


# =========================================================
# Web UI
# =========================================================

@app.get("/")
async def index():
    return FileResponse(
        INDEX_FILE
    )


@app.get("/health")
async def health():
    return {
        "status": "ok"
    }


@app.websocket("/ws")
async def websocket_bridge(websocket: WebSocket):
    await websocket.accept()

    try:
        reader, writer = await open_core_connection()
    except Exception as error:
        await websocket.send_json(
            {
                "type": "error",
                "message": (
                    f"Core connection failed: {error}"
                )
            }
        )
        await websocket.close()
        return

    write_lock = asyncio.Lock()

    async def browser_to_core():
        try:
            while True:
                packet = await websocket.receive_json()

                if not isinstance(
                    packet,
                    dict
                ):
                    continue

                await write_packet(
                    writer,
                    packet,
                    write_lock
                )

        except WebSocketDisconnect:
            try:
                await write_packet(
                    writer,
                    {
                        "type": "quit"
                    },
                    write_lock
                )
            except Exception:
                pass

    async def core_to_browser():
        while True:
            packet = await read_packet(
                reader
            )

            if packet is None:
                break

            if packet.get(
                "type"
            ) == "ping":
                await write_packet(
                    writer,
                    {
                        "type": "pong"
                    },
                    write_lock
                )
                continue

            await websocket.send_json(
                packet
            )

    tasks = [
        asyncio.create_task(
            browser_to_core()
        ),
        asyncio.create_task(
            core_to_browser()
        )
    ]

    done, pending = await asyncio.wait(
        tasks,
        return_when=asyncio.FIRST_COMPLETED
    )

    for task in pending:
        task.cancel()

    writer.close()

    try:
        await writer.wait_closed()
    except Exception:
        pass

    try:
        await websocket.close()
    except Exception:
        pass


# =========================================================
# External HTTP API
# =========================================================

class AlertRequest(BaseModel):
    source: str
    level: str = "info"
    message: str


class DeviceStatusRequest(BaseModel):
    device_id: str
    status: str
    metadata: dict | None = None


def verify_http_api_key(api_key):
    if not SERVICE_API_KEY:
        raise HTTPException(
            status_code=500,
            detail="SERVICE_API_KEY is not configured."
        )

    if api_key != SERVICE_API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key."
        )


async def service_request(packet):
    reader, writer = await open_core_connection()

    try:
        await write_packet(
            writer,
            {
                "type": "service_auth",
                "api_key": SERVICE_API_KEY
            }
        )

        auth_response = await read_packet(
            reader
        )

        if (
            auth_response is None
            or auth_response.get("type") != "auth_ok"
        ):
            raise RuntimeError(
                "Core service authentication failed."
            )

        await write_packet(
            writer,
            packet
        )

        response = await read_packet(
            reader
        )

        return response

    finally:
        try:
            await write_packet(
                writer,
                {
                    "type": "quit"
                }
            )
        except Exception:
            pass

        writer.close()

        try:
            await writer.wait_closed()
        except Exception:
            pass


@app.post("/api/alert")
async def post_alert(
    request: AlertRequest,
    x_api_key: str = Header(
        default=""
    )
):
    verify_http_api_key(
        x_api_key
    )

    response = await service_request(
        {
            "type": "alert",
            "source": request.source,
            "level": request.level,
            "message": request.message
        }
    )

    return {
        "ok": True,
        "core_response": response
    }


@app.post("/api/device-status")
async def post_device_status(
    request: DeviceStatusRequest,
    x_api_key: str = Header(
        default=""
    )
):
    verify_http_api_key(
        x_api_key
    )

    response = await service_request(
        {
            "type": "device_status",
            "device_id": request.device_id,
            "status": request.status,
            "metadata": request.metadata
        }
    )

    return {
        "ok": True,
        "core_response": response
    }


if __name__ == "__main__":
    uvicorn.run(
        app,
        host=WEB_HOST,
        port=WEB_PORT
    )
