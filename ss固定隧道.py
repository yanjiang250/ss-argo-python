import asyncio
import hashlib
import os
import platform
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import time
import urllib.request

from websockets.asyncio.server import serve
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


HOST = "127.0.0.1"
PORT = 13335
PASSWORD = "你的密码"
METHOD = "aes-128-gcm"
PATH = "/"

CLOUDFLARED_TOKEN = "你的固定隧道token"

KEY_LENGTH = 16
TAG_LENGTH = 16
MAX_CHUNK = 16383

TUNNEL_PROCESS = None
STOP_EVENT = None


def evp_bytes_to_key(password):
    result = b""
    previous = b""

    while len(result) < KEY_LENGTH:
        previous = hashlib.md5(previous + password).digest()
        result += previous

    return result[:KEY_LENGTH]


MASTER_KEY = evp_bytes_to_key(PASSWORD.encode())


def derive_subkey(salt):
    return HKDF(
        algorithm=hashes.SHA1(),
        length=KEY_LENGTH,
        salt=salt,
        info=b"ss-subkey"
    ).derive(MASTER_KEY)


def increment_nonce(nonce):
    for i in range(len(nonce)):
        if nonce[i] != 255:
            nonce[i] += 1
            return
        nonce[i] = 0

    raise ValueError("Nonce overflow")


def install_cloudflared():
    if platform.system() != "Linux":
        raise RuntimeError("仅支持 Linux")

    existing = shutil.which("cloudflared")

    if existing:
        return existing

    machine = platform.machine().lower()

    arch_map = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
        "armv7l": "armhf",
        "armv6l": "arm",
        "i386": "386",
        "i686": "386"
    }

    arch = arch_map.get(machine)

    if not arch:
        raise RuntimeError(f"不支持的 CPU 架构: {machine}")

    install_dir = os.path.expanduser("~/.local/bin")
    os.makedirs(install_dir, exist_ok=True)

    binary = os.path.join(install_dir, "cloudflared")

    if os.path.isfile(binary) and os.access(binary, os.X_OK):
        check = subprocess.run(
            [binary, "--version"],
            capture_output=True,
            text=True
        )

        if check.returncode == 0:
            return binary

    url = (
        "https://github.com/cloudflare/cloudflared/"
        f"releases/latest/download/cloudflared-linux-{arch}"
    )

    print("[*] 正在下载 cloudflared...")

    temp_path = None

    try:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "Python-Shadowsocks"}
        )

        with urllib.request.urlopen(request, timeout=120) as response:
            with tempfile.NamedTemporaryFile(
                dir=install_dir,
                delete=False
            ) as temp:
                temp_path = temp.name
                shutil.copyfileobj(response, temp)

        if os.path.getsize(temp_path) < 5 * 1024 * 1024:
            raise RuntimeError("下载文件大小异常")

        os.chmod(temp_path, 0o755)
        os.replace(temp_path, binary)

        check = subprocess.run(
            [binary, "--version"],
            capture_output=True,
            text=True,
            timeout=20
        )

        if check.returncode != 0:
            raise RuntimeError("cloudflared 验证失败")

        print("[+] cloudflared 安装成功")
        return binary

    except Exception:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
        raise


class WSReader:

    def __init__(self, ws):
        self.ws = ws
        self.buffer = bytearray()

    async def readexactly(self, size):
        while len(self.buffer) < size:
            data = await self.ws.recv()

            if not isinstance(data, bytes):
                raise ValueError("Invalid WebSocket frame")

            self.buffer.extend(data)

        result = bytes(self.buffer[:size])
        del self.buffer[:size]

        return result

    async def readsome(self, size):
        if not self.buffer:
            data = await self.ws.recv()

            if not isinstance(data, bytes):
                raise ValueError("Invalid WebSocket frame")

            self.buffer.extend(data)

        result = bytes(self.buffer[:size])
        del self.buffer[:size]

        return result


class SSReader:

    def __init__(self, reader):
        self.reader = reader
        self.cipher = None
        self.nonce = bytearray(12)
        self.buffer = bytearray()

    async def initialize(self):
        salt = await self.reader.readexactly(KEY_LENGTH)
        self.cipher = AESGCM(derive_subkey(salt))

    async def read_chunk(self):
        encrypted_length = await self.reader.readexactly(
            2 + TAG_LENGTH
        )

        length = self.cipher.decrypt(
            bytes(self.nonce),
            encrypted_length,
            None
        )

        increment_nonce(self.nonce)

        size = int.from_bytes(length, "big")

        if size > MAX_CHUNK:
            raise ValueError("Invalid chunk size")

        encrypted_data = await self.reader.readexactly(
            size + TAG_LENGTH
        )

        data = self.cipher.decrypt(
            bytes(self.nonce),
            encrypted_data,
            None
        )

        increment_nonce(self.nonce)

        return data

    async def readexactly(self, size):
        while len(self.buffer) < size:
            self.buffer.extend(await self.read_chunk())

        result = bytes(self.buffer[:size])
        del self.buffer[:size]

        return result

    async def readsome(self, size):
        if not self.buffer:
            self.buffer.extend(await self.read_chunk())

        result = bytes(self.buffer[:size])
        del self.buffer[:size]

        return result


class SSWriter:

    def __init__(self, ws):
        self.ws = ws
        self.salt = os.urandom(KEY_LENGTH)
        self.cipher = AESGCM(derive_subkey(self.salt))
        self.nonce = bytearray(12)
        self.initialized = False

    async def write(self, data):
        if not data:
            return

        if not self.initialized:
            await self.ws.send(self.salt)
            self.initialized = True

        for offset in range(0, len(data), MAX_CHUNK):
            chunk = data[offset:offset + MAX_CHUNK]

            encrypted_length = self.cipher.encrypt(
                bytes(self.nonce),
                struct.pack("!H", len(chunk)),
                None
            )

            increment_nonce(self.nonce)

            encrypted_data = self.cipher.encrypt(
                bytes(self.nonce),
                chunk,
                None
            )

            increment_nonce(self.nonce)

            await self.ws.send(
                encrypted_length + encrypted_data
            )


async def read_address(reader):
    atyp = (await reader.readexactly(1))[0]

    if atyp == 1:
        host = socket.inet_ntop(
            socket.AF_INET,
            await reader.readexactly(4)
        )

    elif atyp == 3:
        length = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(length)).decode("idna")

    elif atyp == 4:
        host = socket.inet_ntop(
            socket.AF_INET6,
            await reader.readexactly(16)
        )

    else:
        raise ValueError("Invalid address type")

    port = struct.unpack(
        "!H",
        await reader.readexactly(2)
    )[0]

    return host, port


async def relay_client(reader, writer):
    while True:
        data = await reader.readsome(MAX_CHUNK)

        if not data:
            break

        writer.write(data)
        await writer.drain()


async def relay_server(reader, writer):
    while True:
        data = await reader.read(MAX_CHUNK)

        if not data:
            break

        await writer.write(data)


async def handle_client(ws):
    request = getattr(ws, "request", None)
    path = getattr(request, "path", "/").split("?", 1)[0]

    if path != PATH:
        await ws.close(code=1008)
        return

    remote_writer = None
    tasks = []

    try:
        ws_reader = WSReader(ws)
        ss_reader = SSReader(ws_reader)

        await ss_reader.initialize()

        host, port = await read_address(ss_reader)

        remote_reader, remote_writer = await asyncio.open_connection(
            host,
            port
        )

        ss_writer = SSWriter(ws)

        tasks = [
            asyncio.create_task(
                relay_client(ss_reader, remote_writer)
            ),
            asyncio.create_task(
                relay_server(remote_reader, ss_writer)
            )
        ]

        done, pending = await asyncio.wait(
            tasks,
            return_when=asyncio.FIRST_COMPLETED
        )

        for task in pending:
            task.cancel()

        await asyncio.gather(
            *tasks,
            return_exceptions=True
        )

    except Exception:
        pass

    finally:
        for task in tasks:
            if not task.done():
                task.cancel()

        if remote_writer:
            remote_writer.close()

            try:
                await remote_writer.wait_closed()
            except Exception:
                pass


def start_tunnel(binary):
    global TUNNEL_PROCESS

    if not CLOUDFLARED_TOKEN or CLOUDFLARED_TOKEN.startswith("在这里"):
        raise RuntimeError("请填写 Cloudflare Tunnel Token")

    TUNNEL_PROCESS = subprocess.Popen([
        binary,
        "tunnel",
        "--no-autoupdate",
        "--protocol",
        "http2",
        "run",
        "--token",
        CLOUDFLARED_TOKEN
    ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL                            
    )

    time.sleep(3)

    if TUNNEL_PROCESS.poll() is not None:
        raise RuntimeError("Cloudflare Tunnel 启动失败")


def stop_tunnel():
    global TUNNEL_PROCESS

    if TUNNEL_PROCESS and TUNNEL_PROCESS.poll() is None:
        TUNNEL_PROCESS.terminate()

        try:
            TUNNEL_PROCESS.wait(timeout=5)
        except subprocess.TimeoutExpired:
            TUNNEL_PROCESS.kill()
            TUNNEL_PROCESS.wait()

    TUNNEL_PROCESS = None


async def main():
    binary = await asyncio.to_thread(install_cloudflared)

    async with serve(
        handle_client,
        HOST,
        PORT,
        max_size=None,
        compression=None,
        ping_interval=20,
    process_request=lambda connection, request: (
    connection.respond(
        404, "404 page not found\n"
    )
    if request.path.split("?", 1)[0] != PATH
    else (
        connection.respond(400, "Bad Request\n")
        if request.headers.get("Upgrade", "").lower() != "websocket"
        or "upgrade" not in request.headers.get("Connection", "").lower()
        else None
    )
    )
):
        try:
            start_tunnel(binary)

            print("Shadowsocks 运行成功")
            print("Cloudflare Tunnel 运行成功")
            print("Port:", PORT)
            print("Method:", METHOD)
            print("Transport: WebSocket")
            print("Path:", PATH)
            print("TLS: Disabled")
            print("Running...")

            while True:
                if TUNNEL_PROCESS.poll() is not None:
                    raise RuntimeError("Cloudflare Tunnel 意外退出")

                await asyncio.sleep(1)

        finally:
            stop_tunnel()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Shadowsocks 已停止")
    except Exception as e:
        print("启动失败:", e)
        stop_tunnel()
