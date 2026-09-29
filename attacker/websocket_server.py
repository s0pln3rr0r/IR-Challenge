import os
import socket
import struct
import hashlib
import base64
from pathlib import Path

out = Path(__file__).resolve().parent.parent / "runtime" / "received"
try:
    out.mkdir(parents=True)
except FileExistsError:
    pass

WS_MAGIC = b"258EAFA5-E914-47DA-95CA-5AB9DC11B85B"


def decode_ws_frame(data):
    """Decode a single WebSocket text/binary frame."""
    if len(data) < 2:
        return None, data
    b1, b2 = data[0], data[1]
    opcode = b1 & 0x0F
    masked = (b2 & 0x80) != 0
    length = b2 & 0x7F
    offset = 2
    if length == 126:
        length = struct.unpack("!H", data[2:4])[0]
        offset = 4
    elif length == 127:
        length = struct.unpack("!Q", data[2:10])[0]
        offset = 10
    if masked:
        mask = data[offset:offset + 4]
        offset += 4
    payload = data[offset:offset + length]
    if masked:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return opcode, payload, data[offset + length:]


def encode_ws_frame(payload, opcode=0x1):
    """Encode a WebSocket frame (unmasked server->client)."""
    frame = bytearray([0x80 | opcode])
    length = len(payload)
    if length < 126:
        frame.append(length)
    elif length < 65536:
        frame.append(126)
        frame.extend(struct.pack("!H", length))
    else:
        frame.append(127)
        frame.extend(struct.pack("!Q", length))
    frame.extend(payload)
    return bytes(frame)


def handle_client(conn):
    """Handle a WebSocket client connection."""
    try:
        # Read HTTP upgrade request
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                return
            data += chunk

        # Parse the WebSocket key from headers
        headers = data.decode("utf-8", errors="replace")
        key = ""
        for line in headers.split("\r\n"):
            if line.lower().startswith("sec-websocket-key:"):
                key = line.split(":", 1)[1].strip()
                break

        if not key:
            return

        # Compute accept key
        accept_key = base64.b64encode(
            hashlib.sha1(key.encode() + WS_MAGIC).digest()
        ).decode()

        # Send upgrade response
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: {}\r\n"
            "\r\n"
        ).format(accept_key)
        conn.sendall(response.encode())

        # Read the incoming frame
        buf = b""
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            buf += chunk
            result = decode_ws_frame(buf)
            if result is None:
                continue
            opcode, payload, buf = result
            if opcode == 0x8:  # Close frame
                break
            if opcode in (0x1, 0x2):  # Text or Binary
                # Save payload
                with open(str(out / "websocket_payload"), 'wb') as f:
                    f.write(payload)
                # Send OK response
                conn.sendall(encode_ws_frame(b"OK", 0x1))
                break
    except Exception as e:
        print("WS server error: {}".format(e), file=__import__('sys').stderr)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 8080))
    server.listen(5)
    server.settimeout(None)

    while True:
        try:
            conn, addr = server.accept()
            handle_client(conn)
        except Exception as e:
            print("WS server accept error: {}".format(e), file=__import__('sys').stderr)


if __name__ == "__main__":
    main()
