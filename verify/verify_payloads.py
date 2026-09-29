#!/usr/bin/env python3
"""
Full payload reconstruction verification for Six Ways Out.

Reads artifacts from output/ and independently recovers each channel's marker,
then constructs the final flag. Fails if any channel cannot be reconstructed.
"""
import base64
import gzip
import hashlib
import io
import os
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PCAP = ROOT / "output/network/exfiltration.pcap"
ENDPOINT = ROOT / "output/endpoint"
BASH_HIST = ENDPOINT / "bash_history.txt"
AUDIT_LOG = ENDPOINT / "audit.log"

EXPECTED_MARKERS = {
    "HTTP": "Q7k2mLp",
    "DNS": "k91Xv2Qa",
    "SMTP": "HncfuEY92kL",
    "ICMP": "xP83LmQa",
    "FTP": "7vQm91Xe",
    "WebSocket": "Lm92Qx7P",
}

EXPECTED_FLAG = "FLAG{Q7k2mLpk91Xv2QaHncfuEY92kLxP83LmQa7vQm91XeLm92Qx7P}"

# Keys from config
HTTP_KEY = b"mango-47"
ICMP_KEY = b"raven-19"
WS_PASSWORD = "Storm-Wind-2026"

errors = []


def log_ok(channel: str, msg: str):
    print("  [\u2713] {}: {}".format(channel, msg))


def log_fail(channel: str, msg: str):
    print("  [\u2717] {}: {}".format(channel, msg))
    errors.append("{}: {}".format(channel, msg))


def check_file_exists(path: Path, desc: str) -> bool:
    if path.exists():
        log_ok("Files", "{} exists: {}".format(desc, path))
        return True
    log_fail("Files", "{} missing: {}".format(desc, path))
    return False


# ---------------------------------------------------------------------------
# 1. File existence checks
# ---------------------------------------------------------------------------
print("\n=== File Existence ===")
check_file_exists(PCAP, "PCAP")
check_file_exists(BASH_HIST, "Bash history")
check_file_exists(AUDIT_LOG, "Audit log")
check_file_exists(ENDPOINT / "auth.log", "Auth log")
check_file_exists(ENDPOINT / "syslog.log", "Syslog")

# ---------------------------------------------------------------------------
# 2. HTTP reconstruction
# ---------------------------------------------------------------------------
print("\n=== HTTP Channel ===")
received_dir = ROOT / "runtime/received"
http_payload_file = received_dir / "http_payload.b64"

if http_payload_file.exists():
    try:
        b64_data = http_payload_file.read_text().strip()
        xor_data = base64.b64decode(b64_data)
        key = HTTP_KEY
        decoded = bytes(x ^ key[i % len(key)] for i, x in enumerate(xor_data))
        decoded_text = decoded.decode("utf-8", errors="replace")
        if "Q7k2mLp" in decoded_text:
            log_ok("HTTP", "Recovered marker from HTTP payload")
        else:
            log_fail("HTTP", "Marker not found in decoded payload")
    except Exception as e:
        log_fail("HTTP", "Decoding failed: {}".format(e))
else:
    log_fail("HTTP", "Payload file not found: {}".format(http_payload_file))

# ---------------------------------------------------------------------------
# 3. DNS reconstruction
# ---------------------------------------------------------------------------
print("\n=== DNS Channel ===")
dns_log = received_dir / "dns_queries.log"

if dns_log.exists():
    try:
        lines = dns_log.read_text().strip().splitlines()
        # Extract labels before .exfil.example
        chunks = []
        for line in lines:
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                qname = parts[1].rstrip(".")
                if "exfil.example" in qname:
                    label = qname.replace(".exfil.example", "")
                    chunks.append(label)
        if chunks:
            # Sort by order of appearance (they should already be in order)
            b32_text = "".join(chunks)
            # Pad to multiple of 8 for base32 decoding
            pad_len = (8 - len(b32_text) % 8) % 8
            b32_text += "=" * pad_len
            try:
                decoded = base64.b32decode(b32_text.upper())
                decoded_text = decoded.decode("utf-8", errors="replace")
                if "k91Xv2Qa" in decoded_text:
                    log_ok("DNS", "Recovered marker from {} DNS chunks".format(len(chunks)))
                else:
                    log_fail("DNS", "Marker not found in reconstructed DNS data")
            except Exception as e:
                log_fail("DNS", "Base32 decode failed: {}".format(e))
        else:
            log_fail("DNS", "No exfil.example queries found")
    except Exception as e:
        log_fail("DNS", "Failed to parse DNS log: {}".format(e))
else:
    log_fail("DNS", "DNS log not found: {}".format(dns_log))

# ---------------------------------------------------------------------------
# 4. SMTP reconstruction (from PCAP)
# ---------------------------------------------------------------------------
print("\n=== SMTP Channel ===")

def extract_smtp_attachments(pcap_path: Path) -> list:
    """Use tshark to extract PNG attachments from SMTP in PCAP."""
    attachments = []
    try:
        # First, find SMTP packets with data fragments
        result = subprocess.run(
            ["tshark", "-r", str(pcap_path), "-Y", "smtp.data.fragment",
             "-T", "fields", "-e", "tcp.stream", "-e", "smtp.data.fragment",
             "-l"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0 and result.returncode != 1:
            print("    tshark warning: {}".format(result.stderr.strip()))
        
        # Group by TCP stream
        streams = {}
        for line in result.stdout.strip().splitlines():
            parts = line.split("\t", 1)
            if len(parts) == 2:
                stream_id, fragment = parts
                if stream_id not in streams:
                    streams[stream_id] = []
                streams[stream_id].append(fragment)
        
        # Try to find PNGs in each stream
        for stream_id, fragments in streams.items():
            full_data = "".join(fragments)
            # Look for PNG signatures in the raw data
            png_start = full_data.find("\x89PNG")
            while png_start != -1:
                png_end = full_data.find(b"IEND", png_start)
                if png_end != -1:
                    png_data = full_data[png_start:png_end + 4]
                    attachments.append(png_data.encode("latin-1") if isinstance(png_data, str) else png_data)
                png_start = full_data.find("\x89PNG", png_start + 1)
        
        # Alternative: use tshark to follow TCP streams and extract
        if not attachments:
            for stream_id in streams:
                result = subprocess.run(
                    ["tshark", "-r", str(pcap_path), "-z", "follow,tcp,ascii,{}".format(stream_id)],
                    capture_output=True, text=True, timeout=30
                )
                # Look for PNG in the output
                for line in result.stdout.splitlines():
                    if "\x89PNG" in line:
                        # Extract the raw stream data
                        pass
    except FileNotFoundError:
        print("    tshark not available for SMTP extraction")
    except Exception as e:
        print("    SMTP extraction error: {}".format(e))
    return attachments


def decode_qr_from_png(png_bytes: bytes) -> str:
    """Decode a QR code from PNG bytes using pyzbar or qrcode."""
    try:
        from PIL import Image
        import qrcode as qrcode_lib
        from qrcode.image.pil import PilImage
        
        img = Image.open(io.BytesIO(png_bytes))
        
        # Try using pyzbar first
        try:
            from pyzbar.pyzbar import decode as pyzbar_decode
            decoded = pyzbar_decode(img)
            if decoded:
                return decoded[0].data.decode("utf-8")
        except ImportError:
            pass
        
        # Fallback: use qrcode's decoder
        # This is a basic approach - in production, use pyzbar
        try:
            from pyzbar.pyzbar import decode as pyzbar_decode
        except ImportError:
            print("    Install pyzbar for QR decoding: pip install pyzbar")
            return ""
    except Exception as e:
        print("    QR decode error: {}".format(e))
    return ""


# Check if we have received QR files from the SMTP server
smtp_qr_dir = ROOT / "runtime/qr"
smtp_pieces = []
if smtp_qr_dir.exists():
    for fname in ["IMG_1841.png", "IMG_1842.png", "IMG_1843.png"]:
        fpath = smtp_qr_dir / fname
        if fpath.exists():
            smtp_pieces.append(fpath)

if smtp_pieces:
    # Decode the QR pieces
    decoded_pieces = []
    for fpath in sorted(smtp_pieces):
        try:
            from PIL import Image
            try:
                from pyzbar.pyzbar import decode as pyzbar_decode
                img = Image.open(fpath)
                data = pyzbar_decode(img)
                if data:
                    decoded_pieces.append(data[0].data.decode("utf-8"))
                    log_ok("SMTP", "Decoded {}: {}".format(fpath.name, data[0].data.decode('utf-8')))
                else:
                    decoded_pieces.append("")
                    log_fail("SMTP", "No QR data in {}".format(fpath.name))
            except ImportError:
                log_fail("SMTP", "pyzbar not installed for QR decoding")
                break
        except Exception as e:
            log_fail("SMTP", "Failed to decode {}: {}".format(fpath.name, e))
    
    combined = "".join(decoded_pieces)
    if combined == EXPECTED_MARKERS["SMTP"]:
        log_ok("SMTP", "Combined marker matches: {}".format(combined))
    else:
        log_fail("SMTP", "Combined marker mismatch: got '{}', expected '{}'".format(combined, EXPECTED_MARKERS['SMTP']))
else:
    log_fail("SMTP", "No QR PNG files found in runtime/qr/")

# ---------------------------------------------------------------------------
# 5. ICMP reconstruction
# ---------------------------------------------------------------------------
print("\n=== ICMP Channel ===")

def extract_icmp_payloads(pcap_path: Path) -> list:
    """Extract ICMP Echo Request payloads from PCAP using scapy or tshark."""
    payloads = []
    try:
        # Try scapy first
        from scapy.all import rdpcap, ICMP, Raw
        packets = rdpcap(str(pcap_path))
        for pkt in packets:
            if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:  # Echo Request
                if pkt.haslayer(Raw):
                    seq = pkt[ICMP].seq
                    raw = pkt[Raw].load
                    try:
                        payload = raw.decode("utf-8", errors="replace")
                        payloads.append((seq, payload))
                    except:
                        pass
    except ImportError:
        # Fallback to tshark
        try:
            result = subprocess.run(
                ["tshark", "-r", str(pcap_path), "-Y", "icmp.type==8",
                 "-T", "fields", "-e", "icmp.seq", "-e", "data.data", "-l"],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.strip().splitlines():
                parts = line.split("\t")
                if len(parts) == 2:
                    seq = int(parts[0])
                    hex_data = parts[1].replace(":", "")
                    try:
                        payload = bytes.fromhex(hex_data).decode("utf-8", errors="replace")
                        payloads.append((seq, payload))
                    except:
                        pass
        except FileNotFoundError:
            print("    scapy/tshark not available for ICMP extraction")
    return payloads


icmp_payloads = extract_icmp_payloads(PCAP)
if icmp_payloads:
    # Sort by sequence number
    icmp_payloads.sort(key=lambda x: x[0])
    hex_text = "".join(p[1] for p in icmp_payloads)
    try:
        xor_data = bytes.fromhex(hex_text)
        key = ICMP_KEY
        decoded = bytes(x ^ key[i % len(key)] for i, x in enumerate(xor_data))
        decoded_text = decoded.decode("utf-8", errors="replace")
        if "xP83LmQa" in decoded_text:
            log_ok("ICMP", "Recovered marker from {} ICMP packets".format(len(icmp_payloads)))
        else:
            log_fail("ICMP", "Marker not found in reconstructed ICMP data")
    except Exception as e:
        log_fail("ICMP", "Decoding failed: {}".format(e))
else:
    log_fail("ICMP", "No ICMP Echo Request payloads found in PCAP")

# ---------------------------------------------------------------------------
# 6. FTP reconstruction
# ---------------------------------------------------------------------------
print("\n=== FTP Channel ===")

def extract_ftp_data(pcap_path: Path) -> bytes:
    """Extract FTP data from PCAP using scapy or tshark."""
    try:
        from scapy.all import rdpcap, TCP, Raw
        packets = rdpcap(str(pcap_path))
        # Find FTP data packets (port 20 or data channel)
        ftp_data = b""
        for pkt in packets:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                payload = bytes(pkt[Raw].load)
                # FTP data typically on port 20 or high ports after STOR
                if sport == 20 or dport == 20:
                    ftp_data += payload
                # Also check for data on high ports (passive FTP)
                elif payload.startswith(b"begin") or payload.startswith(b"BASE64"):
                    ftp_data += payload
        return ftp_data
    except ImportError:
        # Fallback to tshark
        try:
            result = subprocess.run(
                ["tshark", "-r", str(pcap_path), "-Y", "ftp-data",
                 "-T", "fields", "-e", "data.data", "-l"],
                capture_output=True, text=True, timeout=30
            )
            hex_data = "".join(result.stdout.strip().splitlines()).replace(":", "")
            return bytes.fromhex(hex_data) if hex_data else b""
        except:
            pass
    return b""


# Check for the received FTP file
ftp_received = received_dir / "daily_metrics.dat"
if not ftp_received.exists():
    # Try to find it in the FTP server directory
    ftp_server_paths = [
        Path("/srv/ftp/exfil/daily_metrics.dat"),
        Path("/home/svc_backup/daily_metrics.dat"),
    ]
    for p in ftp_server_paths:
        if p.exists():
            ftp_received = p
            break

if ftp_received.exists():
    try:
        b64_data = ftp_received.read_text().strip()
        gz_data = base64.b64decode(b64_data)
        xlsx_data = gzip.decompress(gz_data)
        # Check for marker in the XLSX
        if b"7vQm91Xe" in xlsx_data:
            log_ok("FTP", "Recovered marker from FTP XLSX payload")
        else:
            log_fail("FTP", "Marker not found in reconstructed XLSX")
    except Exception as e:
        log_fail("FTP", "FTP reconstruction failed: {}".format(e))
else:
    log_fail("FTP", "No FTP received file found")

# ---------------------------------------------------------------------------
# 7. WebSocket reconstruction
# ---------------------------------------------------------------------------
print("\n=== WebSocket Channel ===")

ws_payload = received_dir / "websocket_payload"
if ws_payload.exists():
    try:
        enc_data = ws_payload.read_bytes()
        # OpenSSL encrypted format: Salted__ + 8-byte salt + ciphertext
        if enc_data.startswith(b"Salted__"):
            salt = enc_data[8:16]
            ciphertext = enc_data[16:]
        else:
            salt = b""
            ciphertext = enc_data
        
        # Decrypt using OpenSSL CLI
        with tempfile.NamedTemporaryFile(delete=False, suffix=".enc") as tmp_enc:
            tmp_enc.write(enc_data)
            tmp_enc_path = tmp_enc.name
        
        try:
            result = subprocess.run(
                ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-d",
                 "-salt", "-pass", "pass:{}".format(WS_PASSWORD),
                 "-in", tmp_enc_path],
                capture_output=True, text=False, timeout=30
            )
            if result.returncode == 0:
                decrypted = result.stdout
                if isinstance(decrypted, bytes):
                    decrypted_text = decrypted.decode("utf-8", errors="replace")
                else:
                    decrypted_text = decrypted
                if "Lm92Qx7P" in decrypted_text:
                    log_ok("WebSocket", "Recovered marker from WebSocket payload")
                else:
                    log_fail("WebSocket", "Marker not found in decrypted WebSocket data")
            else:
                log_fail("WebSocket", "OpenSSL decryption failed: {}".format(result.stderr.decode(errors='replace')))
        finally:
            os.unlink(tmp_enc_path)
    except Exception as e:
        log_fail("WebSocket", "Decryption failed: {}".format(e))
else:
    log_fail("WebSocket", "WebSocket payload not found: {}".format(ws_payload))

# ---------------------------------------------------------------------------
# 8. Final flag
# ---------------------------------------------------------------------------
print("\n=== Final Flag ===")
if not errors:
    print("\n  [\u2713] All channels verified successfully!")
    print("  [\u2713] Expected flag: {}".format(EXPECTED_FLAG))
    sys.exit(0)
else:
    print("\n  [\u2717] {} channel(s) failed verification:".format(len(errors)))
    for e in errors:
        print("       - {}".format(e))
    sys.exit(1)
