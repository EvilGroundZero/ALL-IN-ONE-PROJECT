#!/usr/bin/env python3
"""
DNS Tunnel Server
=================
Listens for specially crafted DNS TXT queries, extracts the
base32-encoded file data hidden in the subdomain labels, and
reassembles the original file on disk.

Tunnel Protocol
---------------
  START : start.<b32_filename>.<total_chunks_hex>.<domain>
  CHUNK : <seq_hex>.<b32_data>.<domain>
  END   : end.<domain>

The server replies with a TXT record containing an ACK string
so the client knows each packet was received.

Usage
-----
  python server.py                      # port 5353, domain tunnel.test
  python server.py --port 53            # standard DNS port (needs root/admin)
  python server.py --domain corp.local  # custom domain
"""

import os
import base64
import argparse
from dnslib import QTYPE, RR, TXT
from dnslib.server import DNSServer, BaseResolver


# ─────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────

def b32decode_nopad(s: str) -> bytes:
    """
    Decode a base32 string whose '=' padding was stripped by the client.
    We restore the padding before calling the standard library decoder.
    """
    s = s.upper()
    padding = (8 - len(s) % 8) % 8   # how many '=' signs are missing
    return base64.b32decode(s + "=" * padding)


# ─────────────────────────────────────────────────────────────
# Custom Resolver  (the core of the tunnel server)
# ─────────────────────────────────────────────────────────────

class TunnelResolver(BaseResolver):
    """
    Every incoming DNS query is routed through resolve().
    We inspect the subdomain labels to decide whether it is
    a START, CHUNK, or END tunnel packet.
    """

    def __init__(self, tunnel_domain: str, output_dir: str):
        self.domain    = tunnel_domain.lower()   # e.g.  "tunnel.test"
        self.out_dir   = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self._reset_state()

    # ── Transfer state ──────────────────────────────────────

    def _reset_state(self):
        """Clear everything ready for the next file transfer."""
        self.filename  = "output.bin"
        self.total     = None        # expected number of chunks (int)
        self.chunks    = {}          # {seq_int: bytes}
        self.receiving = False

    # ── DNS boilerplate ─────────────────────────────────────

    def _txt_reply(self, request, message: str):
        """Build a minimal DNS reply carrying a single TXT record."""
        reply = request.reply()
        reply.add_answer(
            RR(request.q.qname, QTYPE.TXT, rdata=TXT(message))
        )
        return reply

    # ── Main entry point ────────────────────────────────────

    def resolve(self, request, handler):
        # Normalise: dnslib FQDNs end with '.'
        qname = str(request.q.qname).lower().rstrip(".")

        # Silently ignore anything that is not our tunnel domain
        if not (qname == self.domain or qname.endswith("." + self.domain)):
            return self._txt_reply(request, "NOT_TUNNEL")

        # Strip the tunnel domain suffix to isolate the subdomain part
        if qname == self.domain:
            sub = ""
        else:
            # e.g.  "0001.MFRA2YTB.tunnel.test"  →  "0001.MFRA2YTB"
            sub = qname[: -(len(self.domain) + 1)]

        labels = sub.split(".") if sub else []

        if not labels:
            return self._txt_reply(request, "NOOP")

        tag = labels[0].lower()

        if tag == "start":
            return self._handle_start(request, labels)
        elif tag == "end":
            return self._handle_end(request)
        elif self.receiving:
            return self._handle_chunk(request, labels)
        else:
            return self._txt_reply(request, "NOT_RECEIVING")

    # ── Packet handlers ─────────────────────────────────────

    def _handle_start(self, request, labels):
        """
        Format:  start  <b32_filename>  <total_hex>
        Example: start  NBSWY3DPEB3W64TMMQ  0028
        """
        if len(labels) < 3:
            print("[!] Malformed START packet – expected 3 labels")
            return self._txt_reply(request, "START_ERR")
        try:
            self.filename  = b32decode_nopad(labels[1]).decode()
            self.total     = int(labels[2], 16)
            self.chunks    = {}
            self.receiving = True
            print(f"\n[>] New transfer starting")
            print(f"    Filename : {self.filename}")
            print(f"    Chunks   : {self.total}")
            return self._txt_reply(request, "START_ACK")
        except Exception as exc:
            print(f"[!] START parse error: {exc}")
            return self._txt_reply(request, "START_ERR")

    def _handle_chunk(self, request, labels):
        """
        Format:  <seq_hex>  <b32_data>
        Example: 000a       MFRA2YTBMQ3TEMZU
        """
        if len(labels) < 2:
            return self._txt_reply(request, "CHUNK_ERR")
        try:
            seq  = int(labels[0], 16)
            data = b32decode_nopad(labels[1])
            self.chunks[seq] = data
            print(f"    Chunk [{seq + 1:>4} / {self.total}]  "
                  f"{len(data):>3} B  "
                  f"(received {len(self.chunks)} / {self.total})")
            return self._txt_reply(request, "ACK")
        except Exception as exc:
            print(f"[!] Chunk parse error: {exc}")
            return self._txt_reply(request, "CHUNK_ERR")

    def _handle_end(self, request):
        """Format: end"""
        if not self.receiving:
            return self._txt_reply(request, "END_NOOP")

        missing = self.total - len(self.chunks)
        if missing:
            print(f"[!] Transfer incomplete – {missing} chunk(s) missing.")
        else:
            self._save_file()

        self._reset_state()
        return self._txt_reply(request, "END_ACK")

    # ── File reconstruction ──────────────────────────────────

    def _save_file(self):
        """Reassemble chunks in order and write to disk."""
        raw  = b"".join(self.chunks[i] for i in sorted(self.chunks))
        name = os.path.basename(self.filename)      # safety: strip any path
        path = os.path.join(self.out_dir, name)

        with open(path, "wb") as fh:
            fh.write(raw)

        print(f"\n[+] File saved  →  {path}  ({len(raw):,} bytes)\n")


# ─────────────────────────────────────────────────────────────
# Minimal logger  (only prints errors; suppresses per-packet noise)
# ─────────────────────────────────────────────────────────────

class QuietLogger:
    def log_recv(self, *a):      pass
    def log_send(self, *a):      pass
    def log_request(self, *a):   pass
    def log_reply(self, *a):     pass
    def log_truncated(self, *a): pass
    def log_data(self, *a):      pass
    def log_error(self, handler, e):
        print(f"[!] DNS error: {e}")


# ─────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="DNS Tunnel Server")
    ap.add_argument("--port",   "-p", type=int, default=5353,
                    help="UDP port to listen on  (default: 5353; use 53 as root)")
    ap.add_argument("--domain", "-d", default="tunnel.test",
                    help="Tunnel domain suffix  (default: tunnel.test)")
    ap.add_argument("--output", "-o", default="received",
                    help="Directory for received files  (default: received/)")
    args = ap.parse_args()

    resolver = TunnelResolver(args.domain, args.output)
    server   = DNSServer(resolver, port=args.port,
                         address="0.0.0.0", logger=QuietLogger())

    print("=" * 48)
    print("  DNS Tunnel Server")
    print("=" * 48)
    print(f"  Listening on  : 0.0.0.0:{args.port}  (UDP)")
    print(f"  Tunnel domain : {args.domain}")
    print(f"  Output dir    : {args.output}/")
    print(f"  Press Ctrl+C to stop")
    print("=" * 48)

    try:
        server.start()          # blocking
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")
        server.stop()


if __name__ == "__main__":
    main()
