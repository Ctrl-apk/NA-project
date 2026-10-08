# BinHTTP — HTTP in Binary

> **Course Project · Two Tracks, One Protocol**
> Networks Architecture · Version 1.0

A minimal binary-framed request/response protocol that carries the same semantics as HTTP (method, path, status, headers, body) while replacing all text parsing with fixed-width integers and length-prefixed fields.

---

## Table of Contents

1. [Overview](#overview)
2. [Protocol Design](#protocol-design)
   - [Frame Layout](#frame-layout)
   - [REQUEST Frame](#request-frame)
   - [RESPONSE Frame](#response-frame)
   - [Header Block Encoding](#header-block-encoding)
   - [The Unknown-Frame Rule](#the-unknown-frame-rule)
3. [Project Structure](#project-structure)
4. [Building](#building)
5. [Running](#running)
   - [Track 1 — bserve (the server)](#track-1--bserve-the-server)
   - [Track 2 — bcurl (the client)](#track-2--bcurl-the-client)
6. [Annotated Hexdump](#annotated-hexdump)
7. [Error Codes](#error-codes)
8. [Design Decisions](#design-decisions)
9. [What You Hand In](#what-you-hand-in)

---

## Overview

```
client                          server
  │── TCP SYN ──────────────────▶│
  │◀─ SYN-ACK ──────────────────│
  │── ACK ──────────────────────▶│
  │                              │
  │── REQUEST frame ────────────▶│   one binary frame
  │◀─ RESPONSE frame ───────────│   one binary frame
  │                              │
  │   (connection stays open)    │
```

- One TCP connection carries exactly **one request → one response**.
- Every integer is **big-endian**.
- The client **never opens a second connection**.
- The server **never closes the socket first**.

---

## Protocol Design

### Frame Layout

Every message is exactly **one frame** with a 9-byte fixed header followed by a variable payload:

```
Byte  0      ┌─────────────────────────────────────────────┐
             │  VER  (1 byte)   — always 0x01              │
Byte  1      ├─────────────────────────────────────────────┤
             │  FRAME_TYPE (1 byte)                        │
             │    0x01 = REQUEST   0x02 = RESPONSE         │
Byte  2      ├─────────────────────────────────────────────┤
             │  FLAGS (1 byte)                             │
             │    0x01 = END_STREAM                        │
Bytes 3–6    ├─────────────────────────────────────────────┤
             │  PAYLOAD_LENGTH  (uint32_t, big-endian)     │
             │  — total bytes that follow this header      │
Bytes 7–8    ├─────────────────────────────────────────────┤
             │  HDR_BLOCK_LEN   (uint16_t, big-endian)     │
             │  — byte size of the header block section    │
             ├─────────────────────────────────────────────┤
             │  variable section  (see below)              │
             └─────────────────────────────────────────────┘
```

**Why these widths?**  
HTTP/2 chose 24 / 8 / 8 / 31 bits for its frame header. We use 8 / 8 / 8 / 32 / 16:
- `VER` in 1 byte — 255 future versions is plenty.  
- `FRAME_TYPE` in 1 byte — 255 types, easily extensible.  
- `FLAGS` in 1 byte — 8 independent flag bits, matches HTTP/2.  
- `PAYLOAD_LENGTH` in 4 bytes (uint32) — up to 4 GB per frame; we cap at 10 MB in practice.  
- `HDR_BLOCK_LEN` in 2 bytes (uint16) — up to 64 KB of headers, more than enough.

---

### REQUEST Frame

```
Byte  9      METHOD       (0x01=GET  0x02=POST  0x03=HEAD)
Byte  10     PATH_LEN     (uint8_t, 0–255)
Bytes 11..   PATH         (PATH_LEN bytes, UTF-8)
…            HEADER BLOCK (HDR_BLOCK_LEN bytes)
…            BODY         (remaining bytes, 0 for GET)
```

---

### RESPONSE Frame

```
Byte  9      STATUS_CLASS   (0x02=2xx  0x04=4xx  0x05=5xx)
Byte  10     REASON_LEN     (uint8_t, 0–255)
Bytes 11..   REASON         (REASON_LEN bytes, UTF-8 e.g. "OK")
…            HEADER BLOCK   (HDR_BLOCK_LEN bytes)
…            BODY           (remaining bytes)
```

The exact three-digit HTTP status code is carried in the `Status` header.

---

### Header Block Encoding

The header block is a flat sequence of length-prefixed name/value pairs (a nod to HPACK's first two mechanisms):

```
┌──────────┬──────────────┬──────────┬──────────────┐
│ NAME_LEN │  NAME bytes  │ VAL_LEN  │  VALUE bytes │
│  1 byte  │  NAME_LEN B  │  1 byte  │  VAL_LEN B   │
└──────────┴──────────────┴──────────┴──────────────┘
  repeated for every header
```

The ten well-known header names (numbered 0–9):

| # | Header Name    |
|---|----------------|
| 0 | Host           |
| 1 | Content-Type   |
| 2 | Content-Length |
| 3 | Accept         |
| 4 | User-Agent     |
| 5 | Authorization  |
| 6 | Cache-Control  |
| 7 | Location       |
| 8 | Status         |
| 9 | Connection     |

**Mandatory server headers:** `Status`, `Content-Type`, `Content-Length`, `Connection`  
**Mandatory client header:** `Host`

---

### The Unknown-Frame Rule

> **A receiver that encounters a FRAME_TYPE it does not recognise MUST skip the frame cleanly.**

It reads `PAYLOAD_LENGTH` from bytes 3–6, discards exactly that many bytes, and reads the next frame. It must **not** close the connection. This is how the protocol leaves room for version 2 frame types.

---

## Project Structure

```
.
├── frame.h               # Shared protocol constants, types, and API
├── frame.c               # Frame encode / decode library
├── bserve.c              # Track 1 — the server
├── bcurl.c               # Track 2 — the client
├── Makefile              # Build system
├── spec.md               # Full two-page protocol specification
├── hexdump_annotated.txt # Byte-level annotated hexdump of one exchange
└── www/
    └── index.html        # Test file served by bserve
```

---

## Building

### Prerequisites

| Platform | Toolchain |
|---|---|
| Linux / macOS | `gcc` (any recent version) + `make` |
| Windows | [MSYS2](https://www.msys2.org/) with `mingw-w64-x86_64-gcc` and `make` |

### Linux / macOS

```bash
make all
```

### Windows (MSYS2 MinGW shell)

Open the **MSYS2 MinGW 64-bit** shell, then:

```bash
cd /c/Users/ASUS/Desktop/network_archi
make all
```

Or compile directly with gcc from PowerShell:

```powershell
C:\msys64\usr\bin\bash.exe -lc "export PATH=/mingw64/bin:$PATH; cd /c/Users/ASUS/Desktop/network_archi && make all"
```

Both commands produce:

```
bserve.exe   — the server binary
bcurl.exe    — the client binary
```

### Clean

```bash
make clean
```

---

## Running

### Track 1 — bserve (the server)

```bash
./bserve <root-dir> <port>
```

**Example:**

```bash
./bserve ./www 9000
```

```
[bserve] serving ./www on port 9000
[bserve] connection from 127.0.0.1:54321
[bserve] REQUEST method=0x01 path=/index.html
[bserve] 200 OK  ./www/index.html  (127 bytes)
```

**What it does:**

- Listens for TCP connections on `<port>`
- Reads one binary REQUEST frame per connection
- Maps the request path to a file under `<root-dir>`
- Sends a RESPONSE frame with status + headers + file bytes
- Sends `404` if the file does not exist
- Sends `400` if the frame is malformed or contains a path traversal (`../`)
- Sends `500` on file I/O errors
- **Keeps the connection open** after sending the response

---

### Track 2 — bcurl (the client)

```bash
./bcurl [-v] <host>:<port>/<path>
```

**Example — fetch a page:**

```bash
./bcurl localhost:9000/index.html
```

**Example — verbose mode (hexdumps every frame):**

```bash
./bcurl -v localhost:9000/index.html
```

```
[bcurl] connecting to localhost:9000 path=/index.html

╔══════════════════════════════════════════════════════╗
║         REQUEST FRAME — annotated hexdump           ║
╚══════════════════════════════════════════════════════╝
  Byte  0      : VER           = 0x01  (version 1)
  Byte  1      : FRAME_TYPE    = 0x01  (REQUEST)
  Byte  2      : FLAGS         = 0x01  (END_STREAM)
  Bytes 3-6    : PAYLOAD_LEN   = 56 bytes
  Bytes 7-8    : HDR_BLOCK_LEN = 41 bytes
  Byte  9      : METHOD        = 0x01  (GET)
  Byte  10     : PATH_LEN      = 11
  Bytes 11-21  : PATH          = "/index.html"

── REQUEST (raw bytes)  (63 bytes) ──
  0000  01 01 01 00 00 00 38 00 29 01 0b 2f 69 6e 64 65  |......8.)../inde|
  0010  78 2e 68 74 6d 6c 04 48 6f 73 74 0e 6c 6f 63 61  |x.html.Host.loca|
  0020  6c 68 6f 73 74 3a 39 30 30 30 0a 55 73 65 72 2d  |lhost:9000.User-|
  0030  41 67 65 6e 74 09 62 63 75 72 6c 2f 31 2e 30     |Agent.bcurl/1.0|
...
[bcurl] status_class=0x02 reason="OK"
[bcurl]   Status: 200
[bcurl]   Content-Type: text/html
[bcurl]   Content-Length: 127
[bcurl]   Connection: keep-alive
<!DOCTYPE html>
<html>...
```

**What it does:**

- Builds one binary REQUEST frame (GET method)
- Sends it over **one TCP connection** (never opens a second)
- Reads the RESPONSE frame
- Prints headers to `stderr`, body to `stdout`
- With `-v`: hexdumps and annotates both frames to `stderr`
- Exits **non-zero** on `4xx` or `5xx` status

---

## Annotated Hexdump

`hexdump_annotated.txt` contains a full byte-by-byte breakdown of one complete GET `/index.html` exchange. Key fields for the request frame:

```
Offset  Hex    Field
──────  ─────  ──────────────────────────────────────────────
00      01     VER = 0x01
01      01     FRAME_TYPE = REQUEST
02      01     FLAGS = END_STREAM
03–06   000038 PAYLOAD_LENGTH = 56 bytes
07–08   0029   HDR_BLOCK_LEN = 41 bytes
09      01     METHOD = GET
0a      0b     PATH_LEN = 11
0b–15   /index.html
16–3e          Header block: Host + User-Agent
```

And for the response:

```
Offset  Hex    Field
──────  ─────  ──────────────────────────────────────────────
00      01     VER = 0x01
01      02     FRAME_TYPE = RESPONSE
02      01     FLAGS = END_STREAM
03–06   0000c7 PAYLOAD_LENGTH = 199 bytes
07–08   0048   HDR_BLOCK_LEN = 72 bytes
09      02     STATUS_CLASS = 2xx
0a      02     REASON_LEN = 2
0b–0c   OK
0d–57          Header block: Status + Content-Type + Content-Length + Connection
58–d6          Body: 127 bytes of HTML
```

---

## Error Codes

| Situation | Status class | Reason |
|---|---|---|
| File found and readable | `0x02` (2xx) | `200 OK` |
| Malformed frame / bad version | `0x04` (4xx) | `400 Bad Request` |
| Path traversal attempt (`../`) | `0x04` (4xx) | `400 Bad Request` |
| File not found under root | `0x04` (4xx) | `404 Not Found` |
| File I/O error | `0x05` (5xx) | `500 Internal Server Error` |

---

## Design Decisions

**Why a fixed 9-byte header?**  
It is always fully readable in one `recv` call, decoupling framing from payload parsing. No state machine needed to find the start of a frame.

**Why `PAYLOAD_LENGTH` counts from byte 7 (not byte 0)?**  
The 9 fixed header bytes are always present; the length field only needs to describe the variable part. This matches HTTP/2's frame length convention and avoids always subtracting a constant.

**Why STATUS_CLASS instead of the full 3-digit code?**  
Three classes (2xx / 4xx / 5xx) fit in one nibble. The exact code travels in the `Status` header, which is already length-prefixed and human-readable — no extra fixed field needed.

**Why length-prefix headers instead of null-termination?**  
Null-terminated fields require scanning; length-prefixed fields allow `memcpy` directly into a fixed buffer with a single bounds check. This is also how HPACK's literal header field encoding works.

**The one rule you cannot skip:**  
A receiver that sees an unknown `FRAME_TYPE` must skip it by reading `PAYLOAD_LENGTH` bytes and discarding them. This is what allows a future version 2 to introduce new frame types (e.g. PING, PUSH_PROMISE) without breaking version 1 implementations.

---

## What You Hand In

1. **`spec.md`** — The two-page protocol specification. Enough for a stranger to implement a compatible peer.
2. **`bserve.c` + `bcurl.c` + `frame.c` + `frame.h`** — The working programs.
3. **`hexdump_annotated.txt`** — Annotated hexdump of one complete request and response, with every byte explained.

> *In pairs: one server, one client, and the only thing that crosses between you is the spec. A client that only works against its own server is an implementation, not a protocol.*

---

## License

MIT — free to use, fork, and learn from.
