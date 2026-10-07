# BinHTTP — Binary HTTP Protocol Specification
**Version 1.0** · Two pages · Enough for a stranger.

---

## 1. Purpose

BinHTTP is a compact, binary-framed request/response protocol that carries the same
semantics as HTTP/1.1 (method, path, status, headers, body) while eliminating all
text parsing.  Every integer is big-endian.  A single TCP connection carries exactly
one request followed by one response; **the connection is kept open** until the
response is fully delivered (the server never closes first).

---

## 2. Frame Layout

Every message — request or response — is exactly **one frame**.

```
 0       1       2       3       4       5       6       7  (byte offset)
 ┌───────┬───────────────┬───────┬───────────────────────────────────────────┐
 │  VER  │  FRAME TYPE   │ FLAGS │           PAYLOAD LENGTH (4 bytes)        │
 │ 1 B   │    1 B        │  1 B  │                 uint32_t                  │
 ├───────┴───────────────┴───────┴───────────────────────────────────────────┤
 │                    HEADER BLOCK LENGTH  (2 bytes, uint16_t)               │
 ├───────────────────────────────────────────────────────────────────────────┤
 │  STATUS / METHOD  (1 byte)                                                │
 ├───────────────────────────────────────────────────────────────────────────┤
 │  PATH / STATUS-REASON LENGTH  (1 byte, uint8_t)                          │
 ├───────────────────────────────────────────────────────────────────────────┤
 │  PATH / STATUS-REASON  (0–255 bytes, length given above)                  │
 ├───────────────────────────────────────────────────────────────────────────┤
 │  HEADER BLOCK  (HEADER BLOCK LENGTH bytes)                                │
 ├───────────────────────────────────────────────────────────────────────────┤
 │  BODY  (remaining bytes up to PAYLOAD LENGTH)                             │
 └───────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Fixed Header (10 bytes)

| Field               | Size     | Value / Meaning                        |
|---------------------|----------|----------------------------------------|
| VER                 | 1 byte   | `0x01` for this version                |
| FRAME TYPE          | 1 byte   | `0x01` = REQUEST, `0x02` = RESPONSE    |
| FLAGS               | 1 byte   | `0x01` = END_STREAM (body is complete) |
| PAYLOAD LENGTH      | 4 bytes  | uint32_t, total bytes that follow the fixed header (everything after byte 7) |
| HEADER BLOCK LENGTH | 2 bytes  | uint16_t, byte length of the header block section |

Total fixed header: **8 bytes**.

### 2.2 Variable Section (REQUEST frame, FRAME TYPE = 0x01)

| Field         | Size            | Meaning                                |
|---------------|-----------------|----------------------------------------|
| METHOD        | 1 byte          | `0x01`=GET  `0x02`=POST  `0x03`=HEAD  |
| PATH LENGTH   | 1 byte          | uint8_t, length of the path string     |
| PATH          | PATH LENGTH B   | UTF-8 path, e.g. `/index.html`         |
| HEADER BLOCK  | HDR BLOCK LEN B | Sequence of length-prefixed headers    |
| BODY          | remainder       | Request body (may be 0 bytes for GET)  |

### 2.3 Variable Section (RESPONSE frame, FRAME TYPE = 0x02)

| Field          | Size            | Meaning                                          |
|----------------|-----------------|--------------------------------------------------|
| STATUS CODE    | 1 byte          | HTTP status ÷ 100, e.g. `0x02`=2xx, `0x04`=4xx  |
| REASON LENGTH  | 1 byte          | uint8_t, length of the reason phrase             |
| REASON         | REASON LENGTH B | UTF-8 text, e.g. `OK` or `Not Found`             |
| HEADER BLOCK   | HDR BLOCK LEN B | Sequence of length-prefixed headers              |
| BODY           | remainder       | Response body bytes                              |

> **Why ÷100?**  Three status classes (2xx/4xx/5xx) fit in one nibble.  The exact
> three-digit code is carried in a `Status` header if needed.

---

## 3. Header Block Encoding

The header block is a flat sequence of (name, value) pairs.  Both name and value are
**length-prefixed** with a single byte (max 255 characters each).

```
┌──────────┬───────────────┬──────────┬───────────────┐
│ NAME LEN │  NAME bytes   │ VAL LEN  │  VALUE bytes  │
│  1 byte  │  NAME LEN B  │  1 byte  │  VAL LEN B   │
└──────────┴───────────────┴──────────┴───────────────┘
  (repeated for every header)
```

**Mandatory headers sent by the server:**
- `Content-Length` — decimal string representation of body byte count
- `Content-Type`   — MIME type, e.g. `text/html`

**Mandatory headers sent by the client:**
- `Host` — target hostname

The header names are the ten well-known HTTP names numbered 0–9 (a nod to HPACK's
first two mechanisms):

| #  | Header Name      |
|----|------------------|
| 0  | Host             |
| 1  | Content-Type     |
| 2  | Content-Length   |
| 3  | Accept           |
| 4  | User-Agent       |
| 5  | Authorization    |
| 6  | Cache-Control    |
| 7  | Location         |
| 8  | Status           |
| 9  | Connection       |

Names not in this table are sent as literal UTF-8 strings in the length-prefixed slot.

---

## 4. Frame Type Unknown Rule

> **A receiver that encounters a FRAME TYPE it does not recognise MUST skip the
> frame cleanly.**

Specifically: it reads the PAYLOAD LENGTH from bytes 4–7, discards exactly that many
bytes, and then reads the next frame.  It MUST NOT close the connection.  This is how
the protocol leaves room for version 2 frame types to be introduced without breaking
existing implementations.

---

## 5. Status Codes

| Byte value | Meaning           | Condition                                    |
|------------|-------------------|----------------------------------------------|
| `0x02`     | 200 OK            | File found and readable                      |
| `0x04`     | 400 Bad Request   | Frame is malformed (bad VER, impossible len) |
| `0x04`     | 404 Not Found     | Mapped path does not exist under root        |
| `0x05`     | 500 Server Error  | I/O failure reading the file                 |

The precise three-digit code is carried in the `Status` header (index 8).

---

## 6. Connection Lifecycle

```
client                          server
  │── TCP SYN ──────────────────────▶│
  │◀─ SYN-ACK ──────────────────────│
  │── ACK ──────────────────────────▶│
  │                                  │
  │── REQUEST frame ────────────────▶│  (one frame, END_STREAM set)
  │◀─ RESPONSE frame ───────────────│  (one frame, END_STREAM set)
  │                                  │
  │  (connection remains open)       │
```

- The client sends exactly **one** REQUEST frame per connection.  
- The server sends exactly **one** RESPONSE frame.  
- Neither side opens a second connection for the same exchange.  
- The server keeps the TCP socket open after the response (it does not call `close`).

---

## 7. Error Handling

| Situation                                   | Server action                    |
|---------------------------------------------|----------------------------------|
| VER field ≠ 0x01                            | Send 400, close after response   |
| PAYLOAD LENGTH > 10 MB                      | Send 400, close after response   |
| Path traversal (`../`)                      | Send 400, close after response   |
| File not found under root                   | Send 404                         |
| File I/O error                              | Send 500                         |
| Unknown FRAME TYPE                          | Skip frame (see §4)              |

---

*End of specification — Version 1.0*
