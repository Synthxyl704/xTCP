import socket
import gzip
import mimetypes
import ssl
import time
import struct
import os

from typing import Optional, Dict, Union, List, Tuple
from email.utils import formatdate
from constants import (
    BUFFER_SIZE,
    CERTIFICATION_FILE,
    KEY_FILE,
    HTTP2_PREFACE,
    HTTP2_FRAME_HEADER_LEN,
    HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS,
    HTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
    HTTP2_FLAG_END_STREAM,
    HTTP2_FLAG_END_HEADERS,
    HTTP2_FLAG_ACK,
    HTTP2_FRAME_DATA,
    HTTP2_FRAME_HEADERS,
    HTTP2_FRAME_SETTINGS,
    HTTP2_FRAME_PUSH_PROMISE,
    HTTP2_FRAME_PING,
    HTTP2_FRAME_GOAWAY,
    HTTP2_FRAME_WINDOW_UPDATE,
    serverRunningStatus,
);

from management import SESSION_MANAGER, TRANSACTION_LOGGER;

### --- DNS --- ###


def DNS_LOOKUP(domainName: str) -> Union[str, None]: # i love how this thing does absolutely nothing
    DNS_database = {
        "localhost": "127.0.0.1",
        "localhost6": "::1",
    };

    return DNS_database.get(domainName.lower()); 


### --- USER AGENT PARSING --- ###
browserDatabase = [
    ("firefox", "Firefox", "Firefox/"),
    ("edg", "Edge", "Edg/"),
    ("chrome", "Chrome", "Chrome/"),
    ("safari", "Safari", None),
];

OS_Database = [
    ("Windows", ["windows"]),
    ("macOS", ["mac os x", "macos"]),
    ("Linux", ["linux"]),
    ("Android", ["android"]),
    ("iOS", ["iphone", "ipad"]),
];

def PARSE_USER_AGENT(userAgent: str) -> Dict[str, str]:
    info = {
        "browser": "unknown",
        "version": "unknown",
        "os": "unknown",
        "device": "unknown",
    };

    if not userAgent:
        return (info);

    for name, _, token in browserDatabase:
        if ((token and token) in userAgent):
            info["browser"] = name
            
            try:
                info["version"] = userAgent.split(token, 1)[1].split()[0];
            except:
                pass; # its okay if it doesnt get any browser version
            
            break;

    for (OS_Name, markers )in OS_Database:
        if any(something in userAgent.lower() for something in markers):
            info["os"] = OS_Name;
            break;

    return info;

### --- MIME TYPES --- ###
def getMIMEtype(filePath: str):
    mimeType, varThatIsNotUsed = mimetypes.guess_type(filePath);
    return (mimeType) or ("application/octet-stream");

### --- COMPRESSION --- ###
def COMPRESS_RESPONSE(data: bytes, encodeType: str) -> tuple[bytes, str]:
    # we're gonna do GZIP compression to send HTTP/1.1 data
    if "gzip" in encodeType:
        try:
            compressed = gzip.compress(data);
            
            if len(compressed) < len(data):
                return compressed, "gzip";
        except:
            pass;

    return data, "identity";

### --- HTTP/1.1 --- ###
def PARSE_HTTP_REQUEST(requestBytes: bytes):
    parts = requestBytes.split(b"\r\n\r\n", 1);
    
    headerPart = parts[0].decode("utf-8", errors="ignore");
    bodyPart = parts[1] if len(parts) > 1 else b"";
    
    lines = headerPart.split("\r\n");
    
    if not lines or not lines[0]:
        return None;

    reqLine = lines[0].split(" ");
    method = reqLine[0] if len(reqLine) > 0 else "GET";
    path = reqLine[1] if len(reqLine) > 1 else "/";
    version = reqLine[2] if len(reqLine) > 2 else "HTTP/1.1";
    headers = {};

    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1);
            headers[key.strip().lower()] = value.strip();

    return {
        "method": method,
        "path": path,
        "version": version,
        "headers": headers,
        "body": bodyPart,
    };


def BUILD_HTTP_RESPONSE(
    statusCode,
    contentType,
    contentLength,
    encoding="identity",
    connection="keep-alive",
    isTLS=False,
):
    statusMessages = {200: "OK", 404: "Not Found", 405: "Method Not Allowed"};
    statusMsg = statusMessages.get(statusCode, "Unknown");
    headers = [
        f"HTTP/1.1 {statusCode} {statusMsg}",
        f"Content-Type: {contentType}",
        f"Content-Length: {contentLength}",
        f"Connection: {connection}",
        f"Server: IsoAris_xTCP",
        f"Date: {formatdate(usegmt=True)}",
    ];

    if isTLS:
        headers.append("Strict-Transport-Security: max-age=31536000; includeSubDomains");

    if encoding != "identity":
        headers.append(f"Content-Encoding: {encoding}");

    return ("\r\n".join(headers) + "\r\n\r\n").encode("utf-8");


### --- HPACK (HTTP/2 Header Compression) --- ###
HPACK_STATIC_TABLE: List[Tuple[str, str]] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
]; # a buncha shit

def HPACK_DECODE_INTEGER(byteArrayData: bytes, currentPosition: int, prefixBits: int) -> Tuple[int, int]: # [value, newPosition]
    maxPrefix = (1 << prefixBits) - 1;
    value = byteArrayData[currentPosition] & maxPrefix;
    currentPosition += 1; # actually no idea what this does

    if (value < maxPrefix):
        return value, currentPosition;

    shift: int = 0;
    while currentPosition < len(byteArrayData):
        singularByte = byteArrayData[currentPosition];
        currentPosition += 1;
        value += (singularByte & 0x7F) << shift; # no idea #2
        
        if (singularByte & 0x80) == 0: # if AND returns 1 that means theres more bytes, if 0 that means terminate it
            break;
        
        shift += 7;

    return (value, currentPosition);


def HPACK_ENCODE_INTEGER(integerToEncode: int, prefixBits: int, prefixMask: int = 0) -> bytes:
    maxPrefix = (1 << prefixBits) - 1;
    # https://datatracker.ietf.org/doc/html/rfc7541#section-5.1
    
    if integerToEncode < maxPrefix:
        return bytes([prefixMask | integerToEncode]);

    output = bytearray([prefixMask | maxPrefix]); # its a bitwise OR 
    integerToEncode -= maxPrefix;
    
    while integerToEncode >= 128:
        output.append((integerToEncode % 128) + 128);
        integerToEncode //= 128;

    output.append(integerToEncode);
    return bytes(output);


def HPACK_DECODE_STRING(data: bytes, pos: int) -> Tuple[str, int]:
    if pos >= len(data):
        return "", pos;

    huffman = (data[pos] & 0x80) != 0;
    length, pos = HPACK_DECODE_INTEGER(data, pos, 7);
    raw = data[pos : pos + length];
    pos += length;

    if huffman:
        return "", pos;

    return raw.decode("utf-8", errors="ignore"), pos;


def HPACK_ENCODE_STRING(stringVal: str) -> bytes:
    raw = stringVal.encode("utf-8");
    # stringVal.endswith("ascii?");
    return HPACK_ENCODE_INTEGER(len(raw), 7, 0) + raw;

# len("你好") :: size = 2
# len("你好".encode("utf-8")) :: size = 6


def HPACK_GET_STATIC_HEADER(index: int) -> Tuple[str, str]:
    if index <= 0 or index > len(HPACK_STATIC_TABLE):
        return "", "";

    return HPACK_STATIC_TABLE[index - 1];


def HPACK_FIND_STATIC_INDEX(name: str, optionalValue: str) -> Optional[int]:
    for index, item in enumerate(HPACK_STATIC_TABLE, start=1):
        if optionalValue is None:
            if item[0] == name: 
                return index; # not sure if this simplicity is a good idea
        else:
            if (item[0] == name) and (item[1] == optionalValue):
                return index;

    return 0; 

# AI wrote this, no idea what it does
def HPACK_DECODE_HEADER_BLOCK(binaryData: bytes) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    pos = 0;

    while pos < len(binaryData):
        b = binaryData[pos]
        if b & 0x80:
            index, pos = HPACK_DECODE_INTEGER(binaryData, pos, 7)
            name, value = HPACK_GET_STATIC_HEADER(index)
            if name:
                headers[name] = value
            continue

        if (b & 0x40) or (b & 0x10) or (b & 0x00) == 0:
            if b & 0x40:
                (nameIndex, pos) = HPACK_DECODE_INTEGER(binaryData, pos, 6)
            else:
                (nameIndex, pos) = HPACK_DECODE_INTEGER(binaryData, pos, 4)

            if nameIndex == 0:
                (name, pos) = HPACK_DECODE_STRING(binaryData, pos)
            else:
                name, _ = HPACK_GET_STATIC_HEADER(nameIndex)
            (value, pos) = HPACK_DECODE_STRING(binaryData, pos)
            if name:
                headers[name.lower()] = value
            continue
        break
    return headers


def HPACK_ENCODE_RESPONSE_HEADERS(headers: Dict[str, str]) -> bytes:
    output = bytearray();
    status = headers.get(":status", "200");
    statusIndex = HPACK_FIND_STATIC_INDEX(":status", status);
    
    if statusIndex > 0:
        output.extend(HPACK_ENCODE_INTEGER(statusIndex, 7, 0x80));

    for key, value in headers.items():
        if key == ":status":
            continue;
        
        nameIndex = HPACK_FIND_STATIC_INDEX(key.lower(), None);
        
        if nameIndex > 0:
            output.extend(HPACK_ENCODE_INTEGER(nameIndex, 4, 0x00));
        else:
            output.extend(HPACK_ENCODE_INTEGER(0, 4, 0x00));
            output.extend(HPACK_ENCODE_STRING(key.lower()));

        output.extend(HPACK_ENCODE_STRING(str(value)));

    return bytes(output);


### --- HTTP/2 FRAME HANDLING --- ###
def BUILD_HTTP2_FRAME(
    frameType: int, flags: int, streamId: int, payload: bytes = b""
) -> bytes:
    length = len(payload);
    # https://datatracker.ietf.org/doc/html/rfc7540#section-4.1
    header = bytes( # so technically one frame = total size = (9 bytes + sizeof(payload)) 
        [
            (length >> 16) & 0xFF,
            (length >> 8) & 0xFF,
            length & 0xFF,
            frameType & 0xFF,
            flags & 0xFF,
        ]  
    ) + struct.pack("!I", streamId & 0x7FFFFFFF); # "!I" =4-byte big endian so its readable by other sys
    # top bit observed AND'd result must be zero 

    return (header + payload);

def RECV_EXACT(connection: socket.socket, size: int) -> bytes:
    out = bytearray();

    while len(out) < size:
        chunk = connection.recv(size - len(out));

        if not chunk:
            return b"";

        out.extend(chunk);

    return bytes(out)


def READ_HTTP2_FRAME(connection: socket.socket) -> Optional[Tuple[int, int, int, bytes]]:
    header = RECV_EXACT(connection, HTTP2_FRAME_HEADER_LEN); # 9 bytes, do not forget 
    
    if len(header) != HTTP2_FRAME_HEADER_LEN:
        return None;

    length = (header[0] << 16) | (header[1] << 8) | header[2];
    frameType = header[3];
    flags = header[4];
    streamId = struct.unpack("!I", header[5:9])[0] & 0x7FFFFFFF;
    payload = RECV_EXACT(connection, length) if length > 0 else b"";
    
    if length > 0 and len(payload) != length:
        return None;

    return frameType, flags, streamId, payload;


def BUILD_HTTP2_SETTINGS(maxConcurrentStreams: int = 128, initialWindow: int = 65535) -> bytes:
    payload = struct.pack(
        "!HI", HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, maxConcurrentStreams
    );

    payload += struct.pack("!HI", HTTP2_SETTINGS_INITIAL_WINDOW_SIZE, initialWindow); # who manually just knows what !HI is???
    return BUILD_HTTP2_FRAME(HTTP2_FRAME_SETTINGS, 0x0, 0, payload);


### --- HTTP/2 CONNECTION HANDLER --- ###
def HANDLE_HTTP2_CONNECTION(connection: socket.socket, clientAddress, isTLS=False, isIPv6=False):
    protocol = "HTTPS" if isTLS else "HTTP";
    sessionID = SESSION_MANAGER.CREATE_NEW_SESSION(clientAddress);
    streams: Dict[int, Dict] = {};
    pushedForParent: set[int] = set();
    preface = RECV_EXACT(connection, len(HTTP2_PREFACE))
    if preface != HTTP2_PREFACE:
        return;

    connection.sendall(BUILD_HTTP2_SETTINGS());
    clientSettingsAcked = False;
    serverSettingsAcked = False;

    while serverRunningStatus:
        TXN_start: float = time.time();
        frame: Optional[Tuple[int, int, int, bytes]] = READ_HTTP2_FRAME(connection);
        
        if frame is None:
            break;

        frameType, flags, streamId, payload = frame;

        if frameType == HTTP2_FRAME_SETTINGS:
            if flags & HTTP2_FLAG_ACK:
                serverSettingsAcked = True;
            else:
                connection.sendall(
                    BUILD_HTTP2_FRAME(HTTP2_FRAME_SETTINGS, HTTP2_FLAG_ACK, 0, b"")
                );
                clientSettingsAcked = True;

            continue;

        if frameType == HTTP2_FRAME_PING:
            connection.sendall(
                BUILD_HTTP2_FRAME(
                    HTTP2_FRAME_PING, HTTP2_FLAG_ACK, 0, payload[:8].ljust(8, b"\x00")
                )
            );

            continue;

        if frameType == HTTP2_FRAME_WINDOW_UPDATE:
            continue;

        if frameType == HTTP2_FRAME_HEADERS and streamId > 0:
            pos = 0;
            if flags & 0x8:
                padLength = payload[0] if len(payload) > 0 else 0;
                pos += 1;
            else:
                padLength = 0;
            if flags & 0x20:
                pos += 5;
            headerBlock = payload[
                pos : len(payload) - padLength if padLength > 0 else len(payload)
            ];
            headers = HPACK_DECODE_HEADER_BLOCK(headerBlock);
            streams[streamId] = {
                "headers": headers,
                "body": b"",
                "closed": bool(flags & HTTP2_FLAG_END_STREAM),
            };

            if not (flags & HTTP2_FLAG_END_HEADERS):
                continue;

            if not streams[streamId]["closed"]:
                continue;

        elif frameType == HTTP2_FRAME_DATA and streamId in streams:
            if flags & 0x8:
                padLength = payload[0] if len(payload) > 0 else 0;
                dataPayload = payload[
                    1 : len(payload) - padLength if padLength > 0 else len(payload)
                ];

            else:
                dataPayload = payload;

            streams[streamId]["body"] += dataPayload;

            if not (flags & HTTP2_FLAG_END_STREAM):
                continue;

        else:
            if frameType == HTTP2_FRAME_GOAWAY:
                break;
            continue;

        if not clientSettingsAcked:
            continue;

        reqHeaders = streams[streamId]["headers"];
        method = reqHeaders.get(":method", "GET");
        path = reqHeaders.get(":path", "/");
        userAgent = reqHeaders.get("user-agent", "");
        SESSION_MANAGER.UPDATE_SESSION(sessionID, userAgent);
        if ".." in path:
            status: int = 404;
            body: bytes = b"<h1>ERR_404 - [..] detected in URL, cannot continute</h1>";
        else:
            status = 200;
            body = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>IsoAris Server</title>
</head>
<body>
<h1>IsoAris {protocol} Server</h1>
<p>Request received successfully.</p>
<div>{path}</div>
<footer>Powered by IsoAris_xTCP</footer>
</body>
</html>
""".encode("utf-8");

        (compressedBody, encType) = COMPRESS_RESPONSE(
            body, reqHeaders.get("accept-encoding", "")
        );

        responseHeaders = {
            ":status": str(status),
            "content-type": "text/html",
            "content-length": str(len(compressedBody)),
            "server": "IsoAris_xTCP",
            "date": formatdate(usegmt=True),
        };

        if encType != "identity":
            responseHeaders["content-encoding"] = encType;

        if isTLS:
            responseHeaders["strict-transport-security"] = (
                "max-age=31536000; includeSubDomains"
            );

        headerBlock = HPACK_ENCODE_RESPONSE_HEADERS(responseHeaders);
        connection.sendall(
            BUILD_HTTP2_FRAME(
                HTTP2_FRAME_HEADERS, HTTP2_FLAG_END_HEADERS, streamId, headerBlock
            )
        );

        connection.sendall(
            BUILD_HTTP2_FRAME(
                HTTP2_FRAME_DATA, HTTP2_FLAG_END_STREAM, streamId, compressedBody
            )
        );

        TRANSACTION_LOGGER.LOG_ENTRY(
            {
                "session": sessionID,
                "client": str(clientAddress),
                "method": method,
                "path": path,
                "status": status,
                "duration": (time.time() - TXN_start) * 1000,
                "protocol": f"{protocol}/2",
                "encoding": encType,
            }
        );

        streams.pop(streamId, None);
        if serverSettingsAcked is False:
            continue;


### --- CUSTOM TCP STACK IMPLEMENTATION --- ###
# RFC 793 - Transmission Control Protocol
# RFC 5681 - TCP Congestion Control
# RFC 7323 - TCP Extensions for High Performance [X?]

import random
from dataclasses import dataclass, field
from enum import Enum, Flag, IntEnum
from collections import deque # you can just import in the middle of shit wow

class TCP_STATE(Enum):
    CLOSED = "CLOSED";
    LISTEN = "LISTEN";
    SYN_SENT = "SYN_SENT";
    SYN_RECEIVED = "SYN_RECEIVED"
    ESTABLISHED = "ESTABLISHED"
    FIN_WAIT_1 = "FIN_WAIT_1"
    FIN_WAIT_2 = "FIN_WAIT_2"
    CLOSE_WAIT = "CLOSE_WAIT"
    CLOSING = "CLOSING";
    LAST_ACK = "LAST_ACK";
    TIME_WAIT = "TIME_WAIT";


class TCP_FLAGS(IntEnum):
    FIN = 0x01  # Finish - no more data from sender
    SYN = 0x02  # (START +) Synchronize sequence numbers
    RST = 0x04  # Reset the connection (hard abort)
    PSH = 0x08  # Push function (no buffer, immediate data push)
    ACK = 0x10  # Acknowledgment field is valid 
    URG = 0x20  # Urgent pointer field is valid (idk about this)
    ECE = 0x40  # ECN (Explicit Congestion Notification)-Echo, should use this if too much traffic congeshun
    CWR = 0x80  # Congestion Window Reduced (reduce CN?)

# | CWR | ECE | URG | ACK | PSH | RST | SYN | FIN |
# | 128 | 64  | 32  | 16  |  8  |  4  |  2  |  1  |

@dataclass
class TCP_SEGMENT_HEADER:
    """
    copy paste lolol ()

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Source Port          |       Destination Port        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Sequence Number                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Acknowledgment Number                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Data |           |U|A|P|R|S|F|                               |
    | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
    |       |           |G|K|H|T|N|N|                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Checksum            |         Urgent Pointer        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             data                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    sourcePort: int;
    destinationPort: int;
    sequenceNumber: int;
    acknowledgmentNumber: int;
    dataOffset: int;  # 4-bit field, header length in 32-bit words
    flags: int;
    windowSize: int;
    checksum: int;
    urgentPointer: int;
    options: bytes = field(default_factory=bytes);
    HEADER_LENGTH_MIN: int = 20;  # minimum TCP header size in (20) bytes

    # headers are nothing but control information that describes 
    # how a particular protocol message needs to be interpreted and operated

    def serialize(self) -> bytes:
        # we serialize TCP header to bytes / binary format according to RFC 793

        # 20 bytes, word = 4 bytes, so 20/4 = 5 
        dataOffsetWords: int = 5 + (len(self.options) + 3) // 4; # (1 <-> 4 + 3 // 4 = floor/return 1 = 4 byte padding alignment)
        base2TCPheader: bytes = struct.pack( # binary TCP header
            # 0xF = 1[x4] = 4 bit = 1/2 byte = "nibble"
            # 0xFF = 1[x8] = 8 bit = byte 
            # 0xFFFF = 1[x16] = 16 bit = 2 bytes 
            # 0xFFFFFFFF = 1[x32] = 32-bit = 4 bytes 

            "!HHIIHHHH", # this sucks
            # ! = Big endian (MSB first)
            # H = unsigned short (16-bit)
            # I = unsigned int32_t (32-bit)
                                        
            # "&ing" is "bitmasking" it
            # (<value> & <mask>)

            self.sourcePort & 0xFFFF, # H-16
            self.destinationPort & 0xFFFF, # H
            self.sequenceNumber & 0xFFFFFFFF, # I-32
            self.acknowledgmentNumber & 0xFFFFFFFF, # I
            ((dataOffsetWords << 12) | (self.flags & 0x3F)) & 0xFFFF, # H
            self.windowSize & 0xFFFF, # H
            self.checksum & 0xFFFF, # H
            self.urgentPointer & 0xFFFF, # H
        );

        # 5 bytes = pad by 3 
        # 6 bytes = pad by 2 
        # 7 bytes = pad by 1 

        # -> (4 - ((5 % 4) % 4)) 
        # -> (4 - ((1) % 4)) 
        # -> (4 - 1) 
        # => 3 bytes 

        paddingLength: int = (4 - (len(self.options) % 4)) % 4; # this is great 

        # TCP header = header + options + padding 
        return (base2TCPheader + self.options + (b"\x00" * paddingLength));

    @classmethod # method belongs to class, didnt know they had a decorator for this
    def deserialize(cls, data: bytes) -> Tuple["TCP_SEGMENT_HEADER", int]: # cls = class 
        # deserialize bytes to TCP header
        
        if len(data) < (cls.HEADER_LENGTH_MIN) : # is it less than 20 bytes?
            raise ValueError("\n[!TCP_ERR]: TCP header was/is too short\n");

        # 0–1   : Source Port (16 bits)
        # 2–3   : Destination Port (16 bits)
        # 4–7   : Sequence Number (32 bits)
        # 8–11  : Acknowledgment Number (32 bits)
        # 12–13 : DataOffset + Flags (16 bits)
        # 14–15 : Window Size (16 bits)
        # 16–17 : Checksum (16 bits)
        # 18–19 : Urgent Pointer (16 bits)

        # struct.unpack returns a tuple mandatorily, so gotta use [0] so that we get/extract the I/H/int at [<index=0>]
        # vx: int = struct.unpact("!H", something), vx = (<val>, empty), vx[0] = just <val>

        # HHIIHHHH
        # cannot change order... 
        # [start_at:stop_b4:step]
        sourcePort: int = struct.unpack("!H", data[0:2])[0]; # 
        destinationPort: int      = struct.unpack("!H", data[2:4])[0];
        sequenceNumber: int       = struct.unpack("!I", data[4:8])[0];
        acknowledgmentNumber: int = struct.unpack("!I", data[8:12])[0];
        dataOffsetAndFlags: int   = struct.unpack("!H", data[12:14])[0];

        # leave last 4 bits (MSB, not LSB)
        # multiply by *4 to get bits instead of bytes 
        dataOffset: int = ((dataOffsetAndFlags >> 12) * 4);

        # 0x3F = 0000 0000 0011 1111 | bitmask shit again
        # last 6 bits is what i want
        # we will stencil the first 10 bits like a pro and just get the last 6 bits values 
        # should get 8?
        flags: int = (dataOffsetAndFlags & 0x3F);

        windowSize: int    = struct.unpack("!H", data[14:16])[0];
        checksum: int      = struct.unpack("!H", data[16:18])[0];
        urgentPointer: int = struct.unpack("!H", data[18:20])[0];

        options: bytes = b"";

        if dataOffset > cls.HEADER_LENGTH_MIN:
            # options = data[cls.HEADER_LENGTH_MIN : dataOffsetAndFlags]; # THIS IS wrong 
            options = data[cls.HEADER_LENGTH_MIN : dataOffset];

        header: TCP_SEGMENT_HEADER = cls(
            sourcePort=sourcePort,
            destinationPort=destinationPort,
            sequenceNumber=sequenceNumber,
            acknowledgmentNumber=acknowledgmentNumber,
            dataOffset=dataOffset // 4,
            flags=flags,
            windowSize=windowSize,
            checksum=checksum,
            urgentPointer=urgentPointer,
            options=options,
        );

        return header, dataOffset;

    def has_flag(self, flag: TCP_FLAGS) -> bool:
        return bool(self.flags & flag);

@dataclass
class IP_PACKET_HEADER:
    """
    RFC 791 -> <-

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |Type of Service|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    type of service / ToS is now (DSCP/DSfield (6) + ECN (2))
    the first 4 bits were actually used, the last 3 were for "IP precedence (priority)" and the last wasnt used at all 
    the [xxx] 3-bit IP precedence thingy was for VoIP or "medium priority" or whatever
    more here - https://www.slashroot.in/understanding-differentiated-services-tos-field-internet-protocol-header

    TCP originally leveraged this facility to set its own connection priority 
    it no longer does this as an entire connection re-establish is not feasible hereafter in RFC 2873

    DSCP - Differentiated Services Code Point
    """

    version: int = 4;              # IPv4 only
    internetHeaderLength: int = 5; # 5 * 4 = 20 bytes (max 15, abbr "IHL") (5 = no options, we keep it 20 bytes only)
    typeOfService: int = 0;        # ToS for Quality of Service (QoS) to prioritize traffic, outdated now i suppose
    totalLength: int = 20;         # header + payload
    identification: int = 0;       # IPv4 was supposed to solve routers having MTUs (max packet size they can forward)
                                   # so they "fragmented" it, identification here supports that excpet we wont really need it 
    flags: int = 2;                # because of this flag | set to {0 1 0}
    fragmentOffset: int = 0;       # we will not use this again because flag is set to 010 // 2
    timeToLive: int = 64;          # each router hop decreases the TTL counter by 1 so it will die at some point 
    protocol: int = 6;             # TCP protocol number [1 = ICMP, 6 = TCP, 17 = UDP]
    headerChecksum: int = 0;       # IPv4 checksum, this thing is recomputed every hop because of TTL changes 
    sourceIP: str = "0.0.0.0";     # sender's IP address
    destinationIP: str = "0.0.0.0";# target IP address
    options: bytes = field(default_factory=bytes); # none i think?
    
    HEADER_LENGTH: int = 20;
    PROTOCOL_TCP: int = 6; # see comment at line 832

    def serialize(self) -> bytes:
        # serialize IPv4 header to raw bytes for transmission 
        # according to RFC 791

        # BASE 5 + ceiling(len(options) // 4 bytes)
        # (5 + ((1) + 3) // 4)
        # (5 + (4 // 4)
        # (5 + 1)
        # (6) words
        headerLengthWords: int = (5 + (len(self.options) + 3) // 4);

        def ipToInt(ipStr: str) -> int:
            # 192.168.1.10 <=> 32-bit number
            # in [x.x.x.x], each [x] is an "octet" (8 * 4 = 32)
            # (192 << 24) | (168 << 16) | (1 << 8) | (10) 
            # doing this results in a 32-bit integer [x8 x8 x8 x8]
            # its easy easier to parse this stupid 32 bit number than parsing it as a string 
            # which will be 0s and 1s anyway at the end, but size sux (12 bytes vs just 4 bytes)

            parts: List[str] = ipStr.split(".");
            
            # if you know how in boolean algebra the (bitwise?) OR law uses (A "+" B),
            # same way we're just glueing it here, if we did "+" literally we might as well 
            # get carries which we dont want 
            return (
                (int(parts[0]) << 24) | (int(parts[1]) << 16)
                | (int(parts[2]) << 8) | int(parts[3])
            );

        header: bytes = struct.pack(
            "!BBHHHBBHII",
            ((self.version & 0xF) << 4) | (headerLengthWords & 0xF),
            self.typeOfService & 0xFF,
            self.totalLength & 0xFFFF,
            self.identification & 0xFFFF,
            ((self.flags & 0x7) << 13) | (self.fragmentOffset & 0x1FFF),
            self.timeToLive & 0xFF,
            self.protocol & 0xFF,
            self.headerChecksum & 0xFFFF,
            ipToInt(self.sourceIP) & 0xFFFFFFFF,
            ipToInt(self.destinationIP) & 0xFFFFFFFF,
        );

        if self.options:
            paddingLength: int = (4 - (len(self.options) % 4)) % 4; # same formula + padding alignment
            header += (self.options + (b"\x00" * paddingLength));

        return (header);

    @classmethod
    def deserialize(cls, data: bytes) -> Tuple["IP_PACKET_HEADER", int]:
        if len(data) < cls.HEADER_LENGTH:
            raise ValueError("IP header too short | (len(data) < cls.HEADER_LENGTH");

        firstByte: int = data[0];
        version: int = firstByte >> 4; # rightshift? (IPv4)
        headerLengthWords: int = firstByte & 0x0F; # extract IHL 
        headerLength: int = headerLengthWords * 4;
        typeOfService: int = data[1];
        totalLength: int = struct.unpack("!H", data[2:4])[0]; # get network byte order [!H] 
        identification: int = struct.unpack("!H", data[4:6])[0]; 
        flagsAndFragment: int = struct.unpack("!H", data[6:8])[0];
        flags: int = (flagsAndFragment >> 13) & 0x07;
        fragmentOffset: int = flagsAndFragment & 0x1FFF;
        timeToLive: int = data[8];
        protocol: int = data[9];
        headerChecksum: int = struct.unpack("!H", data[10:12])[0];
        sourceIPInt: int = struct.unpack("!I", data[12:16])[0];
        destIPInt: int = struct.unpack("!I", data[16:20])[0];

        def intToIp(ipInt: int) -> str:
            # return the octets just like we reversed em
            return (f"{(ipInt >> 24) & 0xFF}.{(ipInt >> 16) & 0xFF}.{(ipInt >> 8) & 0xFF}.{ipInt & 0xFF}");

        options: bytes = b"";
        if headerLength > cls.HEADER_LENGTH:
            options = data[cls.HEADER_LENGTH : headerLength];

        header: IP_PACKET_HEADER = cls(
            version=version,
            internetHeaderLength=headerLengthWords, # can die here
            typeOfService=typeOfService,
            totalLength=totalLength,
            identification=identification,
            flags=flags,
            fragmentOffset=fragmentOffset,
            timeToLive=timeToLive,
            protocol=protocol,
            headerChecksum=headerChecksum,
            sourceIP=intToIp(sourceIPInt),
            destinationIP=intToIp(destIPInt),
            options=options,
        );

        return header, headerLength;


def CALCULATE_CHECKSUM(data: bytes) -> int: 
    # data: byte = [0x12, 0x34, 0x56]
    # padded -> [0x12, 0x34, 0x56, 0x00]
    if len(data) % 2 == 1:
        data += b"\x00";

    checksum: int = 0;
    for index in range(0, len(data), 2): # range(start @, stop b4, step);
        # suppose we have 0x67 and 0x69
        # we need to concatenate them but without actually concatenating them
        # (0x67 << 8) + 0x69 (leftshift hexadecimal by binary and return hexadecimal again)
        # 0x6700 + 0x69
        # 0x6769
        word: int = (data[index] << 8) + data[index + 1];
        checksum += word; # add every word into its int from to form the checksum 

    # carry = checksum >> 16 
    # resultLower = checksum & 0xFFFF 
    # checksum = resultLower + carry 
    # this is aka "end around carrying"
    while (checksum >> 16):
        checksum = (checksum & 0xFFFF) + (checksum >> 16);

    return (~checksum & 0xFFFF); # 16 bit checksum integer


def CALCULATE_TCP_CHECKSUM(sourceIP: str, destinationIP: str, tcpHeaderAndData: bytes) -> int:
    """
    Pseudo-header format:
    +--------+--------+--------+--------+
    |           Source Address          |
    +--------+--------+--------+--------+
    |         Destination Address       |
    +--------+--------+--------+--------+
    |  Zero  |  PTCL  |    TCP Length   |
    +--------+--------+--------+--------+
    """

    def ipToBytes(ipStr: str) -> bytes:
        parts: List[int] = [int(part) for part in ipStr.split(".")];
        return bytes(parts);

    pseudoHeader: bytes = (
        ipToBytes(sourceIP)
        + ipToBytes(destinationIP)
        + b"\x00"
        + bytes([6])  # TCP protocol
        + struct.pack("!H", len(tcpHeaderAndData))
    );
    
    return CALCULATE_CHECKSUM(pseudoHeader + tcpHeaderAndData);


@dataclass
class RETRANSMISSION_QUEUE_ENTRY:
    # the retransmission queue is a data structure 
    # we will store packets here that were sent but not ACKed 
    # if theyre ACKed, we will pop them out!

    # if now - transmissionTimestamp > RTO:
    #     retransmit(packet); 

    sequenceNumber: int;            # packet ID
    payloadData: bytes;             # actual data to transmit 
    transmissionTimestamp: float;   # the time last packet was sent 
    retransmissionCount: int = 0;   # the amount of times this packet was sent  

class TCP_CONNECTION_CONTROL_BLOCK:
    # the TCB (TCP Control Block) is an "internal state container" 
    # which contains the connection state, sequence numbers, window sizes, retransmission logic
    # and other parameters needed to manage a TCP connection

    # RFC 793 recommended values
    # IPv4 MTU (max transmision unit) minimum = 576 bytes
    # IP headder = 20 bytes
    # TCP header = 20 bytes
    # (576 - 40) = 536 bytes payload
    DEFAULT_MSS: int = 536;   # Minimum MSS - Maximum Segment Size
    MAXIMUM_MSS: int = 1460;  # Common MSS for Ethernet (we wont really need this?)
    INITIAL_WINDOW_SIZE: int = 65535; # (in bytes)

    # RFC 6298 - Retransmission Timeout (RTO) parameters
    RTO_INITIAL: float = 1.0;       # initial RTO in seconds
    RTO_MIN: float = 0.2;           # min RTO
    RTO_MAX: float = 60.0;          # max RTO
    MAX_RETRANSMISSIONS: int = 5;   # max retransmission attempts

    def __init__(self, localAddress: Tuple[str, int], remoteAddress: Tuple[str, int]):
        # <PROTO>://<IP>:<port> 

        # connection identifiers / identity delimiters 
        # even if we are running on loopback, the TCP requires 2 endpoints
        self.localAddress: Tuple[str, int] = localAddress;   # (my side) addr| endpoint-1
        self.remoteAddress: Tuple[str, int] = remoteAddress; # (their side) |  endpoint-2
        # crazy how i had no idea what the difference b/w local and remote address was
        
        # state of the conn 
        # initialize to CLOSED, CLOSED means "connection is rn inactive" (see 793)
        # if its CLOSED, that means no TCB memory allocation 
        self.currentState: TCP_STATE = TCP_STATE.CLOSED; 
        
        # sequence numbers (RFC 793 Section 3.3)
        # https://datatracker.ietf.org/doc/html/rfc793#section-3.3 
        # TCP gives every packet sent a sequence of numbers (S/SN) like position markers 
        self.initialSendSequenceNumber: int = random.randint(0, 0xFFFFFFFF); # ISSN or ISN randomly inited for avoiding spoofing
        self.sendSequenceNumber: int = self.initialSendSequenceNumber;       # 
        self.sendUnacknowledged: int = self.initialSendSequenceNumber;
        self.sendWindow: int = self.INITIAL_WINDOW_SIZE; # number of unacked data frames/bytes
        self.sendWindowScale: int = 0;

        self.initialReceiveSequenceNumber: int = 0;         # IRS
        self.receiveSequenceNumber: int = 0;                
        self.receiveWindow: int = self.INITIAL_WINDOW_SIZE;
        self.receiveWindowScale: int = 0;
        
        # MSS - Maximum Segment Size
        self.maxSegmentSizeSend: int = self.DEFAULT_MSS;     # MSS we send
        self.maxSegmentSizeReceive: int = self.DEFAULT_MSS;  # MSS we accept/recv

        self.retransmissionQueue: deque = deque(); # amount of buffer that we sent but is unacked 

        self.roundTripTimeSmoothed: Optional[float] = None;     # SRTT
        self.roundTripTimeVariance: Optional[float] = None;     # RTTVAR
        self.retransmissionTimeout: float = self.RTO_INITIAL;   # RTO
 
        # see (RFC 5681)
        self.congestionWindow: int = (self.maxSegmentSizeReceive * 2);  # cwnd - slow start
        self.slowStartThreshold: int = self.INITIAL_WINDOW_SIZE;  # ssthresh
        self.duplicateAcknowledgmentCount: int = 0; # ?? 
         
        # self.sendWindowUpdateThreshold: int = self.DEFAULT_MSS; # ???
        self.sendWindowUpdateThreshold: int = self.maxSegmentSizeReceive;
        
        # header w/ options tracking
        self.selectiveAcknowledgmentEnabled: bool = False;
        self.timestampEnabled: bool = False;

        # data buffers
        self.receiveBuffer: bytearray = bytearray();
        self.sendBuffer: bytearray = bytearray();
        self.outOfOrderSegments: Dict[int, bytes] = {};
        
        # connextion timing
        self.connectionEstablishmentTime: Optional[float] = None;
        self.lastActivityTime: float = time.time();

    def getSendWindow(self) -> int:
        # min(total congestiom window size / allowed send window)
        return min(self.congestionWindow, self.sendWindow);

    def updateRoundTripTime(self, measuredRTT: float) -> None:
        # RTT = round trip time 
        # SRTT = Smoothed RTT = weighted average of multiple RTTs

        # date RTT estimates using RFC 6298 algorithm:
        # SRTT = (1 - alpha) * SRTT + alpha * R' (R' = prior measured RTT)
        # RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R'|
        # RTO = SRTT + max(G, K * RTTVAR)
        # where alpha = 1/8, beta = 1/4, K = 4, G = clock granularity

        # SRTT = 0.1s 
        # RTTVAR = (0.1 / 2) = 0.05s 
        # RTO = 0.1 + max(0.01, 4 * 0.05) = 0.1 + 0.2 = 0.3s
        
        # suppose next R' = 0.12s
        # Error = 0.12 - 0.1 = [+0.02s]
        # RTTVAR = (3/4 * 0.05)) + (1/4 * 0.02) 
        #        = (0.0375 + 0.005) = 0.0425s 
        # SRTT = (7/8 * 0.100) + (1/8 * 0.12) = 0.0875 + 0.015 = 0.1025s
        # RTO = 0.1025 + max(0.01, 4 * 0.0425) = 0.1025 + 0.17 = 0.2725
        
        if self.roundTripTimeSmoothed is None:
            # init first RTT 
            self.roundTripTimeSmoothed = measuredRTT;
            self.roundTripTimeVariance = measuredRTT / 2; 
        else:
            
            error: float = measuredRTT - self.roundTripTimeSmoothed;
            
            # RTTVAR = (3/4) * RTTVAR + ((1/4) * |error|);
            # 75% old value, 25% error
            # self.roundTripTimeVariance = float((3 / 4) * self.roundTripTimeVariance + (
            #    1 / 4
            # ) * abs(error));

            self.roundTripTimeVariance = float((3/4) * self.roundTripTimeVariance + (1/4) * abs(error));
             # self.roundTripTimeVariance = (3/4) * self.roundTripTimeVariance + (1/4) * abs(error);
            self.roundTripTimeSmoothed = (7/8) * self.roundTripTimeSmoothed + (1/8) * measuredRTT;

        # RTO = SRTT + max(G, 4 * RTTVAR)
        self.retransmissionTimeout = self.roundTripTimeSmoothed + max(0.01, 4 * self.roundTripTimeVariance);
        
        # clamping, no idea why tf this works
        self.retransmissionTimeout = max(self.RTO_MIN, min(self.RTO_MAX, self.retransmissionTimeout));

    def handleTimeout(self) -> None:
        
        # binary exponential backoff
        # 1s -> 2s -> 4s -> 8s -> 16s 
        # because the congestion is assumed high, we backoff exponentially
        self.retransmissionTimeout = min(self.RTO_MAX, self.retransmissionTimeout * 2);
        
        # Enter slow start
        self.slowStartThreshold = max(self.congestionWindow // 2, self.maxSegmentSizeReceive * 2);
        self.congestionWindow = self.maxSegmentSizeReceive;

    def incrementCongestionWindow(self, bytesAcked: int) -> None: 
        # slow start: cwnd += MSS for each ACK
        # congestion avoidance: cwnd += MSS * MSS / cwnd for each ACK

        if self.congestionWindow < self.slowStartThreshold:
            self.congestionWindow += self.maxSegmentSizeReceive;
        else:
            self.congestionWindow += (
                self.maxSegmentSizeReceive * self.maxSegmentSizeReceive
            ) // self.congestionWindow;

        self.congestionWindow = min(self.congestionWindow, self.INITIAL_WINDOW_SIZE); 

    def updateState(self, newState: TCP_STATE) -> None:
        oldState: TCP_STATE = self.currentState;
        self.currentState = newState;
        self.lastActivityTime = time.time();

        if newState == TCP_STATE.ESTABLISHED and oldState != TCP_STATE.ESTABLISHED:
            self.connectionEstablishmentTime = time.time();

class CUSTOM_TCP_STACK:
    def __init__(self):
        # ACTIVE_CONNECTIONS
        # LISTENING_SOCKETS
        # PENDING_CONNECTIONS

        # current active connections indexed by (local_addr, remote_addr) tuple
        self.connections: Dict[Tuple[Tuple[str, int], Tuple[str, int]], TCP_CONNECTION_CONTROL_BLOCK] = {}; # holy fuck?
        self.listenSockets: Dict[Tuple[str, int], socket.socket] = {};
        self.pendingConnections: Dict[Tuple[str, int], List[TCP_CONNECTION_CONTROL_BLOCK]] = {}; # unconfirmed/3-way in progress

    def createConnection(self, localAddress: Tuple[str, int], remoteAddress: Tuple[str, int]) -> TCP_CONNECTION_CONTROL_BLOCK:
        connectionKey: Tuple[Tuple[str, int], Tuple[str, int]] = (
            localAddress,
            remoteAddress,
        );

        newConnectionTCB: TCP_CONNECTION_CONTROL_BLOCK = TCP_CONNECTION_CONTROL_BLOCK(
            localAddress, remoteAddress
        );

        self.connections[connectionKey] = newConnectionTCB;
        return newConnectionTCB;

    def getConnection(
        self, localAddress: Tuple[str, int], remoteAddress: Tuple[str, int]
    ) -> Optional[TCP_CONNECTION_CONTROL_BLOCK]:
        connectionKey: Tuple[Tuple[str, int], Tuple[str, int]] = (
            localAddress,
            remoteAddress,
        );

        return self.connections.get(connectionKey);

    def removeConnection(
        self, localAddress: Tuple[str, int], remoteAddress: Tuple[str, int]
    ) -> None:
        connectionKey: Tuple[Tuple[str, int], Tuple[str, int]] = (
            localAddress,
            remoteAddress,
        );

        if connectionKey in self.connections:
            del self.connections[connectionKey];

    def processIncomingSegment(
        self,
        ipHeader: IP_PACKET_HEADER,
        tcpHeader: TCP_SEGMENT_HEADER,
        payloadData: bytes,
    ) -> Optional[Tuple[TCP_SEGMENT_HEADER, bytes]]:

        localAddress: Tuple[str, int] = (
            ipHeader.destinationIP,
            tcpHeader.destinationPort,
        );

        remoteAddress: Tuple[str, int] = (ipHeader.sourceIP, tcpHeader.sourcePort);
    
        receivedChecksum: int = tcpHeader.checksum;
        tcpHeader.checksum = 0;
        calculatedChecksum: int = CALCULATE_TCP_CHECKSUM(
            ipHeader.sourceIP,
            ipHeader.destinationIP,
            tcpHeader.serialize() + payloadData,
        );

        if receivedChecksum != calculatedChecksum:
            print(f"[TCP]: Checksum mismatch, dropping segment");
            return None;

        tcpHeader.checksum = receivedChecksum;
        connectionTCB: Optional[TCP_CONNECTION_CONTROL_BLOCK] = self.getConnection(
            localAddress, remoteAddress
        );

        if (
            connectionTCB is None
            and tcpHeader.has_flag(TCP_FLAGS.SYN)
            and not tcpHeader.has_flag(TCP_FLAGS.ACK)
        ):
            if localAddress in self.listenSockets:
                
                # we create new connection in SYN_RECEIVED state
                connectionTCB = self.createConnection(localAddress, remoteAddress);
                connectionTCB.updateState(TCP_STATE.SYN_RECEIVED); # this is starting to hurt my brain kind of
                connectionTCB.initialReceiveSequenceNumber = tcpHeader.sequenceNumber;
                connectionTCB.receiveSequenceNumber = tcpHeader.sequenceNumber + 1;
                
                # parse options for MSS
                self.parseTCPOptions(connectionTCB, tcpHeader.options);
                # send SYN-ACK
                return self.buildSYNACKSegment(connectionTCB);
            else:
                # no listener - send RST
                return self.buildRSTSegment(localAddress, remoteAddress, tcpHeader.sequenceNumber);

        if connectionTCB is None:
            # connection doesn't exist - send RST
            return self.buildRSTSegment(localAddress, remoteAddress, tcpHeader.sequenceNumber);

        if connectionTCB.currentState == TCP_STATE.SYN_RECEIVED:
            return self.handleSYN_RECEIVED(connectionTCB, tcpHeader, payloadData);
        elif connectionTCB.currentState == TCP_STATE.ESTABLISHED:
            return self.handleESTABLISHED(connectionTCB, tcpHeader, payloadData);
        elif connectionTCB.currentState == TCP_STATE.FIN_WAIT_1:
            return self.handleFIN_WAIT_1(connectionTCB, tcpHeader, payloadData);
        elif connectionTCB.currentState == TCP_STATE.FIN_WAIT_2:
            return self.handleFIN_WAIT_2(connectionTCB, tcpHeader, payloadData);
        elif connectionTCB.currentState == TCP_STATE.CLOSE_WAIT:
            return self.handleCLOSE_WAIT(connectionTCB, tcpHeader, payloadData);
        elif connectionTCB.currentState == TCP_STATE.CLOSING:
            return self.handleCLOSING(connectionTCB, tcpHeader, payloadData);
        elif connectionTCB.currentState == TCP_STATE.LAST_ACK:
            return self.handleLAST_ACK(connectionTCB, tcpHeader, payloadData);
        elif connectionTCB.currentState == TCP_STATE.TIME_WAIT:
            return self.handleTIME_WAIT(connectionTCB, tcpHeader, payloadData);

        return None;

    def parseTCPOptions(self, connectionTCB: TCP_CONNECTION_CONTROL_BLOCK, options: bytes) -> None:
        optionIndex: int = 0;
        while optionIndex < len(options):
            optionKind: int = options[optionIndex];
            
            if optionKind == 0:  # End of options
                break;
            
            elif optionKind == 1:  # NOP
                optionIndex += 1;
                continue;
            
            elif optionKind == 2:  # MSS option
                if optionIndex + 3 < len(options):
                    mssValue: int = struct.unpack(
                        "!H", options[optionIndex + 2 : optionIndex + 4]
                    )[0];

                    connectionTCB.maxSegmentSizeReceive = min(mssValue, connectionTCB.MAXIMUM_MSS);
                optionIndex += 4;
            
            elif optionKind == 3: 
                if optionIndex + 2 < len(options):
                    connectionTCB.receiveWindowScale = options[optionIndex + 2];
                    connectionTCB.sendWindowScale = options[optionIndex + 2];
                
                optionIndex += 3;
            
            elif optionKind == 8:
                connectionTCB.timestampEnabled = True;
                optionIndex += 10;
            
            else:
                if optionIndex + 1 < len(options) and options[optionIndex + 1] > 0:
                    optionIndex += options[optionIndex + 1];
                else:
                    optionIndex += 1;

    def buildSYNACKSegment(
        self, connectionTCB: TCP_CONNECTION_CONTROL_BLOCK
    ) -> Tuple[TCP_SEGMENT_HEADER, bytes]:
        """Build SYN-ACK segment for three-way handshake"""
        options: bytes = (
            bytes([2, 4])
            + struct.pack("!H", connectionTCB.maxSegmentSizeReceive)  # MSS
            + bytes([1, 1, 1])  # NOP padding
            + bytes([3, 3, connectionTCB.sendWindowScale])  # Window scale
        )
        synAckHeader: TCP_SEGMENT_HEADER = TCP_SEGMENT_HEADER(
            sourcePort=connectionTCB.localAddress[1],
            destinationPort=connectionTCB.remoteAddress[1],
            sequenceNumber=connectionTCB.initialSendSequenceNumber,
            acknowledgmentNumber=connectionTCB.receiveSequenceNumber,
            dataOffset=0,
            flags=TCP_FLAGS.SYN | TCP_FLAGS.ACK,
            windowSize=min(connectionTCB.receiveWindow, 0xFFFF),
            checksum=0,
            urgentPointer=0,
            options=options,
        )
        # Calculate checksum
        serializedHeader: bytes = synAckHeader.serialize()
        synAckHeader.checksum = CALCULATE_TCP_CHECKSUM(
            connectionTCB.localAddress[0],
            connectionTCB.remoteAddress[0],
            serializedHeader,
        )
        return synAckHeader, b""

    def buildRSTSegment(
        self,
        localAddress: Tuple[str, int],
        remoteAddress: Tuple[str, int],
        acknowledgmentNumber: int,
    ) -> Tuple[TCP_SEGMENT_HEADER, bytes]:
        """Build RST segment to reset connection"""
        rstHeader: TCP_SEGMENT_HEADER = TCP_SEGMENT_HEADER(
            sourcePort=localAddress[1],
            destinationPort=remoteAddress[1],
            sequenceNumber=0,
            acknowledgmentNumber=acknowledgmentNumber,
            dataOffset=5,
            flags=TCP_FLAGS.RST | TCP_FLAGS.ACK,
            windowSize=0,
            checksum=0,
            urgentPointer=0,
        )
        serializedHeader: bytes = rstHeader.serialize()
        rstHeader.checksum = CALCULATE_TCP_CHECKSUM(
            localAddress[0], remoteAddress[0], serializedHeader
        )
        return rstHeader, b""

    def handleSYN_RECEIVED(
        self,
        connectionTCB: TCP_CONNECTION_CONTROL_BLOCK,
        tcpHeader: TCP_SEGMENT_HEADER,
        payloadData: bytes,
    ) -> Optional[Tuple[TCP_SEGMENT_HEADER, bytes]]:
        """Handle segment in SYN_RECEIVED state (completing three-way handshake)"""
        if tcpHeader.has_flag(TCP_FLAGS.ACK):
            if (
                tcpHeader.acknowledgmentNumber
                == connectionTCB.initialSendSequenceNumber + 1
            ):
                # Three-way handshake complete
                connectionTCB.sendUnacknowledged = tcpHeader.acknowledgmentNumber
                connectionTCB.sendSequenceNumber = tcpHeader.acknowledgmentNumber
                connectionTCB.updateState(TCP_STATE.ESTABLISHED)
                connectionTCB.sendWindow = (
                    tcpHeader.windowSize << connectionTCB.sendWindowScale
                )
                print(
                    f"[TCP]: Connection established {connectionTCB.localAddress} <-> {connectionTCB.remoteAddress}"
                )
                return None
            else:
                # Bad ACK - send RST
                return self.buildRSTSegment(
                    connectionTCB.localAddress,
                    connectionTCB.remoteAddress,
                    tcpHeader.sequenceNumber,
                )

        return None

    def handleESTABLISHED(
        self,
        connectionTCB: TCP_CONNECTION_CONTROL_BLOCK,
        tcpHeader: TCP_SEGMENT_HEADER,
        payloadData: bytes,
    ) -> Optional[Tuple[TCP_SEGMENT_HEADER, bytes]]:
        """Handle segment in ESTABLISHED state"""
        # Update window
        connectionTCB.sendWindow = tcpHeader.windowSize << connectionTCB.sendWindowScale
        # Process ACK
        if tcpHeader.has_flag(TCP_FLAGS.ACK):
            self.processAcknowledgment(connectionTCB, tcpHeader.acknowledgmentNumber)

        # Check for incoming data
        if payloadData:
            if tcpHeader.sequenceNumber == connectionTCB.receiveSequenceNumber:
                # In-order data
                connectionTCB.receiveBuffer.extend(payloadData)
                connectionTCB.receiveSequenceNumber += len(payloadData)
                # Check for out-of-order segments that can now be processed
                while (
                    connectionTCB.receiveSequenceNumber
                    in connectionTCB.outOfOrderSegments
                ):
                    segmentData: bytes = connectionTCB.outOfOrderSegments.pop(
                        connectionTCB.receiveSequenceNumber
                    )
                    connectionTCB.receiveBuffer.extend(segmentData)
                    connectionTCB.receiveSequenceNumber += len(segmentData)
            else:
                # Out-of-order segment - buffer it
                connectionTCB.outOfOrderSegments[tcpHeader.sequenceNumber] = payloadData

        # Check for FIN
        if tcpHeader.has_flag(TCP_FLAGS.FIN):
            connectionTCB.receiveSequenceNumber += 1
            connectionTCB.updateState(TCP_STATE.CLOSE_WAIT)
            # Send ACK for FIN
            ackHeader: TCP_SEGMENT_HEADER = TCP_SEGMENT_HEADER(
                sourcePort=connectionTCB.localAddress[1],
                destinationPort=connectionTCB.remoteAddress[1],
                sequenceNumber=connectionTCB.sendSequenceNumber,
                acknowledgmentNumber=connectionTCB.receiveSequenceNumber,
                dataOffset=5,
                flags=TCP_FLAGS.ACK,
                windowSize=min(connectionTCB.receiveWindow, 0xFFFF),
                checksum=0,
                urgentPointer=0,
            )
            serializedHeader: bytes = ackHeader.serialize()
            ackHeader.checksum = CALCULATE_TCP_CHECKSUM(
                connectionTCB.localAddress[0],
                connectionTCB.remoteAddress[0],
                serializedHeader,
            )
            return ackHeader, b""

        # Send ACK if data received or need to acknowledge
        if (
            payloadData
            or tcpHeader.has_flag(TCP_FLAGS.SYN)
            or tcpHeader.has_flag(TCP_FLAGS.FIN)
        ):
            return self.buildACKSegment(connectionTCB)

        return None

    def processAcknowledgment(
        self, connectionTCB: TCP_CONNECTION_CONTROL_BLOCK, acknowledgmentNumber: int
    ) -> None:
        """Process incoming ACK and update retransmission queue"""
        if acknowledgmentNumber > connectionTCB.sendUnacknowledged:
            bytesAcknowledged: int = (
                acknowledgmentNumber - connectionTCB.sendUnacknowledged
            )
            connectionTCB.sendUnacknowledged = acknowledgmentNumber
            connectionTCB.duplicateAcknowledgmentCount = 0
            # Remove acknowledged segments from retransmission queue
            while connectionTCB.retransmissionQueue:
                entry: RETRANSMISSION_QUEUE_ENTRY = connectionTCB.retransmissionQueue[0]
                if (
                    entry.sequenceNumber + len(entry.payloadData)
                ) <= acknowledgmentNumber:
                    # Calculate RTT if this is the first time segment is acknowledged
                    if entry.retransmissionCount == 0 and entry.transmissionTimestamp:
                        measuredRTT: float = time.time() - entry.transmissionTimestamp
                        connectionTCB.updateRoundTripTime(measuredRTT)

                    connectionTCB.retransmissionQueue.popleft()
                else:
                    break

            # Update congestion window
            connectionTCB.incrementCongestionWindow(bytesAcknowledged)
        elif acknowledgmentNumber == connectionTCB.sendUnacknowledged:
            # Duplicate ACK
            connectionTCB.duplicateAcknowledgmentCount += 1
            # Fast retransmit on 3 duplicate ACKs (RFC 5681)
            if connectionTCB.duplicateAcknowledgmentCount == 3:
                connectionTCB.slowStartThreshold = max(
                    connectionTCB.congestionWindow // 2,
                    connectionTCB.maxSegmentSizeReceive * 2,
                )
                connectionTCB.congestionWindow = connectionTCB.slowStartThreshold + (
                    3 * connectionTCB.maxSegmentSizeReceive
                )

    def buildACKSegment(
        self, connectionTCB: TCP_CONNECTION_CONTROL_BLOCK
    ) -> Tuple[TCP_SEGMENT_HEADER, bytes]:
        """Build ACK segment"""
        ackHeader: TCP_SEGMENT_HEADER = TCP_SEGMENT_HEADER(
            sourcePort=connectionTCB.localAddress[1],
            destinationPort=connectionTCB.remoteAddress[1],
            sequenceNumber=connectionTCB.sendSequenceNumber,
            acknowledgmentNumber=connectionTCB.receiveSequenceNumber,
            dataOffset=5,
            flags=TCP_FLAGS.ACK,
            windowSize=min(connectionTCB.receiveWindow, 0xFFFF),
            checksum=0,
            urgentPointer=0,
        )
        serializedHeader: bytes = ackHeader.serialize()
        ackHeader.checksum = CALCULATE_TCP_CHECKSUM(
            connectionTCB.localAddress[0],
            connectionTCB.remoteAddress[0],
            serializedHeader,
        )
        return ackHeader, b""

    def sendData(
        self, connectionTCB: TCP_CONNECTION_CONTROL_BLOCK, payloadData: bytes
    ) -> List[Tuple[TCP_SEGMENT_HEADER, bytes]]:
        """
        Send data segment(s) with proper segmentation and window checking.
        Returns list of (header, payload) tuples to be sent.
        """
        segmentsToSend: List[Tuple[TCP_SEGMENT_HEADER, bytes]] = []
        dataOffset: int = 0
        while dataOffset < len(payloadData):
            # Calculate how much data we can send
            availableWindow: int = connectionTCB.getSendWindow()
            inFlight: int = (
                connectionTCB.sendSequenceNumber - connectionTCB.sendUnacknowledged
            )
            canSend: int = availableWindow - inFlight
            if canSend <= 0:
                break

            segmentSize: int = min(
                len(payloadData) - dataOffset, connectionTCB.maxSegmentSizeSend, canSend
            )
            if segmentSize <= 0:
                break

            segmentPayload: bytes = payloadData[dataOffset : dataOffset + segmentSize]
            dataHeader: TCP_SEGMENT_HEADER = TCP_SEGMENT_HEADER(
                sourcePort=connectionTCB.localAddress[1],
                destinationPort=connectionTCB.remoteAddress[1],
                sequenceNumber=connectionTCB.sendSequenceNumber,
                acknowledgmentNumber=connectionTCB.receiveSequenceNumber,
                dataOffset=5,
                flags=TCP_FLAGS.ACK | TCP_FLAGS.PSH,
                windowSize=min(connectionTCB.receiveWindow, 0xFFFF),
                checksum=0,
                urgentPointer=0,
            )
            serializedHeader: bytes = dataHeader.serialize()
            dataHeader.checksum = CALCULATE_TCP_CHECKSUM(
                connectionTCB.localAddress[0],
                connectionTCB.remoteAddress[0],
                serializedHeader + segmentPayload,
            )
            # Add to retransmission queue
            retransmissionEntry: RETRANSMISSION_QUEUE_ENTRY = (
                RETRANSMISSION_QUEUE_ENTRY(
                    sequenceNumber=connectionTCB.sendSequenceNumber,
                    payloadData=segmentPayload,
                    transmissionTimestamp=time.time(),
                )
            )
            connectionTCB.retransmissionQueue.append(retransmissionEntry)
            connectionTCB.sendSequenceNumber += segmentSize
            dataOffset += segmentSize
            segmentsToSend.append((dataHeader, segmentPayload))

        return segmentsToSend

    def initiateClose(
        self, connectionTCB: TCP_CONNECTION_CONTROL_BLOCK
    ) -> Tuple[TCP_SEGMENT_HEADER, bytes]:
        """Initiate connection close by sending FIN"""
        connectionTCB.updateState(TCP_STATE.FIN_WAIT_1)
        finHeader: TCP_SEGMENT_HEADER = TCP_SEGMENT_HEADER(
            sourcePort=connectionTCB.localAddress[1],
            destinationPort=connectionTCB.remoteAddress[1],
            sequenceNumber=connectionTCB.sendSequenceNumber,
            acknowledgmentNumber=connectionTCB.receiveSequenceNumber,
            dataOffset=5,
            flags=TCP_FLAGS.FIN | TCP_FLAGS.ACK,
            windowSize=min(connectionTCB.receiveWindow, 0xFFFF),
            checksum=0,
            urgentPointer=0,
        )
        connectionTCB.sendSequenceNumber += 1  # FIN consumes one sequence number

        serializedHeader: bytes = finHeader.serialize()
        finHeader.checksum = CALCULATE_TCP_CHECKSUM(
            connectionTCB.localAddress[0],
            connectionTCB.remoteAddress[0],
            serializedHeader,
        )
        return finHeader, b""

    def handleFIN_WAIT_1(
        self,
        connectionTCB: TCP_CONNECTION_CONTROL_BLOCK,
        tcpHeader: TCP_SEGMENT_HEADER,
        payloadData: bytes,
    ) -> Optional[Tuple[TCP_SEGMENT_HEADER, bytes]]:
        """Handle segment in FIN_WAIT_1 state"""
        if tcpHeader.has_flag(TCP_FLAGS.ACK):
            if tcpHeader.acknowledgmentNumber == connectionTCB.sendSequenceNumber:
                # Our FIN was acknowledged
                if tcpHeader.has_flag(TCP_FLAGS.FIN):
                    # Simultaneous close
                    connectionTCB.receiveSequenceNumber += 1
                    connectionTCB.updateState(TCP_STATE.TIME_WAIT)
                    return self.buildACKSegment(connectionTCB)
                else:
                    connectionTCB.updateState(TCP_STATE.FIN_WAIT_2)

        if tcpHeader.has_flag(TCP_FLAGS.FIN):
            connectionTCB.receiveSequenceNumber += 1
            if connectionTCB.currentState == TCP_STATE.FIN_WAIT_1:
                connectionTCB.updateState(TCP_STATE.CLOSING)
            else:
                connectionTCB.updateState(TCP_STATE.TIME_WAIT)
            return self.buildACKSegment(connectionTCB)

        return None

    def handleFIN_WAIT_2(
        self,
        connectionTCB: TCP_CONNECTION_CONTROL_BLOCK,
        tcpHeader: TCP_SEGMENT_HEADER,
        payloadData: bytes,
    ) -> Optional[Tuple[TCP_SEGMENT_HEADER, bytes]]:
        """Handle segment in FIN_WAIT_2 state"""
        if tcpHeader.has_flag(TCP_FLAGS.FIN):
            connectionTCB.receiveSequenceNumber += 1
            connectionTCB.updateState(TCP_STATE.TIME_WAIT)
            return self.buildACKSegment(connectionTCB)

        # Process any remaining data
        if payloadData:
            return self.handleESTABLISHED(connectionTCB, tcpHeader, payloadData)

        return None

    def handleCLOSE_WAIT(
        self,
        connectionTCB: TCP_CONNECTION_CONTROL_BLOCK,
        tcpHeader: TCP_SEGMENT_HEADER,
        payloadData: bytes,
    ) -> Optional[Tuple[TCP_SEGMENT_HEADER, bytes]]:
        """Handle segment in CLOSE_WAIT state"""
        # Process ACKs for any remaining data we send
        if tcpHeader.has_flag(TCP_FLAGS.ACK):
            self.processAcknowledgment(connectionTCB, tcpHeader.acknowledgmentNumber)

        # Application should call initiateClose() when ready
        return None

    def handleCLOSING(
        self,
        connectionTCB: TCP_CONNECTION_CONTROL_BLOCK,
        tcpHeader: TCP_SEGMENT_HEADER,
        payloadData: bytes,
    ) -> Optional[Tuple[TCP_SEGMENT_HEADER, bytes]]:
        """Handle segment in CLOSING state"""
        if tcpHeader.has_flag(TCP_FLAGS.ACK):
            if tcpHeader.acknowledgmentNumber == connectionTCB.sendSequenceNumber:
                connectionTCB.updateState(TCP_STATE.TIME_WAIT)

        return None

    def handleLAST_ACK(
        self,
        connectionTCB: TCP_CONNECTION_CONTROL_BLOCK,
        tcpHeader: TCP_SEGMENT_HEADER,
        payloadData: bytes,
    ) -> Optional[Tuple[TCP_SEGMENT_HEADER, bytes]]:
        """Handle segment in LAST_ACK state"""
        if tcpHeader.has_flag(TCP_FLAGS.ACK):
            if tcpHeader.acknowledgmentNumber == connectionTCB.sendSequenceNumber:
                connectionTCB.updateState(TCP_STATE.CLOSED)
                self.removeConnection(
                    connectionTCB.localAddress, connectionTCB.remoteAddress
                )

        return None

    def handleTIME_WAIT(
        self,
        connectionTCB: TCP_CONNECTION_CONTROL_BLOCK,
        tcpHeader: TCP_SEGMENT_HEADER,
        payloadData: bytes,
    ) -> Optional[Tuple[TCP_SEGMENT_HEADER, bytes]]:
        """
        Handle segment in TIME_WAIT state.
        TIME_WAIT lasts for 2*MSL (Maximum Segment Lifetime) to ensure
        all segments from the closed connection have left the network.
        """
        # In a real implementation, we'd wait 2*MSL (typically 60-120 seconds)
        # before moving to CLOSED state

        # If we receive a FIN, the other side may not have received our last ACK
        if tcpHeader.has_flag(TCP_FLAGS.FIN):
            # Re-ACK the FIN
            return self.buildACKSegment(connectionTCB)

        return None

    def checkRetransmissions(
        self, connectionTCB: TCP_CONNECTION_CONTROL_BLOCK
    ) -> List[Tuple[TCP_SEGMENT_HEADER, bytes]]:
        """
        Check retransmission queue for timed-out segments.
        Returns list of segments that need to be retransmitted.
        """
        segmentsToRetransmit: List[Tuple[TCP_SEGMENT_HEADER, bytes]] = []
        currentTime: float = time.time()
        for entry in connectionTCB.retransmissionQueue:
            if (
                currentTime - entry.transmissionTimestamp
            ) >= connectionTCB.retransmissionTimeout:
                if entry.retransmissionCount >= connectionTCB.MAX_RETRANSMISSIONS:
                    # Too many retransmissions - close connection
                    print(f"[TCP]: Max retransmissions reached, closing connection")
                    connectionTCB.updateState(TCP_STATE.CLOSED)
                    self.removeConnection(
                        connectionTCB.localAddress, connectionTCB.remoteAddress
                    )
                    return []

                # Retransmit segment
                retransmissionHeader: TCP_SEGMENT_HEADER = TCP_SEGMENT_HEADER(
                    sourcePort=connectionTCB.localAddress[1],
                    destinationPort=connectionTCB.remoteAddress[1],
                    sequenceNumber=entry.sequenceNumber,
                    acknowledgmentNumber=connectionTCB.receiveSequenceNumber,
                    dataOffset=5,
                    flags=TCP_FLAGS.ACK | TCP_FLAGS.PSH,
                    windowSize=min(connectionTCB.receiveWindow, 0xFFFF),
                    checksum=0,
                    urgentPointer=0,
                )
                serializedHeader: bytes = retransmissionHeader.serialize()
                retransmissionHeader.checksum = CALCULATE_TCP_CHECKSUM(
                    connectionTCB.localAddress[0],
                    connectionTCB.remoteAddress[0],
                    serializedHeader + entry.payloadData,
                )
                entry.transmissionTimestamp = currentTime
                entry.retransmissionCount += 1
                connectionTCB.handleTimeout()
                segmentsToRetransmit.append((retransmissionHeader, entry.payloadData))

        return segmentsToRetransmit;


### --- TLS/SSL CONTEXT --- ###
def CREATE_TLS_CONTEXT() -> Union[ssl.SSLContext, None]:
    if not os.path.exists(CERTIFICATION_FILE):
        return None;

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);
        context.load_cert_chain(certfile=CERTIFICATION_FILE, keyfile=KEY_FILE);
        context.check_hostname = False;
        context.minimum_version = ssl.TLSVersion.TLSv1_2;

        # The HTTP/2 handler uses blocking socket I/O which is incompatible with asyncio
        # context.set_alpn_protocols(["h2", "http/1.1"]);
        # DISABLED - HTTP/2 not async-safe
        context.set_alpn_protocols(
            ["http/1.1"]
        );  # HTTP/1.1 only for stable async operation
        return context;

    except Exception as TLS_CONTEXT_CREATION_ERROR:
        print(f"[!TLS_FAIL]: {TLS_CONTEXT_CREATION_ERROR}");
        return None;
