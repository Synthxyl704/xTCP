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

def DNS_LOOKUP(domainName: str) -> Union[str, None]:
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
                pass;
            
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
];

def HPACK_DECODE_INTEGER(byteArrayData: bytes, currentPosition: int, prefixBits: int) -> Tuple[int, int]:
    maxPrefix = (1 << prefixBits) - 1;
    value = byteArrayData[currentPosition] & maxPrefix;
    currentPosition += 1;

    if (value < maxPrefix):
        return value, currentPosition;

    shift: int = 0;
    while currentPosition < len(byteArrayData):
        singularByte = byteArrayData[currentPosition];
        currentPosition += 1;
        value += (singularByte & 0x7F) << shift;
        
        if (singularByte & 0x80) == 0:
            break;
        
        shift += 7;

    return (value, currentPosition);


def HPACK_ENCODE_INTEGER(integerToEncode: int, prefixBits: int, prefixMask: int = 0) -> bytes:
    maxPrefix = (1 << prefixBits) - 1;
    
    if integerToEncode < maxPrefix:
        return bytes([prefixMask | integerToEncode]);

    output = bytearray([prefixMask | maxPrefix]);
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
    return HPACK_ENCODE_INTEGER(len(raw), 7, 0) + raw;


def HPACK_GET_STATIC_HEADER(index: int) -> Tuple[str, str]:
    if index <= 0 or index > len(HPACK_STATIC_TABLE):
        return "", "";

    return HPACK_STATIC_TABLE[index - 1];


def HPACK_FIND_STATIC_INDEX(name: str, optionalValue: str) -> Optional[int]:
    for index, item in enumerate(HPACK_STATIC_TABLE, start=1):
        if optionalValue is None:
            if item[0] == name: 
                return index;
        else:
            if (item[0] == name) and (item[1] == optionalValue):
                return index;

    return 0; 


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
    header = bytes(
        [
            (length >> 16) & 0xFF,
            (length >> 8) & 0xFF,
            length & 0xFF,
            frameType & 0xFF,
            flags & 0xFF,
        ]  
    ) + struct.pack("!I", streamId & 0x7FFFFFFF);

    return (header + payload);

def RECV_EXACT(connection: socket.socket, size: int) -> bytes:
    out = bytearray();

    while len(out) < size:
        chunk = connection.recv(size - len(out));

        if not chunk:
            return b"";

        out.extend(chunk);

    return bytes(out);


def READ_HTTP2_FRAME(connection: socket.socket) -> Optional[Tuple[int, int, int, bytes]]:
    header = RECV_EXACT(connection, HTTP2_FRAME_HEADER_LEN);
    
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

    payload += struct.pack("!HI", HTTP2_SETTINGS_INITIAL_WINDOW_SIZE, initialWindow);
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
import random
from dataclasses import dataclass, field
from enum import Enum, Flag, IntEnum
from collections import deque

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
    FIN = 0x01;
    SYN = 0x02;
    RST = 0x04;
    PSH = 0x08;
    ACK = 0x10;
    URG = 0x20;
    ECE = 0x40;
    CWR = 0x80;

@dataclass
class TCP_SEGMENT_HEADER:
    sourcePort: int;
    destinationPort: int;
    sequenceNumber: int;
    acknowledgmentNumber: int;
    dataOffset: int;
    flags: int;
    windowSize: int;
    checksum: int;
    urgentPointer: int;
    options: bytes = field(default_factory=bytes);
    HEADER_LENGTH_MIN: int = 20;

    def serialize(self) -> bytes:
        dataOffsetWords: int = 5 + (len(self.options) + 3) // 4;
        base2TCPheader: bytes = struct.pack(
            "!HHIIHHHH",
            self.sourcePort & 0xFFFF,
            self.destinationPort & 0xFFFF,
            self.sequenceNumber & 0xFFFFFFFF,
            self.acknowledgmentNumber & 0xFFFFFFFF,
            ((dataOffsetWords << 12) | (self.flags & 0x3F)) & 0xFFFF,
            self.windowSize & 0xFFFF,
            self.checksum & 0xFFFF,
            self.urgentPointer & 0xFFFF,
        );

        paddingLength: int = (4 - (len(self.options) % 4)) % 4;

        return (base2TCPheader + self.options + (b"\x00" * paddingLength));

    @classmethod
    def deserialize(cls, data: bytes) -> Tuple["TCP_SEGMENT_HEADER", int]:
        if len(data) < (cls.HEADER_LENGTH_MIN):
            raise ValueError("\n[!TCP_ERR]: TCP header was/is too short\n");

        sourcePort: int = struct.unpack("!H", data[0:2])[0];
        destinationPort: int      = struct.unpack("!H", data[2:4])[0];
        sequenceNumber: int       = struct.unpack("!I", data[4:8])[0];
        acknowledgmentNumber: int = struct.unpack("!I", data[8:12])[0];
        dataOffsetAndFlags: int   = struct.unpack("!H", data[12:14])[0];

        dataOffset: int = ((dataOffsetAndFlags >> 12) * 4);
        flags: int = (dataOffsetAndFlags & 0x3F);

        windowSize: int    = struct.unpack("!H", data[14:16])[0];
        checksum: int      = struct.unpack("!H", data[16:18])[0];
        urgentPointer: int = struct.unpack("!H", data[18:20])[0];

        options: bytes = b"";

        if dataOffset > cls.HEADER_LENGTH_MIN:
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
    version: int = 4;
    internetHeaderLength: int = 5;
    typeOfService: int = 0;
    totalLength: int = 20;
    identification: int = 0;
    flags: int = 2;
    fragmentOffset: int = 0;
    timeToLive: int = 64;
    protocol: int = 6;
    headerChecksum: int = 0;
    sourceIP: str = "0.0.0.0";
    destinationIP: str = "0.0.0.0";
    options: bytes = field(default_factory=bytes);
    
    HEADER_LENGTH: int = 20;
    PROTOCOL_TCP: int = 6;

    def serialize(self) -> bytes:
        headerLengthWords: int = (5 + (len(self.options) + 3) // 4);

        def ipToInt(ipStr: str) -> int:
            parts: List[str] = ipStr.split(".");
            return (
                (int(parts[0]) << 24) | (int(parts[1]) << 16)| (int(parts[2]) << 8) | int(parts[3])
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
            paddingLength: int = (4 - (len(self.options) % 4)) % 4;
            header += (self.options + (b"\x00" * paddingLength));

        return (header);

    @classmethod
    def deserialize(cls, data: bytes) -> Tuple["IP_PACKET_HEADER", int]:
        if len(data) < cls.HEADER_LENGTH:
            raise ValueError("IP header too short");

        firstByte: int = data[0];
        version: int = firstByte >> 4;
        headerLengthWords: int = firstByte & 0x0F;
        headerLength: int = headerLengthWords * 4;
        typeOfService: int = data[1];
        totalLength: int = struct.unpack("!H", data[2:4])[0];
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
            return (f"{(ipInt >> 24) & 0xFF}.{(ipInt >> 16) & 0xFF}.{(ipInt >> 8) & 0xFF}.{ipInt & 0xFF}");

        options: bytes = b"";
        if headerLength > cls.HEADER_LENGTH:
            options = data[cls.HEADER_LENGTH : headerLength];

        header: IP_PACKET_HEADER = cls(
            version=version,
            internetHeaderLength=headerLengthWords,
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
    if len(data) % 2 == 1:
        data += b"\x00"; 

    checksum: int = 0;
    for index in range(0, len(data), 2):
        word: int = (data[index] << 8) + data[index + 1];
        checksum += word;

    while (checksum >> 16):
        checksum = (checksum & 0xFFFF) + (checksum >> 16);

    return (~checksum & 0xFFFF);


def CALCULATE_TCP_CHECKSUM(sourceIP: str, destinationIP: str, TCP_headerAndData: bytes) -> int:
    def ipToBytes(ipStr: str) -> bytes:
        parts: List[int] = [int(part) for part in ipStr.split(".")];
        return bytes(parts);

    pseudoHeader: bytes = (
        ipToBytes(sourceIP)
        + ipToBytes(destinationIP)
        + b"\x00"
        + bytes([6])
        + struct.pack("!H", len(TCP_headerAndData))
    );
    
    return CALCULATE_CHECKSUM(pseudoHeader + TCP_headerAndData);


@dataclass
class RETRANSMISSION_QUEUE_ENTRY:
    sequenceNumber: int;
    payloadData: bytes;
    transmissionTimestamp: float;
    retransmissionCount: int = 0;

class TCP_CONNECTION_CONTROL_BLOCK:
    DEFAULT_MSS: int = 536;
    MAXIMUM_MSS: int = 1460;
    INITIAL_WINDOW_SIZE: int = 65535;

    RTO_INITIAL: float = 1.0;
    RTO_MIN: float = 0.2;
    RTO_MAX: float = 60.0;
    MAX_RETRANSMISSIONS: int = 5;

    def __init__(self, localAddress: Tuple[str, int], remoteAddress: Tuple[str, int]):
        self.localAddress: Tuple[str, int] = localAddress;
        self.remoteAddress: Tuple[str, int] = remoteAddress;
        self.currentState: TCP_STATE = TCP_STATE.CLOSED; 
        
        self.initialSendSequenceNumber: int = random.randint(0, 0xFFFFFFFF);
        self.sendSequenceNumber: int = self.initialSendSequenceNumber;
        self.sendUnacknowledged: int = self.initialSendSequenceNumber;
        self.sendWindow: int = self.INITIAL_WINDOW_SIZE;
        self.sendWindowScale: int = 0;

        self.initialReceiveSequenceNumber: int = 0;
        self.receiveSequenceNumber: int = 0;
        self.receiveWindow: int = self.INITIAL_WINDOW_SIZE;
        self.receiveWindowScale: int = 0;
        
        self.maxSegmentSizeSend: int = self.DEFAULT_MSS;
        self.maxSegmentSizeReceive: int = self.DEFAULT_MSS;

        self.retransmissionQueue: deque = deque();

        self.roundTripTimeSmoothed: Optional[float] = None;
        self.roundTripTimeVariance: Optional[float] = None;
        self.retransmissionTimeout: float = self.RTO_INITIAL;
 
        self.congestionWindow: int = (self.maxSegmentSizeReceive * 2);
        self.slowStartThreshold: int = self.INITIAL_WINDOW_SIZE;
        self.duplicateAcknowledgmentCount: int = 0;
         
        self.sendWindowUpdateThreshold: int = self.maxSegmentSizeReceive;
        
        self.selectiveAcknowledgmentEnabled: bool = False;
        self.timestampEnabled: bool = False;

        self.receiveBuffer: bytearray = bytearray();
        self.sendBuffer: bytearray = bytearray();
        self.outOfOrderSegments: Dict[int, bytes] = {};
        
        self.connectionEstablishmentTime: Optional[float] = None;
        self.lastActivityTime: float = time.time();

    def getSendWindow(self) -> int:
        return min(self.congestionWindow, self.sendWindow);

    def updateRoundTripTime(self, measuredRTT: float) -> None:
        if self.roundTripTimeSmoothed is None:
            self.roundTripTimeSmoothed = measuredRTT;
            self.roundTripTimeVariance = measuredRTT / 2; 
        else:
            
            error: float = measuredRTT - self.roundTripTimeSmoothed;
            
            self.roundTripTimeVariance = float((3/4) * self.roundTripTimeVariance + (1/4) * abs(error));
            self.roundTripTimeSmoothed = (7/8) * self.roundTripTimeSmoothed + (1/8) * measuredRTT;

        self.retransmissionTimeout = self.roundTripTimeSmoothed + max(0.01, 4 * self.roundTripTimeVariance);
        
        self.retransmissionTimeout = max(self.RTO_MIN, min(self.RTO_MAX, self.retransmissionTimeout));

    def handleTimeout(self) -> None:
        self.retransmissionTimeout = min(self.RTO_MAX, self.retransmissionTimeout * 2);
        
        self.slowStartThreshold = max(self.congestionWindow // 2, self.maxSegmentSizeReceive * 2);
        self.congestionWindow = self.maxSegmentSizeReceive;

    def incrementCongestionWindow(self, bytesAcked: int) -> None: 
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
        self.connections: Dict[Tuple[Tuple[str, int], Tuple[str, int]], TCP_CONNECTION_CONTROL_BLOCK] = {};
        self.listenSockets: Dict[Tuple[str, int], socket.socket] = {};
        self.pendingConnections: Dict[Tuple[str, int], List[TCP_CONNECTION_CONTROL_BLOCK]] = {};


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

    def processIncomingSegment(self, 
        ipHeader: IP_PACKET_HEADER, TCP_header: TCP_SEGMENT_HEADER,
        payloadData: bytes,
    ) -> Optional[Tuple[TCP_SEGMENT_HEADER, bytes]]:
        localAddress: Tuple[str, int] = (
            ipHeader.destinationIP,
            TCP_header.destinationPort,
        );

        remoteAddress: Tuple[str, int] = (ipHeader.sourceIP, TCP_header.sourcePort);
    
        receivedChecksum: int = TCP_header.checksum;
        TCP_header.checksum = 0;
        calculatedChecksum: int = CALCULATE_TCP_CHECKSUM(
            ipHeader.sourceIP,
            ipHeader.destinationIP,
            TCP_header.serialize() + payloadData,
        );

        if receivedChecksum != calculatedChecksum:
            print(f"[TCP]: Checksum mismatch, dropping segment");
            return None;

        TCP_header.checksum = receivedChecksum;
        connectionTCB: Optional[TCP_CONNECTION_CONTROL_BLOCK] = self.getConnection(
            localAddress, remoteAddress
        );

        if (connectionTCB is None and TCP_header.has_flag(TCP_FLAGS.SYN) and not TCP_header.has_flag(TCP_FLAGS.ACK)):
            if localAddress in self.listenSockets:
                
                connectionTCB = self.createConnection(localAddress, remoteAddress);
                connectionTCB.updateState(TCP_STATE.SYN_RECEIVED);
                connectionTCB.initialReceiveSequenceNumber = TCP_header.sequenceNumber;
                connectionTCB.receiveSequenceNumber = TCP_header.sequenceNumber + 1;
                
                self.parseTCPOptions(connectionTCB, TCP_header.options);
                return self.buildSYNACKSegment(connectionTCB);
            else:
                return self.buildRSTSegment(localAddress, remoteAddress, TCP_header.sequenceNumber);

        if connectionTCB is None:
            return self.buildRSTSegment(localAddress, remoteAddress, TCP_header.sequenceNumber);

        if connectionTCB.currentState == TCP_STATE.SYN_RECEIVED:
            return self.handleSYN_RECEIVED(connectionTCB, TCP_header, payloadData);
        elif connectionTCB.currentState == TCP_STATE.ESTABLISHED:
            return self.handleESTABLISHED(connectionTCB, TCP_header, payloadData);
        elif connectionTCB.currentState == TCP_STATE.FIN_WAIT_1:
            return self.handleFIN_WAIT_1(connectionTCB, TCP_header, payloadData);
        elif connectionTCB.currentState == TCP_STATE.FIN_WAIT_2:
            return self.handleFIN_WAIT_2(connectionTCB, TCP_header, payloadData);
        elif connectionTCB.currentState == TCP_STATE.CLOSE_WAIT:
            return self.handleCLOSE_WAIT(connectionTCB, TCP_header, payloadData);
        elif connectionTCB.currentState == TCP_STATE.CLOSING:
            return self.handleCLOSING(connectionTCB, TCP_header, payloadData);
        elif connectionTCB.currentState == TCP_STATE.LAST_ACK:
            return self.handleLAST_ACK(connectionTCB, TCP_header, payloadData);
        elif connectionTCB.currentState == TCP_STATE.TIME_WAIT:
            return self.handleTIME_WAIT(connectionTCB, TCP_header, payloadData);

        return None;

    def parseTCPOptions(self, connectionTCB: TCP_CONNECTION_CONTROL_BLOCK, options: bytes) -> None:
        optionIndex: int = 0;
        while optionIndex < len(options):
            optionKind: int = options[optionIndex];
            
            if optionKind == 0:
                break;
            
            elif optionKind == 1:
                optionIndex += 1;
                continue;
            
            elif optionKind == 2:
                if ((optionIndex + 3) < len(options)):
                    maximumSegmentSize: int = struct.unpack(
                        "!H", options[optionIndex + 2 : optionIndex + 4]
                    )[0];

                    connectionTCB.maxSegmentSizeReceive = min(maximumSegmentSize, connectionTCB.MAXIMUM_MSS);
                
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

    def buildSYNACKSegment(self, connectionTCB: TCP_CONNECTION_CONTROL_BLOCK) -> Tuple[TCP_SEGMENT_HEADER, bytes]:
        options: bytes = (
            bytes([2, 4])
            + struct.pack("!H", connectionTCB.maxSegmentSizeReceive)
            + bytes([1, 1, 1])
            + bytes([3, 3, connectionTCB.sendWindowScale])
        );

        synAckHeader: TCP_SEGMENT_HEADER = TCP_SEGMENT_HEADER(
            sourcePort = connectionTCB.localAddress[1],
            destinationPort = connectionTCB.remoteAddress[1],
            sequenceNumber = connectionTCB.initialSendSequenceNumber,
            acknowledgmentNumber = connectionTCB.receiveSequenceNumber,
            dataOffset = 0,
            flags = TCP_FLAGS.SYN | TCP_FLAGS.ACK,
            windowSize = min(connectionTCB.receiveWindow, 0xFFFF),
            checksum = 0,
            urgentPointer = 0,
            options = options,
        );

        serializedHeader: bytes = synAckHeader.serialize();
        synAckHeader.checksum = CALCULATE_TCP_CHECKSUM(
            connectionTCB.localAddress[0],
            connectionTCB.remoteAddress[0],
            serializedHeader,
        );

        return synAckHeader, b"";

    def buildRSTSegment(self,
        localAddress: Tuple[str, int],
        remoteAddress: Tuple[str, int], acknowledgmentNumber: int,
    ) -> Tuple[TCP_SEGMENT_HEADER, bytes]:

        RST_header: TCP_SEGMENT_HEADER = TCP_SEGMENT_HEADER(
            sourcePort=localAddress[1],
            destinationPort=remoteAddress[1],
            sequenceNumber=0,
            acknowledgmentNumber=acknowledgmentNumber,
            dataOffset=5,
            flags=TCP_FLAGS.RST | TCP_FLAGS.ACK,
            windowSize=0,
            checksum=0,
            urgentPointer=0,
        );

        serializedHeader: bytes = RST_header.serialize();
        RST_header.checksum = CALCULATE_TCP_CHECKSUM(localAddress[0], remoteAddress[0], serializedHeader);
        return (RST_header, b"");

    def handleSYN_RECEIVED(self,
        connectionTCB: TCP_CONNECTION_CONTROL_BLOCK,
        TCP_header: TCP_SEGMENT_HEADER,
        payloadData: bytes,
    ) -> Optional[Tuple[TCP_SEGMENT_HEADER, bytes]]:
        
        if TCP_header.has_flag(TCP_FLAGS.ACK):
            if (TCP_header.acknowledgmentNumber == connectionTCB.initialSendSequenceNumber + 1):
                
                connectionTCB.sendUnacknowledged = TCP_header.acknowledgmentNumber;
                connectionTCB.sendSequenceNumber = TCP_header.acknowledgmentNumber;
                
                connectionTCB.updateState(TCP_STATE.ESTABLISHED);
                
                connectionTCB.sendWindow = (TCP_header.windowSize << connectionTCB.sendWindowScale);
                
                print(f"[TCP]: Connection established {connectionTCB.localAddress} <-> {connectionTCB.remoteAddress}");
                return None;
            
            else:
                return self.buildRSTSegment(
                    connectionTCB.localAddress,
                    connectionTCB.remoteAddress,
                    TCP_header.sequenceNumber,
                );

        return None;

    def handleESTABLISHED(self,
        connectionTCB: TCP_CONNECTION_CONTROL_BLOCK,
        TCP_header: TCP_SEGMENT_HEADER,
        payloadData: bytes,
    ) -> Optional[Tuple[TCP_SEGMENT_HEADER, bytes]]:
        
        connectionTCB.sendWindow = TCP_header.windowSize << connectionTCB.sendWindowScale;
        
        if TCP_header.has_flag(TCP_FLAGS.ACK):
            self.processAcknowledgment(connectionTCB, TCP_header.acknowledgmentNumber);

        if payloadData:
            if TCP_header.sequenceNumber == connectionTCB.receiveSequenceNumber:
                connectionTCB.receiveBuffer.extend(payloadData);
                connectionTCB.receiveSequenceNumber += len(payloadData);
                while (connectionTCB.receiveSequenceNumber in connectionTCB.outOfOrderSegments):
                    segmentData: bytes = connectionTCB.outOfOrderSegments.pop(connectionTCB.receiveSequenceNumber);

                    connectionTCB.receiveBuffer.extend(segmentData);
                    connectionTCB.receiveSequenceNumber += len(segmentData);
            
            else:
                connectionTCB.outOfOrderSegments[TCP_header.sequenceNumber] = payloadData;

        if TCP_header.has_flag(TCP_FLAGS.FIN):
            connectionTCB.receiveSequenceNumber += 1;
            connectionTCB.updateState(TCP_STATE.CLOSE_WAIT);

            ACK_header: TCP_SEGMENT_HEADER = TCP_SEGMENT_HEADER(
                sourcePort=connectionTCB.localAddress[1],
                destinationPort=connectionTCB.remoteAddress[1],
                sequenceNumber=connectionTCB.sendSequenceNumber,
                acknowledgmentNumber=connectionTCB.receiveSequenceNumber,
                dataOffset=5,
                flags=TCP_FLAGS.ACK,
                windowSize=min(connectionTCB.receiveWindow, 0xFFFF),
                checksum=0,
                urgentPointer=0,
            );

            serializedHeader: bytes = ACK_header.serialize(); 
            ACK_header.checksum = CALCULATE_TCP_CHECKSUM(
                connectionTCB.localAddress[0],
                connectionTCB.remoteAddress[0],
                serializedHeader,
            );

            return (ACK_header, b"");

        if (payloadData or TCP_header.has_flag(TCP_FLAGS.SYN) or TCP_header.has_flag(TCP_FLAGS.FIN)):
            return self.buildACKSegment(connectionTCB);

        return None;

    def processAcknowledgment(self, connectionTCB: TCP_CONNECTION_CONTROL_BLOCK, acknowledgmentNumber: int) -> None:
        if acknowledgmentNumber > connectionTCB.sendUnacknowledged:
            bytesAcknowledged: int = (acknowledgmentNumber - connectionTCB.sendUnacknowledged);
            connectionTCB.sendUnacknowledged = acknowledgmentNumber;
            connectionTCB.duplicateAcknowledgmentCount = 0;

            while connectionTCB.retransmissionQueue:
                entry: RETRANSMISSION_QUEUE_ENTRY = connectionTCB.retransmissionQueue[0];
                
                if (entry.sequenceNumber + len(entry.payloadData)) <= acknowledgmentNumber:
                    
                    if entry.retransmissionCount == 0 and entry.transmissionTimestamp:
                        measuredRTT: float = time.time() - entry.transmissionTimestamp;
                        connectionTCB.updateRoundTripTime(measuredRTT);

                    connectionTCB.retransmissionQueue.popleft();
                
                else:
                    break;

            connectionTCB.incrementCongestionWindow(bytesAcknowledged);
        
        elif acknowledgmentNumber == connectionTCB.sendUnacknowledged:
            connectionTCB.duplicateAcknowledgmentCount += 1
            
            if connectionTCB.duplicateAcknowledgmentCount == 3:
                connectionTCB.slowStartThreshold = max(
                    connectionTCB.congestionWindow // 2,
                    connectionTCB.maxSegmentSizeReceive * 2,
                );

                connectionTCB.congestionWindow = connectionTCB.slowStartThreshold + (3 * connectionTCB.maxSegmentSizeReceive);

    def buildACKSegment(self, connectionTCB: TCP_CONNECTION_CONTROL_BLOCK) -> Tuple[TCP_SEGMENT_HEADER, bytes]:
        ACK_header: TCP_SEGMENT_HEADER = TCP_SEGMENT_HEADER(
            sourcePort=connectionTCB.localAddress[1],
            destinationPort=connectionTCB.remoteAddress[1],
            sequenceNumber=connectionTCB.sendSequenceNumber,
            acknowledgmentNumber=connectionTCB.receiveSequenceNumber,
            dataOffset=5,
            flags=TCP_FLAGS.ACK,
            windowSize=min(connectionTCB.receiveWindow, 0xFFFF),
            checksum=0,
            urgentPointer=0,
        );

        serializedHeader: bytes = ACK_header.serialize();
        ACK_header.checksum = CALCULATE_TCP_CHECKSUM(
            connectionTCB.localAddress[0],
            connectionTCB.remoteAddress[0],
            serializedHeader,
        );

        return (ACK_header, b"");

    def sendData(self, connectionTCB: TCP_CONNECTION_CONTROL_BLOCK, payloadData: bytes) -> List[Tuple[TCP_SEGMENT_HEADER, bytes]]:
        segmentsToSend: List[Tuple[TCP_SEGMENT_HEADER, bytes]] = [];
        dataOffset: int = 0;

        while dataOffset < len(payloadData):
            availableWindow: int = connectionTCB.getSendWindow();
            inFlight: int = (connectionTCB.sendSequenceNumber - connectionTCB.sendUnacknowledged);
            canSend: int = (availableWindow - inFlight);
            
            if canSend <= 0:
                break;

            segmentSize: int = min(len(payloadData) - dataOffset, connectionTCB.maxSegmentSizeSend, canSend);
        
            if segmentSize <= 0:
                break;

            segmentPayload: bytes = payloadData[dataOffset : dataOffset + segmentSize];
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
            );

            serializedHeader: bytes = dataHeader.serialize();
            dataHeader.checksum = CALCULATE_TCP_CHECKSUM(
                connectionTCB.localAddress[0],
                connectionTCB.remoteAddress[0],
                serializedHeader + segmentPayload,
            );

            retransmissionEntry: RETRANSMISSION_QUEUE_ENTRY = (
                RETRANSMISSION_QUEUE_ENTRY(
                    sequenceNumber=connectionTCB.sendSequenceNumber,
                    payloadData=segmentPayload,
                    transmissionTimestamp=time.time(),
                )
            );

            connectionTCB.retransmissionQueue.append(retransmissionEntry);
            connectionTCB.sendSequenceNumber += segmentSize;
            dataOffset += segmentSize;
            segmentsToSend.append((dataHeader, segmentPayload));

        return segmentsToSend;

    def initiateClose(self, connectionTCB: TCP_CONNECTION_CONTROL_BLOCK) -> Tuple[TCP_SEGMENT_HEADER, bytes]:
        
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
        );

        connectionTCB.sendSequenceNumber += 1;

        serializedHeader: bytes = finHeader.serialize();
        finHeader.checksum = CALCULATE_TCP_CHECKSUM(
            connectionTCB.localAddress[0],
            connectionTCB.remoteAddress[0],
            serializedHeader,
        );

        return (finHeader, b"");

    def handleFIN_WAIT_1(self,
        connectionTCB: TCP_CONNECTION_CONTROL_BLOCK,
        TCP_header: TCP_SEGMENT_HEADER,
        payloadData: bytes,
    ) -> Optional[Tuple[TCP_SEGMENT_HEADER, bytes]]:
        
        if TCP_header.has_flag(TCP_FLAGS.ACK):
            if TCP_header.acknowledgmentNumber == connectionTCB.sendSequenceNumber:
                if TCP_header.has_flag(TCP_FLAGS.FIN):
                    connectionTCB.receiveSequenceNumber += 1;
                    connectionTCB.updateState(TCP_STATE.TIME_WAIT);
                    return self.buildACKSegment(connectionTCB);
                else:
                    connectionTCB.updateState(TCP_STATE.FIN_WAIT_2);

        if TCP_header.has_flag(TCP_FLAGS.FIN):
            connectionTCB.receiveSequenceNumber += 1;

            if connectionTCB.currentState == TCP_STATE.FIN_WAIT_1:
                connectionTCB.updateState(TCP_STATE.CLOSING);

            else:
                connectionTCB.updateState(TCP_STATE.TIME_WAIT);

            return self.buildACKSegment(connectionTCB);

        return None;

    def handleFIN_WAIT_2(
        self,
        connectionTCB: TCP_CONNECTION_CONTROL_BLOCK,
        TCP_header: TCP_SEGMENT_HEADER,
        payloadData: bytes,
    ) -> Optional[Tuple[TCP_SEGMENT_HEADER, bytes]]:
        if TCP_header.has_flag(TCP_FLAGS.FIN):
            connectionTCB.receiveSequenceNumber += 1;
            connectionTCB.updateState(TCP_STATE.TIME_WAIT);
            return self.buildACKSegment(connectionTCB);

        if payloadData:
            return self.handleESTABLISHED(connectionTCB, TCP_header, payloadData);

        return None;

    def handleCLOSE_WAIT(
        self,
        connectionTCB: TCP_CONNECTION_CONTROL_BLOCK,
        TCP_header: TCP_SEGMENT_HEADER,
        payloadData: bytes,
    ) -> Optional[Tuple[TCP_SEGMENT_HEADER, bytes]]: 

        if TCP_header.has_flag(TCP_FLAGS.ACK):
            self.processAcknowledgment(connectionTCB, TCP_header.acknowledgmentNumber);

        return None;

    def handleCLOSING(self,
        connectionTCB: TCP_CONNECTION_CONTROL_BLOCK,
        TCP_header: TCP_SEGMENT_HEADER,
        payloadData: bytes,
    ) -> Optional[Tuple[TCP_SEGMENT_HEADER, bytes]]:

        if TCP_header.has_flag(TCP_FLAGS.ACK):
            if TCP_header.acknowledgmentNumber == connectionTCB.sendSequenceNumber:
                connectionTCB.updateState(TCP_STATE.TIME_WAIT);

        return None;

    def handleLAST_ACK(
        self,
        connectionTCB: TCP_CONNECTION_CONTROL_BLOCK,
        TCP_header: TCP_SEGMENT_HEADER,
        payloadData: bytes,
    ) -> Optional[Tuple[TCP_SEGMENT_HEADER, bytes]]:

        if TCP_header.has_flag(TCP_FLAGS.ACK):
            if TCP_header.acknowledgmentNumber == connectionTCB.sendSequenceNumber:
                connectionTCB.updateState(TCP_STATE.CLOSED);
                self.removeConnection(connectionTCB.localAddress, connectionTCB.remoteAddress);

        return None;

    def handleTIME_WAIT(
        self,
        connectionTCB: TCP_CONNECTION_CONTROL_BLOCK,
        TCP_header: TCP_SEGMENT_HEADER,
        payloadData: bytes,
    ) -> Optional[Tuple[TCP_SEGMENT_HEADER, bytes]]:

        if TCP_header.has_flag(TCP_FLAGS.FIN):
            return self.buildACKSegment(connectionTCB);

        return None;

    def checkRetransmissions(self, connectionTCB: TCP_CONNECTION_CONTROL_BLOCK) -> List[Tuple[TCP_SEGMENT_HEADER, bytes]]:

        segmentsToRetransmit: List[Tuple[TCP_SEGMENT_HEADER, bytes]] = [];
        currentTime: float = time.time();

        for entry in connectionTCB.retransmissionQueue:
            if (currentTime - entry.transmissionTimestamp) >= connectionTCB.retransmissionTimeout:
                if entry.retransmissionCount >= connectionTCB.MAX_RETRANSMISSIONS:
                    
                    print(f"[TCP]: Max retransmissions reached, closing connection");
                    connectionTCB.updateState(TCP_STATE.CLOSED);
                    self.removeConnection(connectionTCB.localAddress, connectionTCB.remoteAddress);
                    return [];

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
                );

                serializedHeader: bytes = retransmissionHeader.serialize();
                retransmissionHeader.checksum = CALCULATE_TCP_CHECKSUM(
                    connectionTCB.localAddress[0],
                    connectionTCB.remoteAddress[0],
                    serializedHeader + entry.payloadData,
                );

                entry.transmissionTimestamp = currentTime;
                entry.retransmissionCount += 1;
                connectionTCB.handleTimeout();
                segmentsToRetransmit.append((retransmissionHeader, entry.payloadData));

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

        context.set_alpn_protocols(
            ["http/1.1"]
        );
        return context;

    except Exception as TLS_CONTEXT_CREATION_ERROR:
        print(f"[!TLS_FAIL]: {TLS_CONTEXT_CREATION_ERROR}");
        return None;
