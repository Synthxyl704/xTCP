import socket;
import gzip;
import mimetypes;
import ssl;
import time;
import struct;
import os;

from typing import Optional, Dict, Union, List, Tuple;
from email.utils import formatdate;

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
        return info;

    for name, _, token in browserDatabase:
        if token and token in userAgent:
            info["browser"] = name;
            try:
                info["version"] = userAgent.split(token, 1)[1].split()[0];
            except:
                pass;
            break;

    for OS_Name, markers in OS_Database:
        if any(m in userAgent.lower() for m in markers):
            info["os"] = OS_Name;
            break;
    return info;


### --- MIME TYPES --- ###


def getMIMEtype(filePath: str):
    mimeType, _ = mimetypes.guess_type(filePath);
    return mimeType or "application/octet-stream";


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


def HPACK_DECODE_INTEGER(
    byteArrayData: bytes, currentPosition: int, prefixBits: int
) -> Tuple[int, int]:
    maxPrefix = (1 << prefixBits) - 1;
    value = byteArrayData[currentPosition] & maxPrefix;
    currentPosition += 1;
    if value < maxPrefix:
        return value, currentPosition;

    shift: int = 0;
    while currentPosition < len(byteArrayData):
        b = byteArrayData[currentPosition];
        currentPosition += 1;
        value += (b & 0x7F) << shift;
        if (b & 0x80) == 0:
            break;

        shift += 7;

    return (value, currentPosition);


def HPACK_ENCODE_INTEGER(value: int, prefixBits: int, prefixMask: int = 0) -> bytes:
    maxPrefix = (1 << prefixBits) - 1;
    if value < maxPrefix:
        return bytes([prefixMask | value]);

    output = bytearray([prefixMask | maxPrefix]);
    value -= maxPrefix;
    while value >= 128:
        output.append((value % 128) + 128);
        value //= 128;

    output.append(value);
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


def HPACK_ENCODE_STRING(value: str) -> bytes:
    raw = value.encode("utf-8");
    return HPACK_ENCODE_INTEGER(len(raw), 7, 0) + raw;


def HPACK_GET_STATIC_HEADER(index: int) -> Tuple[str, str]:
    if index <= 0 or index > len(HPACK_STATIC_TABLE):
        return "", "";

    return HPACK_STATIC_TABLE[index - 1];


def HPACK_FIND_STATIC_INDEX(
    name: str, optionalValue: str = None
) -> Union[None, int]:
    for idx, item in enumerate(HPACK_STATIC_TABLE, start=1):
        if optionalValue is None:
            if item[0] == name:
                return idx;
        else:
            if (item[0] == name) and (item[1] == optionalValue):
                return idx;

    return 0;


def HPACK_DECODE_HEADER_BLOCK(binaryData: bytes) -> Dict[str, str]:
    headers: Dict[str, str] = {};
    pos = 0;
    while pos < len(binaryData):
        b = binaryData[pos];
        if b & 0x80:
            index, pos = HPACK_DECODE_INTEGER(binaryData, pos, 7);
            name, value = HPACK_GET_STATIC_HEADER(index);
            if name:
                headers[name] = value;

            continue;

        if (b & 0x40) or (b & 0x10) or (b & 0x00) == 0:
            if b & 0x40:
                (nameIndex, pos) = HPACK_DECODE_INTEGER(binaryData, pos, 6);
            else:
                (nameIndex, pos) = HPACK_DECODE_INTEGER(binaryData, pos, 4);

            if nameIndex == 0:
                (name, pos) = HPACK_DECODE_STRING(binaryData, pos);
            else:
                name, _ = HPACK_GET_STATIC_HEADER(nameIndex);
            (value, pos) = HPACK_DECODE_STRING(binaryData, pos);
            if name:
                headers[name.lower()] = value;
            continue;
        break;
    return headers;


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
    return header + payload;


def RECV_EXACT(connection: socket.socket, size: int) -> bytes:
    out = bytearray();
    while len(out) < size:
        chunk = connection.recv(size - len(out));
        if not chunk:
            return b"";
        out.extend(chunk);
    return bytes(out);


def READ_HTTP2_FRAME(
    connection: socket.socket,
) -> Optional[Tuple[int, int, int, bytes]]:
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


def BUILD_HTTP2_SETTINGS(
    maxConcurrentStreams: int = 128, initialWindow: int = 65535
) -> bytes:
    payload = struct.pack(
        "!HI", HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, maxConcurrentStreams
    );
    payload += struct.pack("!HI", HTTP2_SETTINGS_INITIAL_WINDOW_SIZE, initialWindow);
    return BUILD_HTTP2_FRAME(HTTP2_FRAME_SETTINGS, 0x0, 0, payload);


### --- HTTP/2 CONNECTION HANDLER --- ###


def HANDLE_HTTP2_CONNECTION(
    connection: socket.socket, clientAddress, isTLS=False, isIPv6=False
):
    protocol = "HTTPS" if isTLS else "HTTP";
    sessionID = SESSION_MANAGER.CREATE_NEW_SESSION(clientAddress);
    streams: Dict[int, Dict] = {};
    pushedForParent: set[int] = set();
    preface = RECV_EXACT(connection, len(HTTP2_PREFACE));
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


### --- TLS/SSL CONTEXT --- ###


def CREATE_TLS_CONTEXT() -> Union[ssl.SSLContext, None]:
    if not os.path.exists(CERTIFICATION_FILE):
        return None;

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);
        context.load_cert_chain(
            certfile=CERTIFICATION_FILE, keyfile=KEY_FILE
        );
        context.check_hostname = False;
        context.minimum_version = ssl.TLSVersion.TLSv1_2;
        context.set_alpn_protocols(["h2", "http/1.1"]);
        return context;
    except Exception as TLS_CONTEXT_CREATION_ERROR:
        print(f"[!TLS_FAIL]: {TLS_CONTEXT_CREATION_ERROR}");
        return None;
