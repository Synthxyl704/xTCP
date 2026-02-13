import socket
import threading
import os
import gzip 
import mimetypes
import signal
import ssl
import time
import json
import selectors 
import struct

from datetime import datetime
from typing import Optional, Dict, Union, List, Tuple 
from email.utils import formatdate

HOST_SERVER_IPv4: str = '127.0.0.1';
HOST_SERVER_IPv6: str = '::1';

PORT: int = 8080;
TLS_PORT: int = 8443;

BUFFER_SIZE: int = 4096;

CERTIFICATION_FILE: str = 'server.crt';
KEY_FILE: str = 'server.key';

HTTP2_PREFACE: bytes = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
HTTP2_FRAME_HEADER_LEN: int = 9;
HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS: int = 0x3;
HTTP2_SETTINGS_INITIAL_WINDOW_SIZE: int = 0x4;
HTTP2_FLAG_END_STREAM: int = 0x1;
HTTP2_FLAG_END_HEADERS: int = 0x4;
HTTP2_FLAG_ACK: int = 0x1;
HTTP2_FRAME_DATA: int = 0x0;
HTTP2_FRAME_HEADERS: int = 0x1;
HTTP2_FRAME_SETTINGS: int = 0x4;
HTTP2_FRAME_PUSH_PROMISE: int = 0x5;
HTTP2_FRAME_PING: int = 0x6;
HTTP2_FRAME_GOAWAY: int = 0x7;
HTTP2_FRAME_WINDOW_UPDATE: int = 0x8;

serverRunningStatus: bool = True;

class SESSION_MANAGEMENT:
    def __init__(self) -> None:
        self.sessionsDict: Dict[str, Dict] = {};
        self.sessionCounter: int = 0;
        self.sessionLock = threading.Lock(); # non-recursive mutex for handling parallel connections to restrict resource sharing
        # python's GIL only locks bytecode execution
        # aka non re-entrant MUTEX 
        # session metadata doesnt get compromised / altered due to threading.Lock()

    def CREATE_NEW_SESSION(self, clientAddress: tuple):
        with self.sessionLock: # python's RAII
            self.sessionCounter += 1;
            sessionID = f"SESSION_{self.sessionCounter}_{int(time.time())}";
            self.sessionsDict[sessionID] = {
                'id': sessionID,
                'client_address': clientAddress,
                'created_at': datetime.now().isoformat(),
                'last_access': datetime.now().isoformat(),
                'request_count': 0,
                    'user_agent': None,
                'geo_info': None
            };

            return sessionID;
    
    def UPDATE_SESSION(self, sessionID: str, userAgent: str = None, geolocationInfo: Dict = None):
        with self.sessionLock:
            if sessionID in self.sessionsDict:
                self.sessionsDict[sessionID]['last_access'] = datetime.now().isoformat();
                self.sessionsDict[sessionID]['request_count'] += 1;

                if userAgent: self.sessionsDict[sessionID]['user_agent'] = userAgent;
                if geolocationInfo: self.sessionsDict[sessionID]['geo_info'] = geolocationInfo;

SESSION_MANAGER = SESSION_MANAGEMENT();

class transactionLogger:
    def __init__(self, logFile: str = "transaction.log"): # locally ive termed it this
        self.logFile = logFile;
        self.threadLock = threading.Lock();

    def LOG_ENTRY(self, data: Dict):
        with self.threadLock:
            logEntry = {'timestamp': datetime.now().isoformat(), **data}; 
            print(f"[$TxN] {logEntry.get('method')} {logEntry.get('path')} | Status: {logEntry.get('status')} | Time: {logEntry.get('duration'):.2f}ms");
            
            try:
                with open(self.logFile, 'a') as logFile:
                    logFile.write(json.dumps(logEntry) + '\n');
            except Exception as err:
                print(f"[!LOG_ERR]: {err}");

TRANSACTION_LOGGER = transactionLogger();

### --- UTILS --- ###

def DNS_LOOKUP(domainName: str) -> Union[str, None]:
    DNS_database = {
        "localhost": "127.0.0.1",
        "localhost6": "::1"
    }; # removed local dns for push commit, HTTPS should still be supported
    
    return DNS_database.get(domainName.lower());

browserDatabase = [
    ("firefox", "Firefox", "Firefox/"),
    ("edg",     "Edge",    "Edg/"),
    ("chrome",  "Chrome",  "Chrome/"),
    ("safari",  "Safari",  None)
];

OS_Database = [
    ("Windows", ["windows"]),
    ("macOS", ["mac os x", "macos"]),
    ("Linux", ["linux"]),
    ("Android", ["android"]),
    ("iOS", ["iphone", "ipad"])
];

def PARSE_USER_AGENT(userAgent: str) -> Dict[str, str]:
    info = {"browser": "unknown", "version": "unknown", "os": "unknown", "device": "unknown"};
    if (not userAgent): return (info); # fallback return
    
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

def getMIMEtype(filePath: str):
    mimeType, _ = mimetypes.guess_type(filePath);
    return mimeType or 'application/octet-stream';
    # type/subtype
    # type = general category (video/image/text)
    # subtype = plain (text) / html etc
    # 2 types - discrete or multipart
    # discrete = text/plain | text/html | etc
    # application/octet-stream = byte stream of 8-bits app specific  
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/MIME_types

def COMPRESS_RESPONSE(data: bytes, encodeType: str) -> tuple[bytes, str]:
    if 'gzip' in encodeType:
        try:
            compressed = gzip.compress(data);
            if len(compressed) < len(data):
                return compressed, 'gzip';
        except:
            pass;
    return data, 'identity';

def PARSE_HTTP_REQUEST(requestBytes: bytes):
    parts = requestBytes.split(b'\r\n\r\n', 1); # CRLF delimiter
    headerPart = parts[0].decode('utf-8', errors='ignore');
    bodyPart = parts[1] if len(parts) > 1 else b'';
    
    lines = headerPart.split('\r\n');
    if not lines or not lines[0]: return None;
    
    reqLine = lines[0].split(' ');
    method = reqLine[0] if len(reqLine) > 0 else 'GET';
    path = reqLine[1] if len(reqLine) > 1 else '/';
    version = reqLine[2] if len(reqLine) > 2 else 'HTTP/1.1';
    
    headers = {};

    # seq[start:stop:step]
    for line in lines[1:]:
        if ':' in line:
            key, value = line.split(':', 1);
            headers[key.strip().lower()] = value.strip(); # whitespace removal
            
    return {
        'method': method,
        'path': path, 
        'version': version, 
        'headers': headers, 
        'body': bodyPart
    };

def BUILD_HTTP_RESPONSE(statusCode, contentType, contentLength, encoding='identity', connection='keep-alive', isTLS=False):
    statusMessages = {
        200: 'OK', 
        404: 'Not Found', 
        405: 'Method Not Allowed'
    };

    statusMsg = statusMessages.get(statusCode, 'Unknown');
  
    headers = [
        f"HTTP/1.1 {statusCode} {statusMsg}",
        f"Content-Type: {contentType}",
        f"Content-Length: {contentLength}",
        f"Connection: {connection}",
        f"Server: IsoAris_xTCP",
        f"Date: {formatdate(usegmt=True)}"
    ];
     
    if isTLS: # HSTS header | note that it works without as well (http://127.0.0.1:8080)
        headers.append("Strict-Transport-Security: max-age=31536000; includeSubDomains");

    if (encoding != 'identity'):
        headers.append(f"Content-Encoding: {encoding}");

    return ('\r\n'.join(headers) + '\r\n\r\n').encode('utf-8');

HPACK_STATIC_TABLE: List[Tuple[str, str]] = [
    (':authority', ''), (':method', 'GET'), (':method', 'POST'), (':path', '/'), (':path', '/index.html'),
    (':scheme', 'http'), (':scheme', 'https'), (':status', '200'), (':status', '204'), (':status', '206'),
    (':status', '304'), (':status', '400'), (':status', '404'), (':status', '500'), ('accept-charset', ''),
    ('accept-encoding', 'gzip, deflate'), ('accept-language', ''), ('accept-ranges', ''), ('accept', ''),
    ('access-control-allow-origin', ''), ('age', ''), ('allow', ''), ('authorization', ''), ('cache-control', ''),
    ('content-disposition', ''), ('content-encoding', ''), ('content-language', ''), ('content-length', ''),
    ('content-location', ''), ('content-range', ''), ('content-type', ''), ('cookie', ''), ('date', ''), ('etag', ''),
    ('expect', ''), ('expires', ''), ('from', ''), ('host', ''), ('if-match', ''), ('if-modified-since', ''),
    ('if-none-match', ''), ('if-range', ''), ('if-unmodified-since', ''), ('last-modified', ''), ('link', ''),
    ('location', ''), ('max-forwards', ''), ('proxy-authenticate', ''), ('proxy-authorization', ''), ('range', ''),
    ('referer', ''), ('refresh', ''), ('retry-after', ''), ('server', ''), ('set-cookie', ''), ('strict-transport-security', ''),
    ('transfer-encoding', ''), ('user-agent', ''), ('vary', ''), ('via', ''), ('www-authenticate', '')
];

def HPACK_DECODE_INTEGER(data: bytes, pos: int, prefixBits: int) -> Tuple[int, int]:
    maxPrefix = (1 << prefixBits) - 1;
    value = data[pos] & maxPrefix;
    pos += 1;
    if value < maxPrefix:
        return value, pos;
    shift = 0;
    while pos < len(data):
        b = data[pos];
        pos += 1;
        value += (b & 0x7f) << shift;
        if (b & 0x80) == 0:
            break;
        shift += 7;
    return value, pos;

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
        return '', pos;
    huffman = (data[pos] & 0x80) != 0;
    length, pos = HPACK_DECODE_INTEGER(data, pos, 7);
    raw = data[pos:pos + length];
    pos += length;
    if huffman:
        return '', pos;
    return raw.decode('utf-8', errors='ignore'), pos;

def HPACK_ENCODE_STRING(value: str) -> bytes:
    raw = value.encode('utf-8');
    return HPACK_ENCODE_INTEGER(len(raw), 7, 0) + raw;

def HPACK_GET_STATIC_HEADER(index: int) -> Tuple[str, str]:
    if index <= 0 or index > len(HPACK_STATIC_TABLE):
        return '', '';
    return HPACK_STATIC_TABLE[index - 1];

def HPACK_FIND_STATIC_INDEX(name: str, value: str = None) -> int:
    for idx, item in enumerate(HPACK_STATIC_TABLE, start=1):
        if value is None:
            if item[0] == name:
                return idx;
        else:
            if item[0] == name and item[1] == value:
                return idx;
    return 0;

def HPACK_DECODE_HEADER_BLOCK(data: bytes) -> Dict[str, str]:
    headers: Dict[str, str] = {};
    pos = 0;
    while pos < len(data):
        b = data[pos];
        if b & 0x80:
            index, pos = HPACK_DECODE_INTEGER(data, pos, 7);
            name, value = HPACK_GET_STATIC_HEADER(index);
            if name:
                headers[name] = value;
            continue;
        if (b & 0x40) or (b & 0x10) or (b & 0x00) == 0:
            if b & 0x40:
                nameIndex, pos = HPACK_DECODE_INTEGER(data, pos, 6);
            else:
                nameIndex, pos = HPACK_DECODE_INTEGER(data, pos, 4);
            if nameIndex == 0:
                name, pos = HPACK_DECODE_STRING(data, pos);
            else:
                name, _ = HPACK_GET_STATIC_HEADER(nameIndex);
            value, pos = HPACK_DECODE_STRING(data, pos);
            if name:
                headers[name.lower()] = value;
            continue;
        break;
    return headers;

def HPACK_ENCODE_RESPONSE_HEADERS(headers: Dict[str, str]) -> bytes:
    output = bytearray();
    status = headers.get(':status', '200');
    statusIndex = HPACK_FIND_STATIC_INDEX(':status', status);
    if statusIndex > 0:
        output.extend(HPACK_ENCODE_INTEGER(statusIndex, 7, 0x80));
    for key, value in headers.items():
        if key == ':status':
            continue;
        nameIndex = HPACK_FIND_STATIC_INDEX(key.lower(), None);
        if nameIndex > 0:
            output.extend(HPACK_ENCODE_INTEGER(nameIndex, 4, 0x00));
        else:
            output.extend(HPACK_ENCODE_INTEGER(0, 4, 0x00));
            output.extend(HPACK_ENCODE_STRING(key.lower()));
        output.extend(HPACK_ENCODE_STRING(str(value)));
    return bytes(output);

def BUILD_HTTP2_FRAME(frameType: int, flags: int, streamId: int, payload: bytes = b'') -> bytes:
    length = len(payload);
    header = bytes([(length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff, frameType & 0xff, flags & 0xff]) + struct.pack('!I', streamId & 0x7fffffff);
    return header + payload;

def RECV_EXACT(connection: socket.socket, size: int) -> bytes:
    out = bytearray();
    while len(out) < size:
        chunk = connection.recv(size - len(out));
        if not chunk:
            return b'';
        out.extend(chunk);
    return bytes(out);

def READ_HTTP2_FRAME(connection: socket.socket) -> Optional[Tuple[int, int, int, bytes]]:
    header = RECV_EXACT(connection, HTTP2_FRAME_HEADER_LEN);
    if len(header) != HTTP2_FRAME_HEADER_LEN:
        return None;
    length = (header[0] << 16) | (header[1] << 8) | header[2];
    frameType = header[3];
    flags = header[4];
    streamId = struct.unpack('!I', header[5:9])[0] & 0x7fffffff;
    payload = RECV_EXACT(connection, length) if length > 0 else b'';
    if length > 0 and len(payload) != length:
        return None;
    return frameType, flags, streamId, payload;

def BUILD_HTTP2_SETTINGS(maxConcurrentStreams: int = 128, initialWindow: int = 65535) -> bytes:
    payload = struct.pack('!HI', HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, maxConcurrentStreams);
    payload += struct.pack('!HI', HTTP2_SETTINGS_INITIAL_WINDOW_SIZE, initialWindow);
    return BUILD_HTTP2_FRAME(HTTP2_FRAME_SETTINGS, 0x0, 0, payload);

def HANDLE_HTTP2_CONNECTION(connection: socket.socket, clientAddress, isTLS=False, isIPv6=False):
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
        TXN_start = time.time();
        frame = READ_HTTP2_FRAME(connection);
        if frame is None:
            break;
        frameType, flags, streamId, payload = frame;

        if frameType == HTTP2_FRAME_SETTINGS:
            if flags & HTTP2_FLAG_ACK:
                serverSettingsAcked = True;
            else:
                connection.sendall(BUILD_HTTP2_FRAME(HTTP2_FRAME_SETTINGS, HTTP2_FLAG_ACK, 0, b''));
                clientSettingsAcked = True;
            continue;

        if frameType == HTTP2_FRAME_PING:
            connection.sendall(BUILD_HTTP2_FRAME(HTTP2_FRAME_PING, HTTP2_FLAG_ACK, 0, payload[:8].ljust(8, b'\x00')));
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
            headerBlock = payload[pos:len(payload) - padLength if padLength > 0 else len(payload)];
            headers = HPACK_DECODE_HEADER_BLOCK(headerBlock);
            streams[streamId] = {
                'headers': headers,
                'body': b'',
                'closed': bool(flags & HTTP2_FLAG_END_STREAM)
            };
            if not (flags & HTTP2_FLAG_END_HEADERS):
                continue;
            if not streams[streamId]['closed']:
                continue;
        elif frameType == HTTP2_FRAME_DATA and streamId in streams:
            if flags & 0x8:
                padLength = payload[0] if len(payload) > 0 else 0;
                dataPayload = payload[1:len(payload) - padLength if padLength > 0 else len(payload)];
            else:
                dataPayload = payload;
            streams[streamId]['body'] += dataPayload;
            if not (flags & HTTP2_FLAG_END_STREAM):
                continue;
        else:
            if frameType == HTTP2_FRAME_GOAWAY:
                break;
            continue;

        if not clientSettingsAcked:
            continue;

        reqHeaders = streams[streamId]['headers'];
        method = reqHeaders.get(':method', 'GET');
        path = reqHeaders.get(':path', '/');
        userAgent = reqHeaders.get('user-agent', '');
        SESSION_MANAGER.UPDATE_SESSION(sessionID, userAgent);

        if '..' in path:
            status = 404;
            body = b"<h1>404 - Not Found</h1>";
        else:
            status = 200;
            body = f"""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <title>IsoAris Server</title>
                    <style>
                        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                        body {{
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace;
                            background: #404040;
                            color: #f5f5f5;
                            min-height: 100vh;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                        }}
                        .container {{
                            background: #080808;
                            backdrop-filter: blur(10px);
                            padding: 2rem;
                            border-radius: 0.5px;
                            box-shadow: 0 8px 24px rgba(0,0,0,0.5);
                            text-align: center;
                            max-width: 500px;
                        }}
                        h1 {{ font-size: 2rem; margin-bottom: 0.5rem; letter-spacing: 0.5px; }}
                        p {{ font-size: 1.1rem; opacity: 0.9; margin-bottom: 1rem; }}
                        .path {{
                            background: rgba(255,255,255,0.1);
                            padding: 0.75rem;
                            border-radius: 6px;
                            font-family: monospace;
                            font-size: 0.95rem;
                            word-break: break-all;
                            margin-bottom: 1rem;
                        }}
                        footer {{ font-size: 0.85rem; opacity: 0.7; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>IsoAris {protocol} Server</h1>
                        <p>Request received successfully.</p>
                        <div class="path">{path}</div>
                        <footer>Powered by IsoAris_xTCP</footer>
                    </div>
                </body>
                </html>
                """.encode("utf-8");

        compressedBody, encType = COMPRESS_RESPONSE(body, reqHeaders.get('accept-encoding', ''));
        responseHeaders = {
            ':status': str(status),
            'content-type': 'text/html',
            'content-length': str(len(compressedBody)),
            'server': 'IsoAris_xTCP',
            'date': formatdate(usegmt=True)
        };
        if encType != 'identity':
            responseHeaders['content-encoding'] = encType;
        if isTLS:
            responseHeaders['strict-transport-security'] = 'max-age=31536000; includeSubDomains';

        headerBlock = HPACK_ENCODE_RESPONSE_HEADERS(responseHeaders);
        connection.sendall(BUILD_HTTP2_FRAME(HTTP2_FRAME_HEADERS, HTTP2_FLAG_END_HEADERS, streamId, headerBlock));
        connection.sendall(BUILD_HTTP2_FRAME(HTTP2_FRAME_DATA, HTTP2_FLAG_END_STREAM, streamId, compressedBody));

        if path == '/' and streamId not in pushedForParent and streamId % 2 == 1:
            promisedStreamId = streamId + 2;
            while promisedStreamId in streams or promisedStreamId <= streamId:
                promisedStreamId += 2;
            pushedForParent.add(streamId);
            pushHeaders = bytearray();
            pushHeaders.extend(HPACK_ENCODE_INTEGER(2, 7, 0x80));
            pushHeaders.extend(HPACK_ENCODE_INTEGER(7, 7, 0x80));
            pushHeaders.extend(HPACK_ENCODE_INTEGER(31, 6, 0x40));
            pushHeaders.extend(HPACK_ENCODE_STRING('/style.css'));
            pushPayload = struct.pack('!I', promisedStreamId & 0x7fffffff) + bytes(pushHeaders);
            connection.sendall(BUILD_HTTP2_FRAME(HTTP2_FRAME_PUSH_PROMISE, HTTP2_FLAG_END_HEADERS, streamId, pushPayload));

            pushedBody = b"body{margin:0;padding:0}";
            pushedHeaders = {
                ':status': '200',
                'content-type': 'text/css',
                'content-length': str(len(pushedBody)),
                'server': 'IsoAris_xTCP',
                'date': formatdate(usegmt=True)
            };
            pushedHeaderBlock = HPACK_ENCODE_RESPONSE_HEADERS(pushedHeaders);
            connection.sendall(BUILD_HTTP2_FRAME(HTTP2_FRAME_HEADERS, HTTP2_FLAG_END_HEADERS, promisedStreamId, pushedHeaderBlock));
            connection.sendall(BUILD_HTTP2_FRAME(HTTP2_FRAME_DATA, HTTP2_FLAG_END_STREAM, promisedStreamId, pushedBody));

        TRANSACTION_LOGGER.LOG_ENTRY({
            'session': sessionID,
            'client': str(clientAddress),
            'method': method,
            'path': path,
            'status': status,
            'duration': (time.time() - TXN_start) * 1000,
            'protocol': f"{protocol}/2",
            'encoding': encType
        });

        streams.pop(streamId, None);

        if serverSettingsAcked is False:
            continue;

def HANDLE_CLIENT_CONNECTION(connection: socket.socket, clientAddress, isTLS=False, isIPv6=False, applicationProtocol='http/1.1'): 
    if applicationProtocol == 'h2':
        try:
            HANDLE_HTTP2_CONNECTION(connection, clientAddress, isTLS, isIPv6);
        except Exception as HTTP2_SERVER_ERROR:
            print(f"[!ERR]: {HTTP2_SERVER_ERROR}");
        finally:
            try:
                connection.shutdown(socket.SHUT_RDWR);
            except:
                pass;
            connection.close();
        return;

    try:
        connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1);
        # nagles algorithm improved efficiency but reducing the aggregated packet numeric sent over TCP/IP 
        # TCP packets have a 40-byte header - 20-TCP + 20 for IPv4 + 1 byte of actual data (total 41)
        # has to do with max segment size (MSS) and window size (SWP)
        # more: https://en.wikipedia.org/wiki/Nagle%27s_algorithm
        # migrated to TCP_NODELAY to disable Nagle's algorithm and improve latency reduction
    except:
        pass; 

    protocol = "HTTPS" if isTLS else "HTTP";
    IPvX = "IPv6" if isIPv6 else "IPv4";
    sessionID = SESSION_MANAGER.CREATE_NEW_SESSION(clientAddress);
    
    connection.settimeout(10.0); # slightly longer for persistent conns
    
    try:
        while serverRunningStatus:
            TXN_start = time.time();

            try:
                data = connection.recv(BUFFER_SIZE);
                if not data: break;
            except:
                break;

            req = PARSE_HTTP_REQUEST(data);
            if not req: break;

            userAgent = req['headers'].get('user-agent', '');
            browser = PARSE_USER_AGENT(userAgent);
            SESSION_MANAGER.UPDATE_SESSION(sessionID, userAgent);

            connHeader = req['headers'].get('connection', '').lower();
            keepAlive = (connHeader != 'close') if req['version'] == 'HTTP/1.1' else (connHeader == 'keep-alive');
 
            if '..' in req['path']:
                status, body = 404, b"<h1>404 - Not Found</h1>";
            else:
                status = 200;
                # body = f"<html><body><h1>IsoAris {protocol} Server</h1><p>Path: {req['path']}</p></body></html>".encode();
                body = f"""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <title>IsoAris Server</title>
                    <style>
                        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                        body {{
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace;
                            background: #404040;
                            color: #f5f5f5;
                            min-height: 100vh;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                        }}
                        .container {{
                            background: #080808;
                            backdrop-filter: blur(10px);
                            padding: 2rem;
                            border-radius: 0.5px;
                            box-shadow: 0 8px 24px rgba(0,0,0,0.5);
                            text-align: center;
                            max-width: 500px;
                        }}
                        h1 {{ font-size: 2rem; margin-bottom: 0.5rem; letter-spacing: 0.5px; }}
                        p {{ font-size: 1.1rem; opacity: 0.9; margin-bottom: 1rem; }}
                        .path {{
                            background: rgba(255,255,255,0.1);
                            padding: 0.75rem;
                            border-radius: 6px;
                            font-family: monospace;
                            font-size: 0.95rem;
                            word-break: break-all;
                            margin-bottom: 1rem;
                        }}
                        footer {{ font-size: 0.85rem; opacity: 0.7; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>IsoAris {protocol} Server</h1>
                        <p>Request received successfully.</p>
                        <div class="path">{req['path']}</div>
                        <footer>Powered by IsoAris_xTCP</footer>
                    </div>
                </body>
                </html>
                """.encode("utf-8"); # i asked AI to do the UI 

            # compress the content w/ gzip in main memory prior 
            compressedBody, encType = COMPRESS_RESPONSE(body, req['headers'].get('accept-encoding', ''));
            
            # parse isTLS to BUILD_HTTP_RESPONSE to trigger HSTS
            # BUILD_HTTP_RESPONSE(statusCode, contentType, contentLength, encoding='identity', connection='keep-alive', isTLS=False)
            headers = BUILD_HTTP_RESPONSE(
                status, "text/html", len(compressedBody), encType, # inline CSS support is intrinsic with text/html
                'keep-alive' if keepAlive else 'close', isTLS
            );
            
            connection.sendall(headers + compressedBody);

            TRANSACTION_LOGGER.LOG_ENTRY({
                'session': sessionID, 
                'client': str(clientAddress),
                'method': req['method'], 
                'path': req['path'], 
                'status': status,
                'duration': (time.time() - TXN_start) * 1000,
                'protocol': protocol, 
                'encoding': encType
            });

            if (not keepAlive):
                break;

    except Exception as SOME_SERVER_ERROR:
        print(f"[!ERR]: {SOME_SERVER_ERROR}");
    
    finally:
        try:
            connection.shutdown(socket.SHUT_RDWR);
        except:
            pass;
        connection.close();

def CREATE_TLS_CONTEXT() -> Optional[ssl.SSLContext]:
    if not os.path.exists(CERTIFICATION_FILE):
        return None;

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);
        # ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=CERTIFICATION_FILE, keyfile=KEY_FILE); # WILL NOT WORK IF THERE IS NONE SPECIFIED 
        # https://docs.python.org/3/library/ssl.html
        # context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # context.load_cert_chain('/path/to/certchain.pem', '/path/to/private.key')
        
        # i dont know much what these do on lower level, the docs wrote it this way and so did i 
        context.check_hostname = False;
        context.minimum_version = ssl.TLSVersion.TLSv1_2;
        context.set_alpn_protocols(['h2', 'http/1.1']); # specify which protocols the socket should advertise during the SSL/TLS handshake
        # ssl.TLSVersion.__contains__(sex)

        # https://developer.mozilla.org/en-US/docs/Glossary/ALPN
        return context;

    except Exception as TLS_CONTEXT_CREATION_ERROR:
        print(f"[!TLS_FAIL]: {TLS_CONTEXT_CREATION_ERROR}");
        return None;

def START_LOOPBACK_SERVER(IPaddr, port, isTLS=False):
    family = socket.AF_INET6 if ':' in IPaddr else socket.AF_INET;
    server = socket.socket(family, socket.SOCK_STREAM);
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1);
     
    try:
        server.bind((IPaddr, port));

    except OSError as PORT_BIND_ERROR:
        print(f"[!BIND_ERR]: Could not bind to {IPaddr}:{port} - {PORT_BIND_ERROR}");
        return;

    server.listen(128);
    server.setblocking(False); # non blocking, program will execute regardless of operation execution

    mostEfficientSelector = selectors.DefaultSelector(); # selectors for I/O multiplexing. non-blocking
    mostEfficientSelector.register(server, selectors.EVENT_READ);

    TLS_CTX = CREATE_TLS_CONTEXT() if isTLS else None;
    print(f"[*] Serving {('HTTPS' if isTLS else 'HTTP')} on {IPaddr}:{port}");

    while serverRunningStatus:
        events = mostEfficientSelector.select(timeout = 1);
        for key, bitmask in events:
            try:
                conn, addr = server.accept();
                if isTLS and TLS_CTX:
                    try:
                        conn = TLS_CTX.wrap_socket(conn, server_side=True);
                    except Exception as tls_err:
                        print(f"[!TLS_HANDSHAKE_ERR]: {tls_err}");
                        conn.close();
                        continue;
                selectedProtocol = conn.selected_alpn_protocol() if (isTLS and TLS_CTX) else 'http/1.1';
                if selectedProtocol is None:
                    selectedProtocol = 'http/1.1';
                
                threading.Thread(
                    target=HANDLE_CLIENT_CONNECTION,
                    args=(conn, addr, isTLS, family == socket.AF_INET6, selectedProtocol),
                    daemon=True
                ).start();
            except BlockingIOError:
                continue;
            except Exception as e:
                if serverRunningStatus:
                    print(f"[!ACCEPT_ERR]: {e}");

    server.close();

def interruptSignalHandler(sig, frame):
    global serverRunningStatus;
    print("\n[!] Shutdown signal received...");
    serverRunningStatus = False;

if __name__ == "__main__":
    configs = [ # remove multi-port conflict by a clear dual-stack listed tuple structure
        ('127.0.0.1', 8080, False), # HTTP IPv4
        ('::1',       8080, False), # HTTP IPv6
        ('0.0.0.0',   8443, True),  # HTTPS All IPv4 (includes 127.0.0.1)
        ('::1',       8443, True)   # HTTPS IPv6
    ];

    for IPaddr, portUsed, TLS_booleanFlag in configs:
        singularThread = threading.Thread(
            target = START_LOOPBACK_SERVER,
            args = (IPaddr, portUsed, TLS_booleanFlag), 
            daemon = True
        );
        singularThread.start();

    signal.signal(signal.SIGINT, interruptSignalHandler);
    
    while serverRunningStatus:
        time.sleep(1);
