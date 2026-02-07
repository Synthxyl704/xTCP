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

from datetime import datetime
from typing import Optional, Dict, Union 
from email.utils import formatdate

HOST_SERVER_IPv4: str = '127.0.0.1';
HOST_SERVER_IPv6: str = '::1';
PORT: int = 8080;
TLS_PORT: int = 8443;
BUFFER_SIZE: int = 4096;
CERTIFICATION_FILE: str = 'server.crt';
KEY_FILE: str = 'server.key';

serverRunningStatus: bool = True;

### --- CLASSES --- ###

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

def HANDLE_CLIENT_CONNECTION(connection: socket.socket, clientAddress, isTLS=False, isIPv6=False): 
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
        context.set_alpn_protocols(['http/1.1']); # specify which protocols the socket should advertise during the SSL/TLS handshake
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
 
    mostEfficientSelector = selectors.DefaultSelector(); # selectors for I/O multiplexing
    mostEfficientSelector.register(server, selectors.EVENT_READ);

    TLS_CTX = CREATE_TLS_CONTEXT() if isTLS else None;
    print(f"[*] Serving {('HTTPS' if isTLS else 'HTTP')} on {IPaddr}:{port}");

    while serverRunningStatus:
        events = mostEfficientSelector.select(timeout=1);
        for key, mask in events:
            try:
                conn, addr = server.accept();
                if isTLS and TLS_CTX:
                    try:
                        conn = TLS_CTX.wrap_socket(conn, server_side=True);
                    except Exception as tls_err:
                        print(f"[!TLS_HANDSHAKE_ERR]: {tls_err}");
                        conn.close();
                        continue;
                
                threading.Thread(
                    target=HANDLE_CLIENT_CONNECTION,
                    args=(conn, addr, isTLS, family == socket.AF_INET6),
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
