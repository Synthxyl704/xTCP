import socket
import threading
import os
import gzip 
import mimetypes
import signal
import ssl
import time
import json

from datetime import datetime
from typing import Optional, Dict, Union 
from email.utils import formatdate

# neovim auto-imports stuff as i use it - i love it

# def DNS_LOOKUP(domainName: str):
#     # domain name sys is a "set of servers"
#     # might have subnet IP addresses which i wont use rn
#     # DNS is an obstraction over IPv4/IPv6
#     DNS_database = { # hash dns db
#         "localhost": "127.0.0.1"
#     };
#
#     print(f"[+DNS_LOOKUP]: {domainName}");
#
#     IP_address = DNS_database.get(domainName);
#
#     if (IP_address != None):
#         print(f"[+DNS]: {domainName} at {IP_address}");
#         return (IP_address);
#     else:
#         print(f"[-DNS]: {domainName} not found");
#         return (None);

# RFC-7235 + RFC-9110
# https://datatracker.ietf.org/doc/html/rfc7235
# https://datatracker.ietf.org/doc/html/rfc9110

HOST_SERVER_IPv4: str = '127.0.0.1'; # IPv4 loopback address
HOST_SERVER_IPv6: str = '::1';
PORT: int = 8080;
TLS_PORT: int = 8443;
# DOC_ROOT: str = './catgirl';
BUFFER_SIZE: int = 4096;

CERTIFICATION_FILE: str = 'server.crt';
KEY_FILE: str = 'server.key';

serverRunningStatus: bool = True; # why is the T captial ew

### --- CLASSES DEFINITION START --- ###

class SESSION_MANAGEMENT:
    def __init__(self) -> None:
        self.sessionsDict: Dict[str, Dict] = {}; # the sessionID and its metadata in a dictionary
        self.sessionCounter: int = 0;
        self.sessionLock = threading.Lock();

    def CREATE_NEW_SESSION(self, clientAddress: tuple):
        with self.sessionLock:
            self.sessionCounter += 1;
            sessionID = f"[+INFO]: SESSION_[{self.sessionCounter}]_C-T::{int(time.time())}" # horrible UX, cool UI

            self.sessionsDict[sessionID] = {
                'id': sessionID,
                'client_address': clientAddress,
                'created_at': datetime.now().isoformat(),
                'last_access': datetime.now().isoformat(),
                'request_count': 0,
                'user_agent': None,
                'geo_info': None
            };

            print(f"[+SESSION]: Meta - {sessionID} | Client - {clientAddress}"); # meta means metadata here includes sessionID 
            return (sessionID);
    
    def UPDATE_SESSION(self, sessionID: str, userAgent: str = None, geolocationInfo: Dict = None):
        with self.sessionLock:
            if sessionID in self.sessionsDict:
                self.sessionsDict[sessionID]['last_access'] = datetime.now().isoformat();
                self.sessionsDict[sessionID]['request_count'] += 1;

                if userAgent: 
                    self.sessionsDict[sessionID]['user_agent'] = userAgent;
                if geolocationInfo:
                    self.sessionsDict[sessionID]['geo_info'] = geolocationInfo;

    def GET_SESSION_INFO(self, sessionID: str) -> Optional[Dict]:
        with self.sessionLock:
            return (self.sessionsDict.get(sessionID));

SESSION_MANAGER = SESSION_MANAGEMENT();

class transactionLogger:
    def __init__(self, logFile: str = "transactionLogger"):
        self.logFile = logFile;
        self.threadLock = threading.Lock();

    def LOG_ENTRY(self, data: Dict):
        with self.threadLock: # atomic logging + auto release
            timestamp = datetime.now().isoformat();
            logEntry = {'timestamp': timestamp, **data};

            print(f"[#TxN]: ");
            print(f"Session: {logEntry.get('session')} | Client: {logEntry.get('client')}");
            print(f"{logEntry.get('method')} {logEntry.get('path')} → {logEntry.get('status')}");
            print(f"Browser: {logEntry.get('browser')} | OS: {logEntry.get('os')} | Device: {logEntry.get('device')}");
            print(f"Location: {logEntry.get('location')} | Size: {logEntry.get('size')}b | Time: {logEntry.get('duration'):.2f}ms");
            print(f"");

            try:
                with open(self.logFile, 'a') as fileOpened:
                    fileOpened.write(json.dumps(logEntry) + '\n');
            
            except Exception as errorDuringJsonLogDump:
                print(f"[#TxN | +INFO]: There was some ERROR in JSON log dumping - {errorDuringJsonLogDump}");

TRANSACTION_LOGGER = transactionLogger();

### --- END OF CLASSES --- ###

### --- DNS --- ###

def DNS_LOOKUP(domainName: str) -> Union[str, None]:
    DNS_database = {
        "localhost": "127.0.0.1",
        # "catgirl.local": "127.0.0.1",
        # "myserver.local": "127.0.0.1",
        "localhost6": "::1",
        # "catgirl6.local": "::1"
    };

    print(f"[%DNS_LOOKUP]: now resolving domain name: {domainName}");

    IP_address = DNS_database.get(domainName.lower());

    if (IP_address != None):
        print(f"[%DNS_LOOKUP]: DNS lookup successful, now connected to IP - {IP_address}");
        return (IP_address);
    else:
        print(f"[%DNS_LOOKUP]: DNS lookup failure, couldnt find {domainName} - sure nothing is wrong?");
        return (None);

### --- USER AGENT STUFF --- ### 

browserDatabase = [ # make global for one time allocation
    ("firefox", "Firefox", "Firefox/"),
    ("edg",     "Edge",    "Edg/"),
    ("chrome",  "Chrome",  "Chrome/"),
    ("safari",  "Safari",  None) # none is a bad idea but will fix l8r
]; # thx

OS_Database = [
    ("Windows 10/11", ["windows nt 10"]),
    ("Windows 8.1", ["windows nt 6.3"]),
    ("Windows", ["windows"]),
    ("macOS", ["mac os x", "macos"]),
    ("Ubuntu", ["ubuntu"], "Probably a desktop?"),
    ("Linux", ["linux", "Probably a desktop?"]),
    ("Android", ["android"], "Mobile"),
    ("iOS", ["iphone"], "Mobile"),
    ("iOS", ["ipad"], "Tablet")
];

def PARSE_USER_AGENT(userAgent: str) -> Dict[str, str]: # Dict[KT, VT] 
    defaultBrowserInfo = {
        "browser": "unknown",
        "version": "unknown",
        "os": "unknown",
        "device": "unknown"
    };

    if userAgent == None or not userAgent: # are these the same thing?
        return (defaultBrowserInfo);

    # now this is not-so-good implementation 
    # use: pip install ua-parser user-agents
    # and then get manually, ive implemented my own for didactic purposes here

    # userAgentInfoLowered = userAgent.lower();
    # UA = ["mozilla/5.0 (linux; EndeavourOS) Firefox/146.0.1 ..."];

    for browserName, browserVersionToken, identifyingSubstring in browserDatabase:
        if identifyingSubstring and identifyingSubstring in userAgent:
            defaultBrowserInfo["browser"] = browserName;

            try:
                # userAgent = "Mozilla/5.0 ... Firefox/120.0 ..."
                versionString = userAgent.split(identifyingSubstring, 1)[1].split()[0];
                defaultBrowserInfo["version"] = versionString;
            except IndexError:
                defaultBrowserInfo["version"] = "unknown";

            break; 

            # if browserVersionToken in userAgent:
            #   defaultBrowserInfo["version"] = browserVersionToken;
            #   browserVersionToken["version"] = (
            #       userAgent.split(browserVersionToken, 1)[1].split()[0] # AI wrote the logic for this, i dont know how this works
            # );

            # break; 
            # this can be done with regexes as well!?

    for rule in OS_Database:
        OS_name, markers, *userDevice = rule;
        
        if any(x in userAgent for x in markers):
            defaultBrowserInfo["os"] = OS_name;

            if userDevice or userDevice != None:
                defaultBrowserInfo["device"] = userDevice[0];

            break;

    return (defaultBrowserInfo);

### --- CONFIG SETUP HERE --- ###

# Standard host addresses
# etc/hosts
# 127.0.0.1  localhost
# 127.0.0.1  isodns.local | -< custom DNS here?
# ::1        localhost ip6-localhost ip6-loopback
# [X]        [Y]
# # This host address
# 127.0.1.1  isoxiavant-vostro3520

def PRINT_HOST_FILE_SETUP() -> Optional[None]:  
    # 127.0.0.1    localhost + isodns.local
    # ::1          localhost6

    print("\n" + "-"*80);
    print("[~DNS_SETUP]:");
    print("="*80);
    print("\n --- IPv4 mappings ---");
    # print("127.0.0.1  |  catgirl.local");
    print("127.0.0.1  |  isodns.local");
    print("\n --- IPv6 mappings ---");
    # print("::1        |  catgirl_IPv6.local");
    print("[::1]      |  localhost6");
    print("-"*80);
    print("Linux/Mac: /etc/hosts");
    print("Windows: C:\\Windows\\System32\\drivers\\etc\\hosts");
    print("-"*80 + "\n");

def interruptSignalHandler(sigRecieved, frame) -> str:
    # SIGINT / SIGSTP
    global serverRunningStatus; 

    if serverRunningStatus:
        print(f"\n\n[-/+INFO]: SERVER SHUTDOWN SIGNAL RECIEVED!\n\n");
        serverRunningStatus = False;

    TARGET_PORTS = [PORT, TLS_PORT];

    for port in TARGET_PORTS:
        try:
            dummyEndpoint_v4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
            dummyEndpoint_v4.settimeout(0.5); # Don't hang if the server is already dead
            dummyEndpoint_v4.connect(('127.0.0.1', port)); 
            dummyEndpoint_v4.close();
        except Exception as IPv4_EXCEPTION:
            print(f"[+INFO] - IPv4 dummy exception - {IPv4_EXCEPTION}");

        try:
            dummyEndpoint_v6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM);
            dummyEndpoint_v6.settimeout(0.5);
            dummyEndpoint_v6.connect(('::1', port)); 
            dummyEndpoint_v6.close();
        except Exception as IPv6_EXCEPTION:
            print(f"[+INFO] - IPv6 dummy exception - {IPv6_EXCEPTION}");

def getMIMEtype(filePath: str):
    mimeType, encodeType = mimetypes.guess_type(filePath);
    # multipurpose internet media extension
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/MIME_types
    # aka "media types"
    # so basically the web operates using MIME types and not "extensions"
    # file extensions are for filesys naming, MIME is for HTTP(s)'s 'Content-Type' header 
 
    if (mimeType == None):
        return ('application/octet-stream');
        # application/octet-stream is defined as "arbitrary binary data" in RFC 2046

    return (mimeType);

def COMPRESS_RESPONSE(data: bytes, encodeType: str) -> tuple[bytes, str]:
    if ('gzip' in encodeType):
        try:
            compressedData: bytes = gzip.compress(data);

            if (len(compressedData) < len(data)):   # sometimes the compressed data has a longer length than the actual data
                return (compressedData, 'gzip');    # in that case, we mitigate the "pigeonhole principle"
        except Exception as GZIP_COMPRESSION_ERR:   # pass;
            print(f"[!ERROR]: GZip compression failure - {GZIP_COMPRESSION_ERR}");

    return (data, 'identity'); 

def GET_CLIENT_GEOLOC(clientIP: str):
    if clientIP in ['127.0.0.1', '::1', 'localhost', 'local']: # i sure hope the dot acts as a delimter for differentiation
        return {
            'ip': clientIP,
            'location': 'localhost',
            'country': '[x]',
            'city': '[x]',
            'isp': 'loopback address'
        };

    return {
        'ip': clientIP,
        'location': 'Unknown',
        'country': 'Unknown',
        'city': 'Unknown',
        'isp': 'Unknown'
    };

def PARSE_HTTP_REQUEST(requestBytes: bytes): # TCP returns raw bytes

    # GET /sex.html HTTP/1.1\r\n | <method> <path> <ver>
    # Host: dns.com or 127.0.0.1:8080 \r\n           
    # User-Agent: <x>\r\n        | 
    # Accept: */*\r\n            | 
    # # \r\n = CRLF              | 
    # <body>

    HTTP_headerBodySplit = requestBytes.split(b'\r\n\r\n', 1); # maxsplit = 1 

    HTTP_headerPart = HTTP_headerBodySplit[0]; # <method> <path> <ver> <host> ...
    HTTP_bodyPart = HTTP_headerBodySplit[1] if len(HTTP_headerBodySplit) > 1 else b''; # <body>

    HTTP_headerStr = HTTP_headerPart.decode('utf-8', errors='ignore');
    # headerLines = HTTP_headerPart.split(b'\r\n');
    headerLines = HTTP_headerStr.split('\r\n');
    
    requestLineParts = headerLines[0].split(' ');
    requestMethod = requestLineParts[0] if len(requestLineParts) > 0 else '';
    filePath = requestLineParts[1] if len(requestLineParts) > 1 else '/';
    HTTP_version = requestLineParts[2] if len(requestLineParts) > 2 else 'HTTP/1.1'

    headersList = {};
    for aSingularLine in headerLines[1:]:
        if ':' in aSingularLine:
            key, value = aSingularLine.split(':', 1);
            headersList[key.strip().lower()] = value.strip();

    return {
        'method': requestMethod,
        'path': filePath,
        'version': HTTP_version,
        'headersList': headersList,
        'body': HTTP_bodyPart
    };

def READ_FULL_HTTP_REQUEST(socketObj: socket.socket, headersList, initialBody: bytes) -> bytes:
    HTTP_contentLength: int = int(headersList.get('content-length', 0));
    HTTP_currentLength: int = len(initialBody);

    # if HTTP_currentLength > HTTP_contentLength:
    if HTTP_currentLength >= HTTP_contentLength:
        return (initialBody[:HTTP_contentLength])

    HTTP_bodyParts: list = [initialBody];

    while HTTP_currentLength < HTTP_contentLength:
        HTTP_remainingContent = (HTTP_contentLength - HTTP_currentLength);
        # HTTP_chunk = socketObj.recv(min(BUFFER_SIZE, HTTP_remainingContent));
        HTTP_chunk: bytes = socketObj.recv(min(BUFFER_SIZE, HTTP_remainingContent)); 
        # read upto BUFFER_SIZE from endpoint
        if not HTTP_chunk:
            break;
        HTTP_bodyParts.append(HTTP_chunk);
        HTTP_currentLength += len(HTTP_chunk);

    return (b''.join(HTTP_bodyParts));

def BUILD_HTTP_RESPONSE(statusCode, contentType, contentLength, encoding = 'id', connection = 'keep-alive'):
    statusMessages = {
        200: 'OK',
        404: 'Not found',
        405: 'Method not allowed'
    };

    statusText = statusMessages.get(statusCode, '{{something went ambiguous happened here}}'); 

    # from email.utils import formatdate; # inline import or something?
    headersList = [
        f"HTTP/1.1 {statusCode} {statusText}",
        f"Content-Type: {contentType}",
        f"Content-Length: {contentLength}",
        f"Connection: {connection}",
        f"Server: IsoAris_xTCP",
        f"Date: {formatdate(usegmt=True)}"
    ];

    # if (encoding != 'identity'):
    #    headersList.append(f"Content-Encoding: {encoding}");

    headersList.append('\r\n');

    return ('\r\n'.join(headersList).encode('utf-8'));

def HANDLE_CLIENT_CONNECTION(connection: socket.socket, clientAddress, isTLS = False, isIPv6 = False):
    print(f"[+INFO]: Client connection instantiated: {clientAddress}");
    # connection.settimeout(5);

    startTime = time.time(); # idk what type annotation returns here
    protocolUtilized: str = "HTTPS" if isTLS else "HTTP";
    IPvX: str = "IPv6" if isIPv6 else "IPv4";

    print(f"\n[+CONNECT]: {protocolUtilized}/{IPvX} from {clientAddress}");

    sessionID = SESSION_MANAGER.CREATE_NEW_SESSION(clientAddress);
    IPADDR = clientAddress[0];
    geoLocation = GET_CLIENT_GEOLOC(IPADDR);

    connection.settimeout(5);

    try:
        while serverRunningStatus:
            TXN_start = startTime;

            try:
                clientData = connection.recv(BUFFER_SIZE)
                if not clientData:
                    break;

            except (socket.timeout, ConnectionResetError):
                break;

            clientRequest = PARSE_HTTP_REQUEST(clientData);

            print(f"[+INFO]: {clientAddress} - {clientRequest['method']} {clientRequest['path']}");

            userAgent = clientRequest['headersList'].get('user-agent', '');
            browserUsed = PARSE_USER_AGENT(userAgent);
            SESSION_MANAGER.UPDATE_SESSION(sessionID, userAgent, geoLocation);

            if 'content-length' in clientRequest['headersList']:
                clientRequest['body'] = READ_FULL_HTTP_REQUEST(
                    connection,
                    clientRequest['headersList'],
                    clientRequest['body']
                );

                print(f"[++DEBUG_LOG]: Body received ({len(clientRequest['body'])} bytes)");

            # connectionRequest = clientRequest['headersList'].get('connection', '').lower();
            # connectionLifeStatus = not (
            #    clientRequest['version'] == 'HTTP/1.0' and connectionRequest != 'keep-alive'
            # );

            connectionRequest = clientRequest['headersList'].get('connection', '').lower();

            if clientRequest['version'] == 'HTTP/1.1':
                connectionLifeStatus = (connectionRequest != 'close');
            else:
                connectionLifeStatus = (connectionRequest == 'keep-alive');

            # filePath = os.path.join(DOC_ROOT, clientRequest['path'].lstrip('/'));
            statusCode = 200;
            contentType = "text/html";

            if '..' in clientRequest['path']: # this is bad
                statusCode = 404;
                responseBody = b"<h1>404 - Not Found</h1>";

            # elif os.path.exists(filePath) and os.path.isfile(filePath):
            #    contentType = getMIMEtype(filePath);
            #    with open(filePath, 'rb') as f:
            #        responseBody = f.read();

            else:
                responseBody = f"""
                <html>
                <body>
                    <h1>This shit should be visible in loopback serv </h1> <br>
                    <hr>
                    <h1>hi this is isoaris from loopback IPv4, try l8r with IPv6/iNET6</h1>
                    <p>Nothing requested: {clientRequest['path']}</p>
                </body>
                </html>
                """.encode();

            acceptEncoding = clientRequest['headersList'].get('accept-encoding', '');
            compressedBody, encodingType = COMPRESS_RESPONSE(responseBody, acceptEncoding);

            responseHeaders = BUILD_HTTP_RESPONSE(
                statusCode,
                contentType,
                len(compressedBody),
                encoding=encodingType,
                connection='keep-alive' if connectionLifeStatus else 'close'
            );

            connection.sendall(responseHeaders + compressedBody);

            TXN_end = time.time();
            duration = ((TXN_end - TXN_start) * 1000);
            
            TRANSACTION_LOGGER.LOG_ENTRY({
                'session': sessionID, 'client': str(clientAddress), 'ip': clientAddress,
                'method': clientRequest['method'], 'path': clientRequest['path'],
                'status': statusCode, 'size': len(compressedBody),
                'browser': browserUsed['browser'], 'version': browserUsed['version'],
                'os': browserUsed['os'], 'device': browserUsed['device'],
                'location': geoLocation['location'], 'country': geoLocation['country'],
                'duration': duration, 'protocol': protocolUtilized, 'ip_version': IPvX,
                'tls': isTLS, 'encoding': encodingType
            });

            if not connectionLifeStatus:
                break;

    except Exception as connexHandlingERR:
        print(f"[!ERROR]: there was some problem handling the connection - {connexHandlingERR}");

    finally:
        connection.close();
        totalTime = (time.time() - TXN_start) * 1000; # TXN_start is possibly unbound?
        print(f"[+INFO]: connection closed {clientAddress} | Total time elapsed: {totalTime}");

def CREATE_TLS_CONTEXT() -> Optional[ssl.SSLContext]:
    if not os.path.exists(CERTIFICATION_FILE) or not os.path.exists(KEY_FILE):
        print("[!TLS_LOG]: there was some problem with TLS certification");
        print("[!TLS_LOG]: Generate: openssl req -x509 -newkey rsa:4096 -nodes -out {CERT_FILE} -keyout {KEY_FILE} -days 365");
        return None;

    try:
        TLS_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);
        TLS_context.load_cert_chain(certfile=CERTIFICATION_FILE, keyfile=KEY_FILE);
        TLS_context.minimum_version = ssl.TLSVersion.TLSv1_2;
        TLS_context.set_ciphers('ECDHE+AESGCM:!aNULL:!MD5');
        TLS_context.set_alpn_protocols(['h2', 'http/1.1']);
     
        print(f"[+TLS]: Context created with ALPN (h2, http/1.1)");
        print(f"[+TLS]: Context created successfully.");
        return (TLS_context);
    
    except Exception as e:
        print(f"[!ERROR]: TLS setup failed - {e}");
        return (None);

def START_LOOPBACK_SERVER(isUsingIPv6 = False, isUsingTLS = False): 
    if isUsingIPv6:
        serverEndpoint = socket.socket(socket.AF_INET6, socket.SOCK_STREAM);
        clientAddress = (HOST_SERVER_IPv6, TLS_PORT if isUsingTLS else PORT);
        IPvX_VERSION = "IPv6";
    # https://docs.python.org/3/library/socket.html

    else:
        serverEndpoint: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
        clientAddress = (HOST_SERVER_IPv4, TLS_PORT if isUsingTLS else PORT);
        IPvX_VERSION = "IPv4";

    serverEndpoint.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1);
    # iso.bind((HOST_SERVER_IPv4, PORT));

    SSL_CONTEXT = None;
    if isUsingTLS:
        SSL_CONTEXT = CREATE_TLS_CONTEXT();
        
        if not SSL_CONTEXT:
            print(f"[!ERROR]: could not instantiate TLS | ceritification error?");
            return;

    try:
        serverEndpoint.bind((clientAddress));
        serverEndpoint.listen(5);

        protocolUsed = "https" if isUsingTLS else "http";
        port = TLS_PORT if isUsingTLS else PORT;

        print(f"[~SERVER]: listening on {protocolUsed}://{clientAddress[0]}:{clientAddress[1]}");
        print(f"[~SERVER]: input SIGINT for proper closure");

        signal.signal(signal.SIGINT, interruptSignalHandler);

        while serverRunningStatus:
                try:
                    # x = serverEndpoint.accept();
                    clientConnection, clientAddress = serverEndpoint.accept(); # server ssocket will accept incoming connxs 

                    if isUsingTLS:
                        if SSL_CONTEXT:
                            try:
                                clientConnection = SSL_CONTEXT.wrap_socket(clientConnection, server_side=True);
                                print(f"[~SERVER]: TLS handshake successful with {clientAddress}");
                            except Exception as ssl_error:
                                print(f"[!TLS]: TLS handshake failed - {ssl_error}");
                                clientConnection.close();
                                continue;
                        else:
                            print("[!TLS]: No context found, closing connection.");
                            clientConnection.close();
                            continue;

                    # every demultiplex thread will execute HANDLE_CLIENT_CONNECTION(clientConnection, clientAddress); 
                    clientThread = threading.Thread(
                        target = HANDLE_CLIENT_CONNECTION, 
                        args = (clientConnection, clientAddress), # args mandatorily requisite a tuple
                        daemon = True
                    );

                    # https://docs.python.org/3/library/threading.html
                    # network requests made
                    # only one thread executes py bytecode at a time
                    # no new process recreation
                    # clientThread = threading.Thread()
                    
                    clientThread.start();

                except OSError: # should return network/socket errs
                    break; 
    except Exception as serverSideERR:
        print(f"fatal server-side error - {serverSideERR}");
    finally:
        serverEndpoint.close();
        print(f"[~SERVER]: server stopped");

if __name__ == "__main__":
    START_LOOPBACK_SERVER(isUsingTLS=True);
    t2 = threading.Thread(
        target=START_LOOPBACK_SERVER, 
        args=(False, True), 
        daemon=True
    )

    t2.start()
