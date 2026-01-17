# from ast import arguments
# import time
import socket
import threading
import os
import gzip 
import mimetypes
import signal
# import sys
# from types import BuiltinMethodType
from typing import final 

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

HOST_SERVER_IPADDR: str = '127.0.0.1'; # IPv4 loopback address
# HOST_SERVER_IPADDR: str = '0.0.0.0';
PORT: int = 8080;
DOC_ROOT: str = './public';
BUFFER_SIZE: int = 4096;

serverRunningStatus: bool= True; # why is the T captial ew

def interruptSignalHandler(sigRecieved, frame) -> str:
    # SIGINT / SIGSTP
    global serverRunningStatus; 
    print(f"\n\n[-/+INFO]: SERVER SHUTDOWN SIGNAL RECIEVED!\n\n");
    serverRunningStatus = False;

    try:
        # AF_INET = strictly IPv4 | SOCK_STREAM = socket_type = TCP
        dummyEndpoint = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
        dummyEndpoint.connect((HOST_SERVER_IPADDR, PORT)); 
        dummyEndpoint.close();

        # so we first switch it off, then make another dummy socket and then close it 
        # and then as result, the serverRunningStatus will be false the next time it iterates
        # so it will k*ll itself there
    except:
        pass;

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

            if (len(compressedData) < len(data)):
                return (compressedData, 'gzip'); # pigeonhole principle
        except Exception as GZIP_COMPRESSION_ERR: # pass;
            print(f"[!ERROR]: GZip compression failure - {GZIP_COMPRESSION_ERR}");

    return (data, '<encode_identity>');

def PARSE_HTTP_REQUEST(requestBytes: bytes):

    # GET /sex.html HTTP/1.1\r\n | <method> <path> <ver>
    # Host: hi.com\r\n           |
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

    headersDict = {};
    for aSingularLine in headerLines[1:]:
        if ':' in aSingularLine:
            key, value = aSingularLine.split(':', 1);
            headersDict[key.strip().lower()] = value.strip();

    return {
        'method': requestMethod,
        'path': filePath,
        'version': HTTP_version,
        'headersDict': headersDict,
        'body': HTTP_bodyPart
    };

def READ_FULL_HTTP_REQUEST(socketObj: socket.socket, headersDict, initialBody: bytes) -> bytes:
    HTTP_contentLength: int = int(headersDict.get('content-length', 0));
    HTTP_currentLength: int = len(initialBody);

    if HTTP_currentLength > HTTP_contentLength:
        return (initialBody);

    HTTP_bodyParts = [initialBody];

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

    headersDict = [
        f"HTTP/1.1 {statusCode} {statusText}",
        f"Content-Type: {contentType}",
        f"Content-Length: {contentLength}",
        f"Encoding: {encoding}",
        f"Connection: {connection}"
    ];

    # if (encoding != 'identity'):
    #    headersDict.append(f"Content-Encoding: {encoding}");

    headersDict.append('\r\n');

    return ('\r\n'.join(headersDict).encode('utf-8'));

def HANDLE_CLIENT_CONNECTION(connection: socket.socket, clientAddress):
    print(f"[+INFO]: New connection from {clientAddress}")

    connection.settimeout(5)

    try:
        while serverRunningStatus:
            try:
                clientData = connection.recv(BUFFER_SIZE)
                if not clientData:
                    break;

            except (socket.timeout, ConnectionResetError):
                break;

            clientRequest = PARSE_HTTP_REQUEST(clientData);

            print(f"[+INFO]: {clientAddress} - {clientRequest['method']} {clientRequest['path']}");

            if 'content-length' in clientRequest['headersDict']:
                clientRequest['body'] = READ_FULL_HTTP_REQUEST(
                    connection,
                    clientRequest['headersDict'],
                    clientRequest['body']
                );

                print(f"[++DEBUG_LOG]: Body received ({len(clientRequest['body'])} bytes)");

            connectionRequest = clientRequest['headersDict'].get('connection', '').lower();
            connectionLifeStatus = not (
                clientRequest['version'] == 'HTTP/1.0' and connectionRequest != 'keep-alive'
            );

            filePath = os.path.join(DOC_ROOT, clientRequest['path'].lstrip('/'));
            statusCode = 200;
            contentType = "text/html";

            if '..' in clientRequest['path']:
                statusCode = 404;
                responseBody = b"<h1>404 - Not Found</h1>";

            elif os.path.exists(filePath) and os.path.isfile(filePath):
                contentType = getMIMEtype(filePath);
                with open(filePath, 'rb') as f:
                    responseBody = f.read();

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

            acceptEncoding = clientRequest['headersDict'].get('accept-encoding', '');
            compressedBody, encodingType = COMPRESS_RESPONSE(responseBody, acceptEncoding);

            responseHeaders = BUILD_HTTP_RESPONSE(
                statusCode,
                contentType,
                len(compressedBody),
                encoding=encodingType,
                connection='keep-alive' if connectionLifeStatus else 'close'
            );

            connection.sendall(responseHeaders + compressedBody);

            if not connectionLifeStatus:
                break;

    except Exception as connexHandlingERR:
        print(f"[!ERROR]: there was some problem handling the connection - {connexHandlingERR}");

    finally:
        connection.close()
        print(f"[+INFO]: connection closed {clientAddress}");

def START_LOOPBACK_SERVER():
    # https://docs.python.org/3/library/socket.html
    serverEndpoint: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM);
    serverEndpoint.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1);

    try:
        serverEndpoint.bind((HOST_SERVER_IPADDR, PORT));
        serverEndpoint.listen(5);

        print(f"[~SERVER]: listening on http://{HOST_SERVER_IPADDR}:{PORT}");
        print(f"[~SERVER]: input SIGINT for proper closure");

        signal.signal(signal.SIGINT, interruptSignalHandler);

        while serverRunningStatus:
                try:
                    clientConnection, clientAddress = serverEndpoint.accept(); # server ssocket will accept incoming connxs 

                    clientThread = threading.Thread(
                        target = HANDLE_CLIENT_CONNECTION, 
                        args =(clientConnection, clientAddress), 
                        daemon = True
                    );
                    
                    clientThread.start();

                except OSError:
                    break;
    except Exception as serverSideERR:
        print(f"fatal server-side error - {serverSideERR}");
    finally:
        serverEndpoint.close();
        print(f"[~SERVER]: server stopped");

if __name__ == "__main__":
    START_LOOPBACK_SERVER();
