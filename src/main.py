import asyncio
import signal
import time
from constants import (
    HOST_SERVER_IPv4,
    HOST_SERVER_IPv6,
    PORT,
    TLS_PORT,
    BUFFER_SIZE,
    serverRunningStatus,
)
from management import SESSION_MANAGER, TRANSACTION_LOGGER
from protocols import (
    PARSE_USER_AGENT,
    PARSE_HTTP_REQUEST,
    BUILD_HTTP_RESPONSE,
    COMPRESS_RESPONSE,
    HANDLE_HTTP2_CONNECTION,
    CREATE_TLS_CONTEXT,
)

# import threading;
# import selectors;
# import socket;
#
# def HANDLE_CLIENT_CONNECTION(
#     connection: socket.socket,
#     clientAddress,
#     isTLS=False,
#     isIPv6=False,
#     applicationProtocol="http/1.1",
# ):
#     if applicationProtocol == "h2":
#         try:
#             HANDLE_HTTP2_CONNECTION(connection, clientAddress, isTLS, isIPv6);
#         except Exception as HTTP2_SERVER_ERROR:
#             print(f"[!ERR]: {HTTP2_SERVER_ERROR}");
#         finally:
#             try:
#                 connection.shutdown(socket.SHUT_RDWR);
#             except:
#                 pass;
#             connection.close();
#         return;
#
#     try:
#         connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1);
#     except:
#         pass;
#
#     protocol = "HTTPS" if isTLS else "HTTP";
#     IPvX = "IPv6" if isIPv6 else "IPv4";
#     sessionID = SESSION_MANAGER.CREATE_NEW_SESSION(clientAddress);
#     connection.settimeout(10.0);
#
#     try:
#         while serverRunningStatus:
#             TXN_start = time.time();
#             try:
#                 data = connection.recv(BUFFER_SIZE);
#                 if not data:
#                     break;
#             except:
#                 break;
#
#             req = PARSE_HTTP_REQUEST(data);
#             if not req:
#                 break;
#
#             userAgent = req["headers"].get("user-agent", "");
#             browser = PARSE_USER_AGENT(userAgent);
#             SESSION_MANAGER.UPDATE_SESSION(sessionID, userAgent);
#             connHeader = req["headers"].get("connection", "").lower();
#             keepAlive = (
#                 (connHeader != "close")
#                 if req["version"] == "HTTP/1.1"
#                 else (connHeader == "keep-alive")
#             );
#             if ".." in req["path"]:
#                 status, body = 404, b"<h1>404 - Not Found</h1>";
#             else:
#                 status = 200;
#                 body = f"""
#                 <!DOCTYPE html>
#                 <html lang="en">
#                 <head>
#                     <meta charset="UTF-8">
#                     <title>IsoAris Server</title>
#                     <style>
#                         * {{ margin: 0; padding: 0; box-sizing: border-box; }}
#                         body {{
#                             font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace;
#                             background: #404040;
#                             color: #f5f5f5;
#                             min-height: 100vh;
#                             display: flex;
#                             align-items: center;
#                             justify-content: center;
#                         }}
#                         .container {{
#                             background: #080808;
#                             backdrop-filter: blur(10px);
#                             padding: 2rem;
#                             border-radius: 0.5px;
#                             box-shadow: 0 8px 24px rgba(0,0,0,0.5);
#                             text-align: center;
#                             max-width: 500px;
#                         }}
#                         h1 {{ font-size: 2rem; margin-bottom: 0.5rem; letter-spacing: 0.5px; }}
#                         p {{ font-size: 1.1rem; opacity: 0.9; margin-bottom: 1rem; }}
#                         .path {{
#                             background: rgba(255,255,255,0.1);
#                             padding: 0.75rem;
#                             border-radius: 6px;
#                             font-family: monospace;
#                             font-size: 0.95rem;
#                             word-break: break-all;
#                             margin-bottom: 1rem;
#                         }}
#                         footer {{ font-size: 0.85rem; opacity: 0.7; }}
#                     </style>
#                 </head>
#                 <body>
#                     <div class="container">
#                         <h1>IsoAris {protocol} Server</h1>
#                         <p>Request received successfully.</p>
#                         <div class="path">{req["path"]}</div>
#                         <footer>Powered by IsoAris_xTCP</footer>
#                     </div>
#                 </body>
#                 </html>
#                 """.encode("utf-8");
#
#             compressedBody, encType = COMPRESS_RESPONSE(
#                 body, req["headers"].get("accept-encoding", "")
#             );
#             headers = BUILD_HTTP_RESPONSE(
#                 status,
#                 "text/html",
#                 len(compressedBody),
#                 encType,
#                 "keep-alive" if keepAlive else "close",
#                 isTLS,
#             );
#             connection.sendall(headers + compressedBody);
#             TRANSACTION_LOGGER.LOG_ENTRY(
#                 {
#                     "session": sessionID,
#                     "client": str(clientAddress),
#                     "method": req["method"],
#                     "path": req["path"],
#                     "status": status,
#                     "duration": (time.time() - TXN_start) * 1000,
#                     "protocol": protocol,
#                     "encoding": encType,
#                 }
#             );
#             if not keepAlive:
#                 break;
#     except Exception as SOME_SERVER_ERROR:
#         print(f"[!ERR]: {SOME_SERVER_ERROR}");
#     finally:
#         try:
#             connection.shutdown(socket.SHUT_RDWR);
#         except:
#             pass;
#         connection.close();
#
#
# def START_LOOPBACK_SERVER(IPaddr, port, isTLS=False):
#     family = socket.AF_INET6 if ":" in IPaddr else socket.AF_INET;
#     server = socket.socket(family, socket.SOCK_STREAM);
#     server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1);
#     try:
#         server.bind((IPaddr, port));
#     except OSError as PORT_BIND_ERROR:
#         print(f"[!BIND_ERR]: Could not bind to {IPaddr}:{port} - {PORT_BIND_ERROR}");
#         return;
#
#     server.listen(128);
#     server.setblocking(False);
#
#     mostEfficientSelector = selectors.DefaultSelector();
#     mostEfficientSelector.register(server, selectors.EVENT_READ);
#     TLS_CTX = CREATE_TLS_CONTEXT() if isTLS else None;
#     print(f"[*] Serving {('HTTPS' if isTLS else 'HTTP')} on {IPaddr}:{port}");
#     while serverRunningStatus:
#         events = mostEfficientSelector.select(timeout=1);
#         for key, bitmask in events:
#             try:
#                 connection, addr = server.accept();
#                 if isTLS and TLS_CTX:
#                     try:
#                         connection = TLS_CTX.wrap_socket(connection, server_side=True);
#                     except Exception as tls_err:
#                         print(f"[!TLS_HANDSHAKE_ERR]: {tls_err}");
#                         connection.close();
#                         continue;
#
#                 selectedProtocol = (
#                     connection.selected_alpn_protocol() if (isTLS and TLS_CTX) else "http/1.1"
#                 );
#
#                 if selectedProtocol is None:
#                     selectedProtocol = "http/1.1";
#
#                 threading.Thread(
#                     target=HANDLE_CLIENT_CONNECTION,
#                     args=(
#                         connection,
#                         addr,
#                         isTLS,
#                         family == socket.AF_INET6,
#                         selectedProtocol,
#                     ),
#                     daemon=True,
#                 ).start();
#             except BlockingIOError:
#                 continue;
#             except Exception as SERVER_EXIT_ERROR:
#                 if serverRunningStatus:
#                     print(f"[!ACCEPT_ERR]: {SERVER_EXIT_ERROR}");
#
#     server.close();
#
#
# def interruptSignalHandler(sig, frame):
#     global serverRunningStatus;
#     print("\n[!] Shutdown signal received...");
#     serverRunningStatus = False;
#
#
# if __name__ == "__main__":
#     configs = [
#         ("127.0.0.1", 8080, False),
#         ("::1", 8080, False),
#         ("0.0.0.0", 8443, True),
#         ("::1", 8443, True),
#     ];
#     for IPaddr, portUsed, TLS_booleanFlag in configs:
#         singularThread = threading.Thread(
#             target=START_LOOPBACK_SERVER,
#             args=(IPaddr, portUsed, TLS_booleanFlag),
#             daemon=True,
#         );
#         singularThread.start();
#
#     signal.signal(signal.SIGINT, interruptSignalHandler);
#     while serverRunningStatus:
#         time.sleep(1);

async def HANDLE_ASYNC_CLIENT_CONNECTION(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    isTLSenabled: bool = False,
    isIPv6enabled: bool = False,
    applcationLayerProtocol: str = "http/1.1" # default settings
):
    clientAddress = writer.get_extra_info("peername");

    # if protocol is HTTP/2 we switch it to that instead of defaulting to HTTP/1.1
    if applcationLayerProtocol == "h2":
        try:
            HANDLE_HTTP2_CONNECTION(writer.get_extra_info("socket"), clientAddress, isTLSenabled, isIPv6enabled);
        except Exception as HTTP2_SERVER_ERROR:
            print(f"[!ERR]: {HTTP2_SERVER_ERROR}");

        finally:
            try:
                writer.close();
                await writer.wait_closed();
            except Exception as ASYNCIO_WRITER_ERROR:
                print(f"[!ERR]: {ASYNCIO_WRITER_ERROR}");

