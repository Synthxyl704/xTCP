import asyncio
import signal

import time

from constants import (
    BUFFER_SIZE,
)

from typing import Optional

from management import SESSION_MANAGER, TRANSACTION_LOGGER
from protocols import (
    PARSE_USER_AGENT,
    PARSE_HTTP_REQUEST,
    BUILD_HTTP_RESPONSE,
    COMPRESS_RESPONSE,
    HANDLE_HTTP2_CONNECTION,
    CREATE_TLS_CONTEXT,
    CUSTOM_TCP_STACK,
    TCP_SEGMENT_HEADER,
    TCP_STATE,
    TCP_FLAGS,
    IP_PACKET_HEADER,
    TCP_CONNECTION_CONTROL_BLOCK,
    CALCULATE_TCP_CHECKSUM,
    CALCULATE_CHECKSUM,
)


async def HANDLE_ASYNC_CLIENT_CONNECTION(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    isTLSenabled: bool = False,
    isIPv6enabled: bool = False,
    applicationLayerProtocol: str = "http/1.1",
):
    clientAddress = writer.get_extra_info("peername")
    if applicationLayerProtocol == "h2":
        try:
            HANDLE_HTTP2_CONNECTION(
                writer.get_extra_info("socket"),
                clientAddress,
                isTLSenabled,
                isIPv6enabled,
            )
        except Exception as HTTP2_SERVER_ERROR:
            print(f"[!HTTP/2_ERR]: {HTTP2_SERVER_ERROR}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception ASYNCIO_WRITER_ERROR:
                print(f"[!ERR]: {ASYNCIO_WRITER_ERROR}")

        return

    transportProtocol: str = "HTTPS" if (isTLSenabled) else "HTTP"
    IPvX: str = "IPv6" if (isIPv6enabled) else "IPv4"
    uniqueSessionID = SESSION_MANAGER.CREATE_NEW_SESSION(clientAddress)
    try:
        while True:
            transactionStartTS: float = time.time()
            try:
                incomingDataBuffer = await asyncio.wait_for(
                    reader.read(BUFFER_SIZE), timeout=10.0
                )
                if not incomingDataBuffer:
                    break
            except asyncio.TimeoutError as ASYNCIO_TIMEOUT_ERROR:
                print(f"[!ERR]: {ASYNCIO_TIMEOUT_ERROR}")
            except Exception as ASYNCTIO_INCOMING_BUFFER_ERROR:
                print(f"[!L291-ERR]: {ASYNCTIO_INCOMING_BUFFER_ERROR}")

            parsedHTTPrequest = PARSE_HTTP_REQUEST(incomingDataBuffer)
            if not parsedHTTPrequest:
                print(
                    f"[!ERR]: something went wrong in parsing the HTTP request function"
                )

                break

            userAgentStr: str = parsedHTTPrequest["headers"].get("user-agent", "")
            browserInfo = PARSE_USER_AGENT(userAgentStr)
            SESSION_MANAGER.UPDATE_SESSION(uniqueSessionID, userAgentStr)
            connectionHeaderValue = (
                parsedHTTPrequest["headers"].get("connection", "").lower()
            )
            isKeepAliveConnection = (
                (connectionHeaderValue != "close")
                if (parsedHTTPrequest["version"] == "HTTP/1.1")
                else (connectionHeaderValue == "keep-alive")
            )
            if ".." in parsedHTTPrequest["path"]:
                HTTP_STATUS_CODE: int = 404
                responseBodyContent = (
                    b"<h1>ERR 404 - Invalid page access was restricted</h1>"
                )
            else:
                HTTP_STATUS_CODE: int = 200
                responseBodyContent = f"""
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
                        <h1>IsoAris {transportProtocol} Server</h1>
                        <p>Request received successfully.</p>
                        <div class="path">{parsedHTTPrequest["path"]}</div>
                        <footer>Powered by IsoAris_xTCP</footer>
                    </div>
                </body>
                </html>
                """.encode("utf-8")

            compressedResponseBody, contentEncodingType = COMPRESS_RESPONSE(
                responseBodyContent,
                parsedHTTPrequest["headers"].get("accept-encoding", ""),
            )
            httpResponseHeaders: bytes = BUILD_HTTP_RESPONSE(
                HTTP_STATUS_CODE,
                "text/html",
                len(compressedResponseBody),
                contentEncodingType,
                "keep-alive" if (isKeepAliveConnection) else "close",
                isTLSenabled,
            )
            writer.write(httpResponseHeaders + compressedResponseBody)
            await writer.drain()
            TRANSACTION_LOGGER.LOG_ENTRY(
                {
                    "session": uniqueSessionID,
                    "client": str(clientAddress),
                    "method": parsedHTTPrequest["method"],
                    "path": parsedHTTPrequest["path"],
                    "status": HTTP_STATUS_CODE,
                    "duration": ((time.time() - transactionStartTS) * 1000),
                    "protocol": transportProtocol,
                    "encoding": contentEncodingType,
                }
            )
            if not isKeepAliveConnection:
                print(f"[LOG]: closed connection")
                break
    except Exception as SOME_SERVER_ERROR:
        print(f"[!ERR]: {SOME_SERVER_ERROR}")
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception ASYNCIO_WRITER_ERROR:
            print(f"[!ERR]: {ASYNCIO_WRITER_ERROR}")


async def START_ASYNCHRONOUS_SERVER(
    serverHostAddr: str, serverPortNumeric: int, isTLSenabled: bool = False
):
    isIPv6 = ":" in (serverHostAddr)
    if isTLSenabled:
        TLScontext = CREATE_TLS_CONTEXT()
    else:
        TLScontext = None

    protocolName = "HTTPS" if (isTLSenabled) else "HTTP"
    print(f"[x]: Serving {protocolName} on {serverHostAddr}:{serverPortNumeric}")

    async def clientConnectionHandler(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        ssl_object = writer.get_extra_info("ssl_object")
        if ssl_object and isTLSenabled:
            negotiated_protocol = ssl_object.selected_alpn_protocol()
            application_protocol = (
                negotiated_protocol if negotiated_protocol else "http/1.1"
            )
        else:
            application_protocol = "http/1.1"

        await HANDLE_ASYNC_CLIENT_CONNECTION(
            reader, writer, isTLSenabled, isIPv6, application_protocol
        )

    asyncServerInstance = await asyncio.start_server(
        clientConnectionHandler,
        host=serverHostAddr,
        port=serverPortNumeric,
        ssl=TLScontext,
    )
    async with asyncServerInstance:
        await asyncServerInstance.serve_forever()


async def RUN_SERVERS_CONCURRENTLY():
    serverConfigurationList = [
        ("127.0.0.1", 8080, False),
        ("::1", 8080, False),
        ("0.0.0.0", 8443, True),
        ("::1", 8443, True),
    ]
    serverTaskList = []
    for hostAddr, portNumeric, TLSenabledFlag in serverConfigurationList:
        serverCoroutine = START_ASYNCHRONOUS_SERVER(
            hostAddr, portNumeric, TLSenabledFlag
        )
        serverTaskList.append(asyncio.create_task(serverCoroutine))

    await asyncio.gather(*serverTaskList, return_exceptions=True)


def SETUP_ASYNC_SIGNAL_HANDLERS(eventLoop: asyncio.AbstractEventLoop):
    def handleAsyncInterruptSignal():
        print("\n[!SERVER]: server shutdown signal recv'd")
        for currentTask in asyncio.all_tasks(eventLoop):
            currentTask.cancel()

    for signalNumber in (signal.SIGINT, signal.SIGTERM):
        eventLoop.add_signal_handler(signalNumber, handleAsyncInterruptSignal)


async def MAIN_ASYNC_ENTRY_POINT():
    eventLoop = asyncio.get_running_loop()
    SETUP_ASYNC_SIGNAL_HANDLERS(eventLoop)
    try:
        await RUN_SERVERS_CONCURRENTLY()
    except asyncio.CancelledError:
        print("[!SERVER]: shutting down the server")


def INITIALIZE_CUSTOM_TCP_STACK() -> CUSTOM_TCP_STACK:
    customTCPstackInstance: CUSTOM_TCP_STACK = CUSTOM_TCP_STACK()
    print("[+] TCP Stack initialized: custom implementation ready")
    return customTCPstackInstance


def DEMONSTRATE_TCP_THREE_WAY_HANDSHAKE():
    print("\n[TCP] Three-way handshake demo (RFC 793)")
    customTCPstack: CUSTOM_TCP_STACK = INITIALIZE_CUSTOM_TCP_STACK()
    clientAddress: Tuple[str, int] = ("127.0.0.1", 54321)
    serverAddress: Tuple[str, int] = ("127.0.0.1", 8080)
    customTCPstack.listenSockets[serverAddress] = Optional[None]
    print(f"[Client] -> SYN -> Server")
    clientISN: int = random.randint(0, 0xFFFFFFFF)
    print(f"[Client] ISN = {clientISN} (0x{clientISN:08x})")
    clientSYNheader: TCP_SEGMENT_HEADER = TCP_SEGMENT_HEADER(
        sourcePort=clientAddress[1],
        destinationPort=serverAddress[1],
        sequenceNumber=clientISN,
        acknowledgmentNumber=0,
        dataOffset=5,
        flags=TCP_FLAGS.SYN,
        windowSize=65535,
        checksum=0,
        urgentPointer=0,
    )
    serializedSYN: bytes = clientSYNheader.serialize()
    clientSYNheader.checksum = CALCULATE_TCP_CHECKSUM(
        clientAddress[0], serverAddress[0], serializedSYN
    )
    clientIPheader: IP_PACKET_HEADER = IP_PACKET_HEADER(
        sourceIP=clientAddress[0],
        destinationIP=serverAddress[0],
        totalLength=40,
    )
    response: Optional[Tuple[TCP_SEGMENT_HEADER, bytes]] = (
        customTCPstack.processIncomingSegment(clientIPheader, clientSYNheader, b"")
    )
    if response:
        synAckHeader: TCP_SEGMENT_HEADER = response[0]
        print(f"[Server] <- SYN-ACK <- Client")
        print(
            f"[Server] ISN = {synAckHeader.sequenceNumber}, ACK = {synAckHeader.acknowledgmentNumber}"
        )
    connectionTCB: Optional[TCP_CONNECTION_CONTROL_BLOCK] = (
        customTCPstack.getConnection(serverAddress, clientAddress)
    )
    if connectionTCB:
        clientACKheader: TCP_SEGMENT_HEADER = TCP_SEGMENT_HEADER(
            sourcePort=clientAddress[1],
            destinationPort=serverAddress[1],
            sequenceNumber=clientISN + 1,
            acknowledgmentNumber=synAckHeader.sequenceNumber + 1,
            dataOffset=5,
            flags=TCP_FLAGS.ACK,
            windowSize=65535,
            checksum=0,
            urgentPointer=0,
        )
        serializedACK: bytes = clientACKheader.serialize()
        clientACKheader.checksum = CALCULATE_TCP_CHECKSUM(
            clientAddress[0], serverAddress[0], serializedACK
        )
        serverIPheader: IP_PACKET_HEADER = IP_PACKET_HEADER(
            sourceIP=serverAddress[0],
            destinationIP=clientAddress[0],
            totalLength=40,
        )
        customTCPstack.processIncomingSegment(serverIPheader, clientACKheader, b"")
        print(f"[Client] -> ACK -> Server")
        print(f"[Done] Connection ESTABLISHED, state = {connectionTCB.currentState.value}")
    
    print('');
    return customTCPstack;


def DEMONSTRATE_TCP_DATA_TRANSFER():
    print("\n[TCP] Data transfer demo")
    customTCPstack: CUSTOM_TCP_STACK = DEMONSTRATE_TCP_THREE_WAY_HANDSHAKE()
    clientAddress: Tuple[str, int] = ("127.0.0.1", 54321)
    serverAddress: Tuple[str, int] = ("127.0.0.1", 8080)
    connectionTCB: Optional[TCP_CONNECTION_CONTROL_BLOCK] = (
        customTCPstack.getConnection(serverAddress, clientAddress)
    )
    if not connectionTCB or connectionTCB.currentState != TCP_STATE.ESTABLISHED:
        print("[Err] No connection")
        return
    samplePayloadData: bytes = b"Hello TCP!"
    print(
        f'[Data] Sending: "{samplePayloadData.decode()}" ({len(samplePayloadData)} bytes)'
    )
    segments: List[Tuple[TCP_SEGMENT_HEADER, bytes]] = customTCPstack.sendData(
        connectionTCB, samplePayloadData
    )
    print(f"[TCP] Segmented into {len(segments)} part(s)")
    for i, (hdr, payload) in enumerate(segments):
        print(f"  [{i + 1}] SEQ={hdr.sequenceNumber}, len={len(payload)}")
    print(
        f"[State] SND.UNA={connectionTCB.sendUnacknowledged}, SND.NXT={connectionTCB.sendSequenceNumber}"
    )
    print()
    return customTCPstack


def DEMONSTRATE_TCP_CONNECTION_TEARDOWN():
    print("\n[TCP] Connection teardown demo")
    customTCPstack: CUSTOM_TCP_STACK = DEMONSTRATE_TCP_THREE_WAY_HANDSHAKE()
    clientAddress: Tuple[str, int] = ("127.0.0.1", 54321)
    serverAddress: Tuple[str, int] = ("127.0.0.1", 8080)
    connectionTCB: Optional[TCP_CONNECTION_CONTROL_BLOCK] = (
        customTCPstack.getConnection(serverAddress, clientAddress)
    )
    if not connectionTCB:
        print("[Err] No connection")
        return
    print(f"[Server] -> FIN -> Client")
    finSegment: Tuple[TCP_SEGMENT_HEADER, bytes] = customTCPstack.initiateClose(
        connectionTCB
    )
    print(f"[State] {connectionTCB.currentState.value}")
    print("[Client] -> ACK -> Server")
    clientACKheader: TCP_SEGMENT_HEADER = TCP_SEGMENT_HEADER(
        sourcePort=clientAddress[1],
        destinationPort=serverAddress[1],
        sequenceNumber=connectionTCB.receiveSequenceNumber,
        acknowledgmentNumber=finSegment[0].sequenceNumber + 1,
        dataOffset=5,
        flags=TCP_FLAGS.ACK,
        windowSize=65535,
        checksum=0,
        urgentPointer=0,
    )
    serializedClientACK: bytes = clientACKheader.serialize()
    clientACKheader.checksum = CALCULATE_TCP_CHECKSUM(
        clientAddress[0], serverAddress[0], serializedClientACK
    )
    serverIPheader: IP_PACKET_HEADER = IP_PACKET_HEADER(
        sourceIP=serverAddress[0],
        destinationIP=clientAddress[0],
        totalLength=40,
    )
    customTCPstack.processIncomingSegment(serverIPheader, clientACKheader, b"")
    print(f"[Client] -> FIN -> Server")
    clientFINheader: TCP_SEGMENT_HEADER = TCP_SEGMENT_HEADER(
        sourcePort=clientAddress[1],
        destinationPort=serverAddress[1],
        sequenceNumber=clientACKheader.sequenceNumber,
        acknowledgmentNumber=finSegment[0].sequenceNumber + 1,
        dataOffset=5,
        flags=TCP_FLAGS.FIN | TCP_FLAGS.ACK,
        windowSize=65535,
        checksum=0,
        urgentPointer=0,
    )
    serializedClientFIN: bytes = clientFINheader.serialize()
    clientFINheader.checksum = CALCULATE_TCP_CHECKSUM(
        clientAddress[0], serverAddress[0], serializedClientFIN
    )
    customTCPstack.processIncomingSegment(serverIPheader, clientFINheader, b"")
    print(f"[Server] -> ACK -> Client")
    print(f"[Done] TIME_WAIT, then closed")
    print()


if __name__ == "__main__":
    import random
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--tcp-demo":
        print("\nTCP Stack Demo (RFC 793)")
        print("1: Handshake  2: Data  3: Teardown  4: All")
        try:
            choice = input("> ").strip()
        except EOFError:
            choice = "4"
        if choice in ("1", "4"):
            DEMONSTRATE_TCP_THREE_WAY_HANDSHAKE()
        if choice in ("2", "4"):
            DEMONSTRATE_TCP_DATA_TRANSFER()
        if choice in ("3", "4"):
            DEMONSTRATE_TCP_CONNECTION_TEARDOWN()
        print("Done.")
    else:
        try:
            asyncio.run(MAIN_ASYNC_ENTRY_POINT())
        except KeyboardInterrupt:
            print("\n[Stop] Server stopped")
