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

HOST_SERVER_IPv4: str = "127.0.0.1";
HOST_SERVER_IPv6: str = "::1";
PORT: int = 8080;
TLS_PORT: int = 8443;
BUFFER_SIZE: int = 4096;
CERTIFICATION_FILE: str = "server.crt";
KEY_FILE: str = "server.key";
# HTTP/2 contains binary frames
# HTTP/1.1 contains textual content
# a frame is a small structured binary message to comm over connection (basically network packets)

HTTP2_PREFACE: bytes = (
    b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"  # 24-byte/octet sequence | client conn preface
);
HTTP2_FRAME_HEADER_LEN: int = 9;  # every HTTP/2 begins with a 9 byte header
HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS: int = (
    0x3  # maximum parallel user connection streams
);
HTTP2_SETTINGS_INITIAL_WINDOW_SIZE: int = (
    0x4  # how much data can be set before WINDOW_UPDATE
);
HTTP2_FLAG_END_STREAM: int = 0x1;  # final data frame
HTTP2_FLAG_END_HEADERS: int = (
    0x4  # this frame completes the header sect, headers may span multiple frames
);
HTTP2_FLAG_ACK: int = 0x1;  # acknowledgement
HTTP2_FRAME_DATA: int = 0x0;  # carries response after headers
HTTP2_FRAME_HEADERS: int = 0x1;  # carries HTTP headers compressed via HPACK
HTTP2_FRAME_SETTINGS: int = 0x4;  # idk
HTTP2_FRAME_PUSH_PROMISE: int = 0x5;  # for server push
HTTP2_FRAME_PING: int = 0x6;  # 8-byte payload latency check to measure RTT
HTTP2_FRAME_GOAWAY: int = (
    0x7  # [error_code | last processed stream ID] - used during connection shutdown
);
HTTP2_FRAME_WINDOW_UPDATE: int = 0x8;  # thing that sends bytes or something

# https://www.rfc-editor.org/rfc/rfc7540#section-6.9
# WINDOW_UPDATE is related to "window size" which informs the client how many bytes its "prepared to recieve"
# (SO) - Flow control, on the other hand, is about how many data bytes each endpoint can send on the connection.
# (SO) - The only frame that is subject to flow control is the DATA frame.
# (SO) - Flow control is a necessary mechanism that multiplexed protocols should implement.

serverRunningStatus: bool = True;
