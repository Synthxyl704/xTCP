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
HTTP2_PREFACE: bytes = (
    b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
);
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
