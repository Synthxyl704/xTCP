import threading
import time
import json

from datetime import datetime
from typing import Dict


class SESSION_MANAGEMENT:
    def __init__(self) -> None:
        self.sessionsDict: Dict[str, Dict] = {};
        self.sessionCounter: int = 0;
        self.sessionLock = threading.Lock();  # non-recursive mutex for handling parallel connections to restrict resource sharing

    # python's GIL only locks bytecode execution
    # aka non re-entrant MUTEX
    # session metadata doesnt get compromised / altered due to threading.Lock()

    def CREATE_NEW_SESSION(self, clientAddress: tuple):
        with self.sessionLock:  # python's RAII
            self.sessionCounter += 1;
            sessionID = f"SESSION_{self.sessionCounter}_{int(time.time())}";
            self.sessionsDict[sessionID] = {
                "id": sessionID,
                "client_address": clientAddress,
                "created_at": datetime.now().isoformat(),
                "last_access": datetime.now().isoformat(),
                "request_count": 0,
                "user_agent": None,
                "geo_info": None,
            };
            return sessionID;

    def UPDATE_SESSION(
        self, sessionID: str, userAgent: str = None, geolocationInfo: Dict = None
    ):
        with self.sessionLock:
            if sessionID in self.sessionsDict:
                self.sessionsDict[sessionID]["last_access"] = datetime.now().isoformat();
                self.sessionsDict[sessionID]["request_count"] += 1;
                if userAgent:
                    self.sessionsDict[sessionID]["user_agent"] = userAgent;
                if geolocationInfo:
                    self.sessionsDict[sessionID]["geo_info"] = geolocationInfo;


SESSION_MANAGER = SESSION_MANAGEMENT();


class transactionLogger:
    def __init__(self, logFile: str = "transaction.log"):  # locally ive termed it this
        self.logFile = logFile;
        self.threadLock = threading.Lock();

    def LOG_ENTRY(self, data: Dict):
        with self.threadLock:
            logEntry = {"timestamp": datetime.now().isoformat(), **data};
            print(
                f"[$TxN] {logEntry.get('method')} {logEntry.get('path')} | Status: {logEntry.get('status')} | Time: {logEntry.get('duration'):.2f}ms"
            );
            try:
                with open(self.logFile, "a") as logFile:
                    logFile.write(json.dumps(logEntry) + "\n");
            except Exception as err:
                print(f"[!LOG_ERR]: {err}");


TRANSACTION_LOGGER = transactionLogger();
