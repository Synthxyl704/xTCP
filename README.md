# xTCP - its not a TCP!
Well, **it is actually an HTTP/1.1 server** instead.

## Run locally (loopback is used):
Git clone the repo:
```
git clone github.com/Synthxyl704/xTCP
```

Run main:
```
python main.py
```

> [!IMPORTANT]
> I didn not try `0.0.0.0` yet, maybe you can experiment with it if you want. <br>

Run in browser's search (any one or discriminate in seperate tabs, program uses threads for handling it so it will work anyway):

| Protocol | Address                  | Requirements                |
| -------- | ------------------------ | --------------------------- |
| HTTP     | `http://127.0.0.1:8080`  | None                        |
| HTTP     | `http://[::1]:8080`      | None                        |
| HTTPS    | `https://127.0.0.1:8443` | `server.crt` + `server.key` |
| HTTPS    | `https://[::1]:8443`     | `server.crt` + `server.key` |

> [!NOTE]
> Now yes there might be some TLS issues in your code when you run it, but I will not really assume youre interested enough here to generate your own OpenSSL certificate. <br>
> So you are allowed to use the loopback address w/ HTTP only as an alternative for quick checking / working as well.

OpenSSL command to generate a self-signed certificate (-x509) and a 4096-bit RSA key (--newkey rsa:4096) as required by the code:
```
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"
```

> [!WARNING]
> (This) self-signed certificate/s will trigger some browser security warnings which is to be expected for locally signed shit. <br>
Just click "Advanced" > "Proceed" to bypass.

## Logs

| Date | LogNote |
| ----     | ------------------------ | 
| 14-02-2026 | Modularized shit into a common folder `/src` |
| 13-02-2026     | Add HTTP/2 implementation  |
