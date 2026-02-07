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
> Now yes there might be some TLS issues in your code when you run it, but I wont really assume youre interested enough to generate your own OpenSSL certificate for the sake of this project. <br>
> So you are allowed to use the loopback address w/ HTTP only as an alternative for quick checking / working.
