# xTCP - its not a TCP!
Well, it is actually an HTTP/1.1 server instead.

Pretty simple, all you need to do is:
Git clone the repo:
```
git clone github.com/Synthxyl704/xTCP
```

Run main:
```
python main.py
```

Run in browser's search (any one or discriminate in seperate tabs, program uses threads for handling it so it will work anyway):
```
http://127.0.0.1:8080
http://[::1]:8080
```

or if you have `server.crt` and `server.key` locally generated
```
https://127.0.0.1:8443
https://[::1]:8443
```
Didn't try `0.0.0.0` yet, maybe you can experiment with it if you want.

Now yes there might be some TLS issues in your code but I wont really assume youre interested enough to run your own OpenSSL certificate. <br>
So, for now, just use the loopback address w/ HTTP.
