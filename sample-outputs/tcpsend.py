#!/usr/bin/env python3

import socket

s = socket.socket()

data = b'GET / HTTP/1.1\r\nAccept: text/html, application/xhtml+xml, image/jxr, */*\r\nAccept-Language: en-US\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36 Edge/15.15063\r\nAccept-Encoding: gzip, deflate\r\nHost: microsoft-patch.access.ly\r\nDNT: 1\r\nConnection: Keep-Alive\r\n\r\n'

s.bind(('', 50072))
s.connect(("127.0.0.1", 5000))

s.send(data)

print(s.recv(2048))
