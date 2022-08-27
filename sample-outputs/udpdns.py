#!/usr/bin/env python3

import socket


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)



data = b'H\x12\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01'

s.bind(('', 55618))
addr = ("192.168.1.10", 53)
s.sendto(data,addr)

print(s.recvfrom(4096))
