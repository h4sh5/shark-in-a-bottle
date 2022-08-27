#!/usr/bin/env python3

import requests

headers = {'Host': 'localhost:8000', 'User-Agent': 'curl/7.82.0', 'Accept': '*/*', 'Content-Length': '7', 'Content-Type': 'application/x-www-form-urlencoded'}
data='''foo=bar'''
r = requests.request(method="POST", url="http://localhost:8000/", headers=headers, data=data)

print(r.status_code)

print(r.text)
for i in r.headers:
    print(i + ": " + r.headers[i])

#import code
#code.interact(local=locals())