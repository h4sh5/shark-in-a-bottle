#!/usr/bin/env python3

from flask import Flask, app, Response

app = Flask(__name__)

@app.route('/')
def index():
    body = '''<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
        "http://www.w3.org/TR/html4/strict.dtd">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: 501</p>
        <p>Message: Can only POST to CGI scripts.</p>
        <p>Error code explanation: HTTPStatus.NOT_IMPLEMENTED - Server does not support this operation.</p>
    </body>
</html>
'''
    headers = {}
    resp = Response(body,headers=headers, status=501)
    return resp

if __name__ == '__main__':
   app.run(debug = False,port=7777)