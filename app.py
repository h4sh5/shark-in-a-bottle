#!/usr/bin/env python3
from flask import Flask, render_template, request,jsonify,Response
from werkzeug.utils import secure_filename
import hashlib
import pyshark
import os
import time
import json
import subprocess

app = Flask(__name__,
            static_url_path='',
            static_folder='templates',
            template_folder='templates')
UPLOADPATH = 'uploads'

@app.route('/')
def index():
   return render_template('index.html')

@app.route('/dump/<path>')
def streampackets(path: str):
    '''
    given a path (atm its the md5sum of the file uploaded), return the analysis 
    of the pcap file stored there

    return a stream of packets
    '''
    cap = pyshark.FileCapture(os.path.join(UPLOADPATH, path))
    def generate():
        for p in cap:
            yield json.dumps({'num':p.number,'repr':p.__repr__(), 'src':p.ip.src, 'dst':p.ip.dst, 'length':p.length})+'\n'

    return app.response_class(generate(), mimetype='application/json')


def gen_replay_http_request(p, cap=None):
    url = '"' + p.http.request_full_uri + '"'
    # right now only supports tcp/http (not QUIC)
    # manual header parsing cos everything sucks
    fullrequest=''
    try:
        # XXX ascii or utf-8?
        fullrequest = bytes.fromhex(p.tcp.payload.replace(':','')).decode('utf-8')
    except Exception as e:
        return str(e)
    
    rawheaders = fullrequest.split("\r\n\r\n")[0].split("\r\n")[1:]
    data = ''
    if len(fullrequest.split("\r\n\r\n")) > 1:
        data = '\r\n\r\n'.join(fullrequest.split("\r\n\r\n")[1:])
    # XXX this means it cannot have repeat headers; use socket mode in that case?
    headers = {}
    for h in rawheaders:
        key = h.split(":")[0]
        value = ':'.join(h.split(":")[1:]).lstrip()
        headers[key] = value
    # drop headers we dont want
    if headers.get("If-None-Match"):
        del headers['If-None-Match']
    if headers.get(""):
        del headers['']
    headers =str(headers)
    method = '"' + p.http.request_method + '"'
    return Response(render_template('http_client.py.template', headers=headers, method=method, url=url, data=data),mimetype='text/plain')

def gen_replay_http_response(p, cap=None):
    response_code = int(p.http.response_code)
    
    # get headers somehow (need to parse the tcp response)

    # XXX need to reconstruct/find tcp streams, ffs
    body = bytes.fromhex(p.tcp.payload.replace(':','')).decode('utf-8')
    
    # if len(fullresponse.split("\r\n\r\n")) > 1:
        # body = '\r\n\r\n'.join(fullresponse.split("\r\n\r\n")[1:])

    # XXX this means it cannot have repeated/malformed headers; use socket mode in that case?
    # TODO get headers somehow by getting and parsing the entire TCP stream
    headers = {}
    # for h in rawheaders:
        # key = h.split(":")[0]
        # value = ':'.join(h.split(":")[1:]).lstrip()
        # headers[key] = value
    return Response(render_template('http_response.py.template', headers=headers, status=response_code, body=body), mimetype='text/plain')

def gen_replay_tcp(p):
    host = '"'+p.ip.dst+'"'
    port = p.tcp.dstport
    srcport = p.tcp.port
    data = bytes.fromhex(p.tcp.payload.replace(':',''))

    return Response(render_template('tcp_request.py.template', host=host,port=port,srcport=srcport,data=data), mimetype='text/plain')


def gen_replay_udp(p):
    return "WIP"

@app.route("/replay/<path>")
def replaypkt(path:str):
    args = request.args
    displayfilter = None
    if args.get('filter') != None:
        displayfilter = args.get("filter")
    pktnum = args.get('pktnum')
    if pktnum == None:
        return "Error: no packet number chosen"
    elif not pktnum.isdigit():
        return "Invalid packet number"
    # direction = args.get('direction')
    # if direction != "client" and direction != "server":
    #     return "Error: invalid replay type"
    replaytype = args.get('replaytype')

    cap = pyshark.FileCapture(os.path.join(UPLOADPATH, path))
    # select packet
    p = cap[int(pktnum) - 1] # tshark's output is 1-indexed

    if replaytype == 'auto':
        if len(p.get_multiple_layers("HTTP")) > 0: #means HTTP exists
            replaytype = "http"
        else:
            replaytype = 'socket'

    if replaytype == "http":
        if p.http.get('request') == '1':
            return gen_replay_http_request(p) #,cap=cap) # optional
   
        elif p.http.get('response') == '1':
            return gen_replay_http_response(p)

    elif replaytype == "socket":
        if len(p.get_multiple_layers("TCP")) > 0:
            return gen_replay_tcp(p)
        elif len(p.get_multiple_layers("UDP")) > 0:
            return gen_replay_udp(p)

    else:
        return "invalid replay type"

@app.route('/show/<path>')
def showfile(path:str):
    '''
    render a frontend to show the file
    '''

    args = request.args
    displayfilter = args.get('filter')

    args = ['tshark', '-r', os.path.join(UPLOADPATH,path)]

    if displayfilter != None:
        args.extend(['-Y', displayfilter])

    output = subprocess.check_output(args)
    output = output.decode('utf-8')

    return render_template('show.html', filename=path, output=output)


@app.route('/upload', methods = ['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # import pprint
        # pprint.pprint(request.files)

        # files = request.files
        # import code
        # code.interact(local=locals())
        success_count = 0
        md5hash = None
        try:
            print(request.files.getlist('files[]'))
            # find the first non-empty file
            f = None
            for f in request.files.getlist('files[]'):
                if f.filename != '':
                    break

            if f.filename != "":
                print('secure filename: ', secure_filename(f.filename))
                md5hash = hashlib.md5(f.read()).hexdigest()
                f.seek(0)
                f.save(os.path.join(UPLOADPATH, md5hash))
                success_count+=1
        except Exception as e:
            errmsg = str(e)
            return jsonify({"message":errmsg, 'success':0})
        if success_count > 0:
            return jsonify({'message':'file uploaded successfully', 'success':1, 'path':'/show/'+md5hash})
        else:
            return jsonify({'message':'no files uploaded', 'success':0})
        
if __name__ == '__main__':
   app.run(debug = True)