#!/usr/bin/env python3
from flask import Flask, render_template, request,jsonify
from werkzeug.utils import secure_filename
import hashlib
import pyshark
import os
import time
import json
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

    cap = pyshark.FileCapture(os.path.join(UPLOADPATH, path), display_filter=displayfilter)
    # select packet
    p = cap[int(pktnum)]


    if replaytype == "http":
        # if direction == 'client':
        print(p)
        if p.http.get('request') == '1':
            url = '"' + p.http.request_full_uri + '"'
            # right now only supports tcp/http (not QUIC)
            # manual header parsing cos everything sucks
            try:
                # XXX ascii or utf-8?
                fullrequest = bytes.fromhex(p.tcp.payload.replace(':','')).decode('utf-8')
            except Exception as e:
                return str(e)
            
            rawheaders = fullrequest.split("\r\n")[1:]
            # XXX this means it cannot have repeat headers; use socket mode in that case?
            headers = {}
            for h in rawheaders:
                key = h.split(":")[0]
                value = ''.join(h.split(":")[1:]).lstrip()
                headers[key] = value
            # drop headers we dont want
            del headers['If-None-Match']
            del headers['']
            headers =str(headers)
            method = '"' + p.http.request_method + '"'
            return render_template('http_client.py.template', headers=headers, method=method, url=url)





    elif replaytype == "socket":
        return "WIP"
    else:
        return "invalid replay type"

@app.route('/show/<path>')
def showfile(path:str):
    '''
    render a frontend to show the file
    '''

    args = request.args
    displayfilter = args.get('filter')

    if displayfilter != None:
        cap = pyshark.FileCapture(os.path.join(UPLOADPATH, path, display_filter=displayfilter))
        # if there's a display filter, get every packet from that filter
        start = time.time()

        # for p in cap:
            # custom pretty print each layer
            # for layer in p.layers:



        print('time taken:', time.time() - start)


    else:
        cap = pyshark.FileCapture(os.path.join(UPLOADPATH, path), only_summaries=True)
        start = time.time()
        protostats = {} # each type per count
        for p in cap:
            # HACK XXX attempt to turn a protocol name into a filter by some parsing 
            proto_filter = str(p.protocol).lower().split('/')[0]
            if protostats.get(proto_filter) == None:
                protostats[proto_filter] = 0
            protostats[proto_filter] += 1
        print(protostats)
        print('time taken:', time.time() - start)
        return render_template('show.html', protostats=protostats,filename=path)

# @app.route('/validatefilter/<path>')
# def validatefilter(path:str):
#     args = request.args
#     display_filter = args['f']
#     try:
#         cap = pyshark.FileCapture(os.path.join(UPLOADPATH, path), display_filter=display_filter)
#     except Exception as e:
#         return jsonify({"success":0, "msg":str(e)})



# @app.route('/displayfilter/<path>')
# def filterfile(path:str):
#     args = request.args
#     display_filter = args['f']
#     try:
#         cap = pyshark.FileCapture(os.path.join(UPLOADPATH, path), display_filter=display_filter)
#     except:







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
            f = request.files.getlist('files[]')[0]
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
            return jsonify({'message':'file uploaded successfully', 'success':1, 'path':'/file/'+md5hash})
        else:
            return jsonify({'message':'no files uploaded', 'success':0})
        
if __name__ == '__main__':
   app.run(debug = True)