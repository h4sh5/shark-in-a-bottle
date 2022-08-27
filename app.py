#!/usr/bin/env python3
from flask import Flask, render_template, request,jsonify
from werkzeug.utils import secure_filename
import hashlib
import pyshark
import os
app = Flask(__name__,
            static_url_path='',
            static_folder='templates',
            template_folder='templates')
UPLOADPATH = 'uploads'

@app.route('/')
def index():
   return render_template('index.html')

@app.route('/file/<path>')
def showfile(path: str):
    '''
    given a path (atm its the md5sum of the file uploaded), return the analysis 
    of the pcap file stored there
    '''


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