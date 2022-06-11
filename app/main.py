from flask import Flask, render_template, request, session, make_response
import datetime
from hashlib import sha256
from base64 import b64encode
import requests
from uuid import uuid4

app = Flask(__name__)
app.secret_key = 'any random string'
app.permanent_session_lifetime = datetime.timedelta(days=365)


@app.route('/')
def main_page():
    if request.method == 'GET':
        return render_template('main.html')


@app.route('/raw', methods=['POST'])
def raw_render():
    if request.method == 'POST':
        if 'raw_payload' in request.form:
            print(request.form)
            resp = make_response(render_template('results.html', payload=request.form['raw_payload']))
            resp.set_cookie('someuser', 'flask')
            return resp
        else:
            return render_template('err.html', err={'error': "Invalid Data", "message": "Payload not in message"})


@app.route('/raw-with-csp', methods=['POST'])
def raw_with_csp():
    if request.method == 'POST':
        if 'raw_payload' in request.form and 'csp_payload' in request.form:
            resp = make_response(render_template('results.html', payload=request.form['raw_payload']))
            resp.headers.set('Content-Security-Policy', request.form['csp_payload'])
            return resp
        else:
            return render_template('err.html', err={'error': "Invalid Data", "message": "Payload not in message"})


@app.route('/session-attributes', methods=['POST'])
def session_attrs():
    if request.method == 'POST':
        if 'raw_payload' in request.form:
            resp = make_response(render_template('results.html', payload=request.form['raw_payload']))
            resp.set_cookie('someuser', 'flask', secure=True, httponly=True, samesite='Strict', max_age=600)
            return resp
        else:
            return render_template('err.html', err={'error': "Invalid Data", "message": "Payload not in message"})


@app.route('/csp-bypass', methods=['POST'])
def csp_bypass():
    if request.method == 'POST':
        if 'raw_payload' in request.form:
            resp = make_response(render_template('bypass_1.html', payload=request.form['raw_payload']))
            resp.headers.set('Content-Security-Policy', "default-src 'none'; script-src 'self' *.digitaloceanspaces.com")
            return resp
        else:
            return render_template('err.html', err={'error': "Invalid Data", "message": "Payload not in message"})


@app.route('/csp-hash', methods=['POST'])
def csp_hash():
    if request.method == 'POST':
        if 'raw_payload' in request.form:
            resp = make_response(render_template('bypass.html', payload=request.form['raw_payload']))
            static_js = requests.get('https://ase-csp.sfo3.digitaloceanspaces.com/index.js').content.strip()
            csp_hash = b64encode(sha256(static_js).digest()).decode()
            resp.headers.set('Content-Security-Policy',
                             "default-src 'self'; script-src 'sha256-{}'".format(csp_hash))
            return resp
        else:
            return render_template('err.html', err={'error': "Invalid Data", "message": "Payload not in message"})


@app.route('/csp-nonce', methods=['POST'])
def csp_nonce():
    if request.method == 'POST':
        if 'raw_payload' in request.form:
            static_js = requests.get('https://ase-csp.sfo3.digitaloceanspaces.com/index.js').content.strip()
            csp_nonce = uuid4().hex
            resp = make_response(
                render_template('nonce.html', payload=request.form['raw_payload'], nonce=csp_nonce,
                                script=static_js.decode()))
            resp.headers.set('Content-Security-Policy',
                             "default-src 'self'; script-src 'nonce-{}'".format(csp_nonce))
            return resp
        else:
            return render_template('err.html', err={'error': "Invalid Data", "message": "Payload not in message"})


@app.route('/dompurify', methods=['POST'])
def dompurify():
    if request.method == 'POST':
        if 'raw_payload' in request.form:
            print(request.form)
            resp = make_response(render_template('purified.html', payload=request.form['raw_payload']))
            return resp
        else:
            return render_template('err.html', err={'error': "Invalid Data", "message": "Payload not in message"})


@app.route('/sri', methods=['POST'])
def sri_clock():
    if request.method == 'POST':
        if 'raw_payload' in request.form:
            resp = make_response(render_template('sri.html', payload=request.form['raw_payload']))
            return resp
        else:
            return render_template('err.html', err={'error': "Invalid Data", "message": "Payload not in message"})


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=80, debug=True)
