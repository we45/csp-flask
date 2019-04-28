from flask import Flask, render_template, request,session, make_response
import datetime

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

@app.route('/raw-with-csp', methods = ['POST'])
def raw_with_csp():
    if request.method == 'POST':
        if 'raw_payload' in request.form and 'csp_payload' in request.form:
            resp = make_response(render_template('results.html', payload=request.form['raw_payload']))
            resp.headers.set('Content-Security-Policy', request.form['csp_payload'])
            return resp
        else:
            return render_template('err.html', err={'error': "Invalid Data", "message": "Payload not in message"})

@app.route('/session-attributes', methods = ['POST'])
def session_attrs():
    if request.method == 'POST':
        if 'raw_payload' in request.form:
            resp = make_response(render_template('results.html', payload=request.form['raw_payload']))
            resp.set_cookie('someuser', 'flask', httponly=True, samesite='Strict', max_age = 600)
            return resp
        else:
            return render_template('err.html', err={'error': "Invalid Data", "message": "Payload not in message"})

@app.route('/csp-bypass', methods = ['POST'])
def csp_bypass():
    if request.method == 'POST':
        if 'raw_payload' in request.form:
            resp = make_response(render_template('bypass.html', payload=request.form['raw_payload']))
            resp.headers.set('Content-Security-Policy', "default-src 'self'; script-src 'self' *.amazonaws.com")
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

@app.route('/sri', methods = ['GET'])
def sri_clock():
    return render_template('sri-clock.html')

if __name__ == '__main__':
    app.run(debug=True)
