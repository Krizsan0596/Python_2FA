from flask import Flask, render_template, request, redirect, url_for
from flask_socketio import SocketIO
from io import BytesIO
from string import digits
from argon2 import PasswordHasher, exceptions
import qrcode
import socket
import base64
import pickle
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)
ph = PasswordHasher()
code_length = 6
passcode = None
config = None


try:
    with open("config.pickle", "rb") as file:
        config = pickle.load(file)
except FileNotFoundError:
    config = None


def generate_hash(string: str):
    return ph.hash(string)


def verify_hash(string: str, hash: str):
    return ph.verify(hash, string)


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't have to be reachable, just need to access a valid IP
        s.connect(("8.8.8.8", 80))  # Google's DNS server (for IP lookup only)
        ip_address = s.getsockname()[0]
    except Exception:
        ip_address = "127.0.0.1"  # Fallback to localhost
    finally:
        s.close()
    return ip_address


def generate_qrcode(string: str):
    img = qrcode.make(string)
    buffered = BytesIO()
    img.save(buffered)
    img_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
    return f"data:image/png;base64,{img_base64}"


def generate_code():
    return ''.join(random.choice(digits) for _ in range(code_length))


@app.route('/', methods=['GET'])
def index():
    try:
        qr_code = generate_qrcode(f"http://{get_local_ip()}:5000/scan")
    except Exception as e:
        print(e)
        return "QR code generation failed", 500
    return render_template('index.html',  qr_code=qr_code)


@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if config is not None:
        if request.method == 'POST':
            password = request.form['password']
            try:
                verify_hash(password, config)
            except exceptions.VerifyMismatchError:
                return render_template('scan.html', error="Incorrect passcode.")
            else:
                socketio.emit('scanned')
                passcode = generate_code()
                return redirect(url_for('code', code=passcode))
        return render_template('scan.html')
    return redirect(url_for('configuration'))


@app.route('/config', methods=['GET', 'POST'])
def configuration():
    if request.method == 'POST':
        password = request.form['password']
        if len(password) < 8:
            return render_template('config.html', error="Passcode must be at least 8 characters long.")
        password = generate_hash(password)
        with open("config.pickle", "wb") as file:
            pickle.dump(password, file)
        global config
        config = password
        return redirect(url_for('scan'))
    return render_template('config.html')


@app.route('/code', methods=['GET'])
def code():
    global passcode
    passcode = generate_code()
    return render_template('code.html', valid=15, passcode=passcode)


@app.route('/verification', methods=['GET', 'POST'])
def verification():
    global passcode
    if request.method == 'POST':
        code1 = request.form['code_digit_1']
        code2 = request.form['code_digit_2']
        code3 = request.form['code_digit_3']
        code4 = request.form['code_digit_4']
        code5 = request.form['code_digit_5']
        code6 = request.form['code_digit_6']
        code_entered = ''.join([code1, code2, code3, code4, code5, code6])
        if code_entered == passcode:
            passcode = None
            socketio.emit('verified')
            return redirect("http://www.example.com")
    return render_template('verification.html')


@socketio.on('connect')
def handle_connect():
    print('Client connected')


@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')


@socketio.on('scanned')
def handle_scanned():
    print('QR code scanned')


@socketio.on('verified')
def handle_verified():
    print('Passcode verified')


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
