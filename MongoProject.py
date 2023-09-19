from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')

if __name__ == '__main__':
    cert_path = "C:\\Users\\raemu\\Desktop\\MasterProj\\HTTPS Certs\\cert.pem"
    key_path = "C:\\Users\\raemu\\Desktop\\MasterProj\\HTTPS Certs\\key.pem"
    app.run(port=3000, ssl_context=(cert_path, key_path))
