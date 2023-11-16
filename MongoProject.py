from flask import Flask, render_template
from pymongo import MongoClient

app = Flask(__name__)

client = MongoClient('localhost', 27017)
db = client.test

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/friends')
def friends():
    try:
        # Assuming you have a collection named 'users'
        users_collection = db.users
        users_list = list(users_collection.find({}))
        return render_template('friends.html', users=users_list)
    except Exception as e:
        # If an error occurs, print it to the console and return an error message
        print("An error occurred:", e)
        return "An error occurred fetching user data"

@app.route('/signup')
def signup():
    return render_template('signup.html')

if __name__ == '__main__':
    cert_path = "C:\\Users\\raemu\\Desktop\\MasterProj\\HTTPS Certs\\cert.pem"
    key_path = "C:\\Users\\raemu\\Desktop\\MasterProj\\HTTPS Certs\\key.pem"
    app.run(port=3000, ssl_context=(cert_path, key_path))
