from flask import Flask, render_template, request, redirect, url_for, flash
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import re

def is_password_strong(password):
    """
    Checks if the password is strong.
    - At least 8 characters long
    - Contains both uppercase and lowercase characters
    - Contains at least one digit
    - Contains at least one special character
    """
    if len(password) < 8:
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Set a secret key for message flashing

client = MongoClient('localhost', 27017)
db = client.test

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Find user by username
        user = db.users.find_one({'username': username})

        if user and check_password_hash(user['password'], password):
            # If the username and hashed password match, redirect to home or another page
            return redirect(url_for('home'))
        else:
            # If they don't match, flash a message and reload the login page
            flash('Invalid username or password')
            return redirect(url_for('login'))

    return render_template('login.html')

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

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Get form data
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        username = request.form.get('username')
        email = request.form.get('email')
        phone_number = request.form.get('phone_number')
        address = request.form.get('address')
        dob = request.form.get('dob')
        password = request.form.get('password')
        # Hash the password for security
        hashed_password = generate_password_hash(password)

        # Check if the password is strong enough
        if not is_password_strong(password):
            return "Password is not strong enough", 400
        
        # Check if username already exists
        existing_user = db.users.find_one({'username': username})
        if existing_user:
            return "Username already taken, please choose another one", 400

        # Insert the new user into the database
        user_id = db.users.insert_one({
            'firstName': first_name,
            'lastName': last_name,
            'username': username,
            'email': email,
            'phoneNumber': phone_number,
            'address': address,
            'dob': dob,
            'password': hashed_password,  # Store the hashed password
        }).inserted_id

        if user_id:
            # Redirect to the home page if signup is successful
            return redirect(url_for('home'))
        else:
            # In a real application, you would return an error message here
            return "Signup failed", 500

    # If it's a GET request, just render the signup template
    return render_template('signup.html')


if __name__ == '__main__':
    cert_path = "C:\\Users\\raemu\\Desktop\\MasterProj\\HTTPS Certs\\cert.pem"
    key_path = "C:\\Users\\raemu\\Desktop\\MasterProj\\HTTPS Certs\\key.pem"
    app.run(port=3000, ssl_context=(cert_path, key_path))
