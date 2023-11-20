from flask import Flask, render_template, request, redirect, url_for, flash, session
from pymongo import MongoClient
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from password_strength import PasswordPolicy
import os
import re

app = Flask(__name__)
#app.secret_key = os.urandom(24) #used to test and reset the cookies every boot
app.secret_key = 'your_secret_key'  # Set a secret key for message flashing, used in production

# Define your password policy
policy = PasswordPolicy.from_names(
    length=8,  # minimum length: 8
    uppercase=1,  # need min. 1 uppercase letters
    numbers=1,  # need min. 1 digits
    special=1,  # need min. 1 special characters
)

client = MongoClient('localhost', 27017)
db = client.test

@app.route('/')
def home():
    user_data = None
    if 'user_id' in session:
        user_id = session['user_id']
        user = db.users.find_one({"_id": ObjectId(user_id)})
        if user:
            user_data = {'username': user['username']}

    return render_template('home.html', user=user_data)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Find user by username
        user = db.users.find_one({'username': username})

        if user and check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])  # Storing user's ID in the session
            # If the username and hashed password match, redirect to home or another page
            return redirect(url_for('home'))
        else:
            # If they don't match, flash a message and reload the login page
            flash('Invalid username or password')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)  # Remove the user_id from the session
    return redirect(url_for('home'))

@app.route('/add_friend', methods=['GET', 'POST'])
def add_friend():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        friend_username = request.form.get('friend_username')
        user_id = ObjectId(session['user_id'])

        if friend_username:
            # Prevent adding self as friend
            current_user = db.users.find_one({'_id': user_id})
            if current_user['username'] == friend_username:
                return "You cannot add yourself as a friend."

            # Find the friend's user document by username
            friend = db.users.find_one({'username': friend_username})

            if friend:
                # Prevent duplicate friend entries
                if friend['_id'] in current_user.get('friends', []):
                    return "This user is already your friend."

                # Add friend's ID to the user's friend list
                db.users.update_one(
                    {'_id': user_id},
                    {'$addToSet': {'friends': friend['_id']}}
                )
                return "Friend added successfully!"
            else:
                return "Friend not found"

    return render_template('add_friend.html')

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

        # Validate phone number format
        if not re.match(r"^\d{10}$", phone_number):
            # Handle invalid phone number format
            return "Invalid phone number format", 400
        
        # Check if username already exists
        existing_user = db.users.find_one({'username': username})
        if existing_user:
            return "Username already taken, please choose another one", 400

        # Calculate age
        dob = request.form.get('dob')
        dob_date = datetime.strptime(dob, '%Y-%m-%d')  # Adjust format if needed
        today = datetime.now()
        age = today.year - dob_date.year - ((today.month, today.day) < (dob_date.month, dob_date.day))

        # Check if user is over 10 years old
        if age < 10:
            # Handle the case where the user is too young
            return "You must be over 10 years old to sign up", 400
        
        # Check if the password is strong enough
        errors = policy.test(password)
        if errors:
            error_messages = [str(error) for error in errors]
            return "Password is not strong enough. " + "; ".join(error_messages), 400
        
        # Default friend's ObjectId
        default_friend_id = ObjectId("655aa04ef9faafd43349bdab")

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
            'friends': [default_friend_id]  # Add default friend
        }).inserted_id

        if user_id:
            # Redirect to the home page if signup is successful and login
            session['user_id'] = str(user_id)
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