from flask import Flask, render_template, request, redirect, url_for, flash, session
from pymongo import MongoClient
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from password_strength import PasswordPolicy
import smtplib
from email.mime.text import MIMEText
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

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = db.users.find_one({'_id': ObjectId(user_id)})

    # Fetch friends' user documents based on the IDs in the 'friends' list
    friend_ids = user.get('friends', [])
    friends = db.users.find({'_id': {'$in': friend_ids}})

    return render_template('checkout.html', friends=list(friends))

@app.route('/finalize_checkout', methods=['POST'])
def finalize_checkout():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    friend_username = request.form.get('friend')

    # Fetch the friend's email address from the database
    friend = db.users.find_one({'username': friend_username})
    if not friend or not friend.get('email'):
        return "Friend's email address not found.", 400

    # Prepare the email content (e.g., list of items in the cart)
    user = db.users.find_one({'_id': ObjectId(user_id)})
    cart_items = ', '.join(user.get('cart', []))
    email_content = f"Hello, {friend_username}! You've received the following items: {cart_items}."
 
    # Send the email
    try:
        send_email(friend['email'], email_content)
    except Exception as e:
        print("Failed to send email:", e)
        return "Failed to send email.", 500

    # Clear the user's cart after sending the email
    db.users.update_one({'_id': ObjectId(user_id)}, {'$set': {'cart': []}})

    return redirect(url_for('home'))

def send_email(to_email, content):
    sender_email = "Put_Email_Here"
    password = "16digitcode" #under google "app password", have to put dual auth to allow

    msg = MIMEText(content)
    msg['Subject'] = "You've Got a Gift!"
    msg['From'] = sender_email
    msg['To'] = to_email

    # Send the message via an SMTP server
    s = smtplib.SMTP('smtp.gmail.com', 587) #this is the gmail smtp email
    s.starttls()
    s.login(sender_email, password)
    s.sendmail(sender_email, [to_email], msg.as_string())
    s.quit()

@app.route('/cart')
def cart():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user = db.users.find_one({'_id': ObjectId(user_id)})

    cart_items = user.get('cart', [])
    return render_template('cart.html', cart_items=cart_items)


@app.route('/clear_cart')
def clear_cart():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    # Clear the cart in the user's document in the database
    db.users.update_one(
        {'_id': ObjectId(user_id)},
        {'$set': {'cart': []}}
    )

    return redirect(url_for('cart'))

@app.route('/remove_item_from_cart', methods=['POST'])
def remove_item_from_cart():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    item_to_remove = request.form.get('item')
    #print("Removing item:", item_to_remove)  # Debug print //fixed

    # Remove the specified item from the user's cart
    db.users.update_one(
        {'_id': ObjectId(user_id)},
        {'$pull': {'cart': item_to_remove}}
    )

    return redirect(url_for('cart'))


@app.route('/add_to_cart')
def add_to_cart():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    item = request.args.get('item')
    user_id = session['user_id']

    # Add the item to the user's cart in the database
    db.users.update_one(
        {'_id': ObjectId(user_id)},
        {'$addToSet': {'cart': item}}
    )

    return redirect(url_for('home'))

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
        current_user_id = ObjectId(session['user_id'])

        # Fetch the current user's data
        current_user = db.users.find_one({'_id': current_user_id})

        if current_user['username'] == friend_username:
            return "You cannot send a friend request to yourself."

        # Find the potential friend's user document by username
        friend = db.users.find_one({'username': friend_username})
        if friend:
            # Check if already friends
            if friend['_id'] in current_user.get('friends', []):
                return "This user is already your friend."

            # Check if a request has already been sent
            if friend['_id'] in current_user.get('friend_requests', []):
                return "A friend request has already been sent to this user."

            # Add a friend request to the targeted user
            db.users.update_one(
                {'_id': friend['_id']},
                {'$addToSet': {'friend_requests': current_user_id}}
            )
            return "Friend request sent!"
        else:
            return "User not found"

    return render_template('add_friend.html')

@app.route('/accept_request/<requester_id>')
def accept_request(requester_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user_id = ObjectId(session['user_id'])
    requester_id = ObjectId(requester_id)

    # Add requester to the current user's friends list
    db.users.update_one(
        {'_id': current_user_id},
        {'$addToSet': {'friends': requester_id}}
    )

    # Also, add the current user to the requester's friends list
    db.users.update_one(
        {'_id': requester_id},
        {'$addToSet': {'friends': current_user_id}}
    )

    # Remove the friend request
    db.users.update_one(
        {'_id': current_user_id},
        {'$pull': {'friend_requests': requester_id}}
    )

    return redirect(url_for('friends'))  # Redirect to the friends list page


@app.route('/reject_request/<requester_id>')
def reject_request(requester_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user_id = ObjectId(session['user_id'])
    requester_id = ObjectId(requester_id)

    # Remove the friend request
    db.users.update_one(
        {'_id': current_user_id},
        {'$pull': {'friend_requests': requester_id}}
    )

    return redirect(url_for('friends'))  # Redirect to the friends list page

@app.route('/friends')
def friends():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    current_user_id = ObjectId(session['user_id'])
    user = db.users.find_one({'_id': current_user_id})

    # Fetch friends' information
    friends = db.users.find({'_id': {'$in': user.get('friends', [])}})

    # Fetch pending friend requests' information
    friend_requests = db.users.find({'_id': {'$in': user.get('friend_requests', [])}})

    return render_template('friends.html', friends=list(friends), friend_requests=list(friend_requests))

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
    #cert_path = "C:Pathway to HTTP cert \\cert.pem"
    #key_path = "C:Pathway to HTTP key\\key.pem"
    app.run(port=3000, ssl_context=(cert_path, key_path))
