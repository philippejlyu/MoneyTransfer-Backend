from flask import Flask, request, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import time
from random import random
from typing import Tuple, Optional

app = Flask(__name__)
app.config.from_object(__name__)

def get_user_record(username: str) -> Optional[Tuple]:
    """
    Return a tuple of the user information

    Returns a tuple [username, hashed_password, balance]
    """
    conn = sqlite3.connect("MoneyTransfer.db")
    c = conn.cursor()
    t = (username,)
    c.execute("SELECT * FROM users WHERE username=?", t)
    result = c.fetchone()
    c.close()
    conn.commit()
    return result

def verify_non_duplicate_user(username: str) -> bool:
    """
    Check to see if there is alrady a user with username
    """
    return get_user_record(username) is None


def generate_access_token(user: str) -> Tuple[str, int]:
    """
    Generates an access token for user and records it
    Access token expires always after 1 hour
    return a tuple of (token, expiry)
    """
    expiry = int(time.time()) + 3600
    random_number = random()
    generating_string = user + ' %i %f' % (expiry, random_number)
    hashed = generate_password_hash(generating_string)
    token = hashed[14:]
    # Now we record the token and the user
    conn = sqlite3.connect('MoneyTransfer.db')
    c = conn.cursor()
    values = (user, token, expiry)
    c.execute("INSERT INTO accessTokens VALUES ('%s', '%s', '%i')" % values)
    c.close()
    conn.commit()
    return (token, expiry)

def get_username_for_access_token(token: str) -> Optional[str]:
    """
    Given a valid access token, return the username
    If the token is expired or if the token is invalid, None will be returned
    """
    conn = sqlite3.connect('MoneyTransfer.db')
    c = conn.cursor()
    values = (token,)
    c.execute("SELECT * FROM accessTokens WHERE token=?", values)
    result = c.fetchone()
    c.close()
    conn.commit()
    time_since_epoch = int(time.time())
    if result is None or time_since_epoch > result[2]:
        return None
    else:
        return result[0]

def verify_user_exists(user: str) -> bool:
    """
    Given a username, checks to see if the user exists
    """
    conn = sqlite3.connect('MoneyTransfer.db')
    c = conn.cursor()
    values = (user,)
    c.execute("SELECT username FROM users WHERE username=?", values)
    result = c.fetchone()
    c.close()
    conn.commit()
    return result is not None


@app.route('/createaccount', methods=['POST'])
def create_account():
    """
    Create an account
    Verify there isn't another user with this name

    === Header ===
    username: the username
    password: the user password
    """
    conn = sqlite3.connect('MoneyTransfer.db')
    c = conn.cursor()
    username = request.headers['username']
    password = request.headers['password']
    if not verify_non_duplicate_user(username):
        response = {
            'error': 'Username is already in use'
        }
        return jsonify(response)
    else:

        conn = sqlite3.connect('MoneyTransfer.db')
        c = conn.cursor()
        hashed_password = generate_password_hash(password)
        credentials = (username, hashed_password)
        c.execute("INSERT INTO users VALUES ('%s', '%s', 0.0)" % credentials)
        conn.commit()
        conn.close()

        token = generate_access_token(username)
        response = {
            'token': token[0],
            'expiry': token[1]
        }
        return jsonify(response)


@app.route('/login', methods=['POST'])
def login():
    """
    Verify the username and password
    If it's correct, send back a token and expiry time

    === Header ===
    username: the candiate username
    password: the candidate password
    :return:
    """
    if request.method == 'POST':
        username = request.headers['username']
        password = request.headers['password']

        conn = sqlite3.connect('MoneyTransfer.db')
        c = conn.cursor()
        t = (username,)
        c.execute("SELECT * FROM users WHERE username=?", t)
        user_data = c.fetchone()
        c.close()
        conn.commit()
        invalid_credentials = {'error': 'Invalid username or password'}
        if user_data is None:
            return jsonify(invalid_credentials)
        else:
            user_info = user_data
            if check_password_hash(user_info[1], password):
                # We have successfully authenticated the user
                token = generate_access_token(username)
                response = {
                    'token': token[0],
                    'expiry': token[1]
                }
                return jsonify(response)
            else:
                return jsonify(invalid_credentials)
    else:
        abort(400)

@app.route('/transfer', methods=["POST"])
def transfer():
    """
    Transfer money from one person to another

    === Header ===
    token: The token that was given by the server to the client
    username: The username of the person sending the money
    recipient: The username of the recipient
    amount: The amount of money being sent

    === Preconditions ===
    amount is an number
    """
    token = request.headers['token']
    username = request.headers['username']
    recipient = request.headers['recipient']
    amount = float(request.headers['amount'])

    # First verify sender's authentication
    name = get_username_for_access_token(token)
    if name != username:
        response = {'error': 'Token could be expired or be invalid'}
        return jsonify(response)

    # Now verify to see recipient is valid
    if not verify_user_exists(recipient):
        response = { 'error': 'The recipient does not exist'}
        return jsonify(response)


    # See if the sender has enough money to send
    sender_record = get_user_record(username)
    recipient_record = get_user_record(recipient)
    if sender_record[2] < amount:
        # They don't have enough money
        response = { 'error': 'Insufficient balance'}
        return jsonify(response)

    # Now create a transaction record
    conn = sqlite3.connect('MoneyTransfer.db')
    c = conn.cursor()
    time_since_epoch = int(time.time())
    values = (username, recipient, amount, time_since_epoch)
    c.execute("INSERT INTO transactions VALUES ('%s', '%s', %f, %i)" % values)

    # Now subtract the money from the sender
    new_sender_balance = sender_record[2] - amount
    new_recipient_balance = recipient_record[2] + amount

    temp_data = (new_sender_balance, username,)
    c.execute("UPDATE users SET balance=? WHERE username=?", temp_data)
    # Now add the money to the recipient

    temp_data = (new_recipient_balance, recipient)
    c.execute("UPDATE users SET balance=? WHERE username=?", temp_data)
    # Send a response if it got to this point with a confirmation code maybe?
    c.close()
    conn.commit()
    response = { 'success': ''}
    return jsonify(response)

@app.route('/canreceivemoney', methods=['GET'])
def can_receive_money():
    """
    Returns whether or not a user can receive money i.e. a user exists
    === Header ===
    username: the username of the user we want info about
    """
    if verify_user_exists(request.headers['username']):
        response = { 'userExists': True }
        return jsonify(response)
    else:
        response = { 'userExists': False }
        return jsonify(response)

@app.route('/balance', methods=['GET'])
def balance():
    """
    Return the balance of the current user.
    === Header ===
    token: The authorization token for the user we want information about
    username: The username we want info about
    """
    username = get_username_for_access_token(request.headers['token'])
    if username == request.headers['username']:
        # Now we verified it's the correct person
        user_record = get_user_record(username)
        response = { 'username': user_record[0], 'balance': user_record[2] }
        return jsonify(response)
    else:
        abort(401)


if __name__ == '__main__':
    app.run()
