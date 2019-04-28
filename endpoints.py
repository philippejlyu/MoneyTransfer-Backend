from flask import Flask, request, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import time
from random import random
from typing import Tuple
from flask import g

app = Flask(__name__)
app.config.from_object(__name__)

def verify_non_duplicate_user(username: str) -> bool:
    """
    Check to see if there is alrady a user with username
    """
    conn = sqlite3.connect('MoneyTransfer.db')
    c = conn.cursor()
    t = (username,)
    c.execute("SELECT * FROM users WHERE username=?", t)
    if c.fetchone() is None:
        conn.close()
        return True
    else:
        conn.close()
        return False


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

@app.route('/post')
def post():
    response = {
        'name': 'Philippe',
        'username': 'philippejlyu',
        'country': 'Canada',
    }
    return jsonify(response)


if __name__ == '__main__':
    app.run()
