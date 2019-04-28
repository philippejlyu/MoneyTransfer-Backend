from flask import Flask, request, jsonify
import sqlite3
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
        hashed_password = password
        credentials = (username, hashed_password)
        c.execute("INSERT INTO users VALUES ('%s', '%s', 0.0)" % credentials )
        conn.commit()
        conn.close()
        # TODO: Create an access token

        response = {
            'token': 'asdfasdf'
        }
        return jsonify(response)



@app.route("/")
def index():
    return 'Index'

@app.route('/user/<username>')
def show_user_profile(username):
    return 'User: %s' % username

@app.route('/login', methods=['POST'])
def login():
    if request.method == 'POST':
        return '' + request.headers['username'] + request.headers['password']
    else:
        return 'Error 401'

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
