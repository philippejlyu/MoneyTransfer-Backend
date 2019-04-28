import sqlite3
from typing import *
conn = sqlite3.connect('MoneyTransfer.db')

c = conn.cursor()

#c.execute("INSERT INTO users VALUES ('Taylor', 'Swift', 500)")

t = ('Taylor',)
#c.execute("SELECT * FROM users WHERE username=?", t)
#values = ('150000$q4CeejTK$74036e73646a965131f622b2ee371849cbba7e224a00ca3b32ebe7c60c5d7dd6',)
#c.execute("SELECT * FROM accessTokens WHERE token=?", values)
#values = ('Philippejlyu',)
#c.execute("SELECT username FROM users WHERE username=?", values)
#print(c.fetchone())
#t = (42, 'cindy',)
#c.execute("UPDATE users SET balance=? WHERE username=?", t)
values = ('asdf', 'ghjk', 50.45, 234)
c.execute("INSERT INTO transactions VALUES ('%s', '%s', %f, %i)" % values)
conn.commit()
conn.close()

'''
def get_user_record(username: str) -> Optional[Tuple]:
    """
    Return a tuple of the user information
    """
    conn = sqlite3.connect("MoneyTransfer.db")
    c = conn.cursor()
    t = (username,)
    c.execute("SELECT * FROM users WHERE username=?", t)
    result = c.fetchone()
    c.close()
    conn.commit()
    return result

print(get_user_record('cindy'))
print(type(get_user_record('cindy')[2]))
'''
