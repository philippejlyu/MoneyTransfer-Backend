import sqlite3
conn = sqlite3.connect('MoneyTransfer.db')

c = conn.cursor()

#c.execute("INSERT INTO users VALUES ('Taylor', 'Swift', 500)")

t = ('Taylor',)
#c.execute("SELECT * FROM users WHERE username=?", t)
#values = ('150000$q4CeejTK$74036e73646a965131f622b2ee371849cbba7e224a00ca3b32ebe7c60c5d7dd6',)
#c.execute("SELECT * FROM accessTokens WHERE token=?", values)
values = ('Philippejlyu',)
c.execute("SELECT username FROM users WHERE username=?", values)
print(c.fetchone())

conn.commit()
conn.close()
