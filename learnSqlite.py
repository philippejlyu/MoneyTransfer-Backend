import sqlite3
conn = sqlite3.connect('MoneyTransfer.db')

c = conn.cursor()

#c.execute("INSERT INTO users VALUES ('Taylor', 'Swift', 500)")

t = ('Taylor',)
c.execute("SELECT * FROM users WHERE username=?", t)
print(c.fetchone())

conn.commit()
conn.close()
