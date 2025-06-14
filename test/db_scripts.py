import sqlite3

conn = sqlite3.connect('../ids_data.db')
cursor = conn.cursor()

cursor.execute("PRAGMA table_info(alerts);")
columns = cursor.fetchall()
for col in columns:
    print(col)

