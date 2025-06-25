import sqlite3

conn = sqlite3.connect('../ids_data.db')
cursor = conn.cursor()

print("..................... alerts ..........................")

cursor.execute("PRAGMA table_info(alerts);")
columns = cursor.fetchall()
for col in columns:
    print(col)

print("..................... Flows ..........................")
cursor.execute("PRAGMA table_info(flows);")
columns = cursor.fetchall()
for col in columns:
    print(col)

print("......................ml_alerts .........................")
cursor.execute("PRAGMA table_info(ml_alerts);")
columns = cursor.fetchall()
for col in columns:
    print(col)