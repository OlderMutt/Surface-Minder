import sqlite3
conn = sqlite3.connect('db/easm.sqlite')
c = conn.cursor()
for row in c.execute("SELECT id, scan_file FROM scan_files ORDER BY id DESC"):
    print(row)
print('--- ports sample ---')
for row in c.execute("SELECT ip, port, proto, state FROM ports LIMIT 10"):
    print(row)
conn.close()

