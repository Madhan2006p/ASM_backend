import psycopg2

conn = psycopg2.connect(host="localhost", port=5435, dbname="faraday", user="faraday", password="faraday")
cur = conn.cursor()
cur.execute("SELECT indexdef FROM pg_indexes WHERE tablename = 'vulnerability';")
for row in cur.fetchall():
    print(row[0])
