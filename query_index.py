import psycopg2
try:
    conn = psycopg2.connect(host="localhost", port=5435, dbname="faraday", user="faraday", password="faraday")
    cur = conn.cursor()
    cur.execute("SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'vulnerability';")
    rows = cur.fetchall()
    for r in rows:
        print(r)
except Exception as e:
    print(f"Error: {e}")
