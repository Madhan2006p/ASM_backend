import psycopg2
try:
    conn = psycopg2.connect(host="localhost", port=5435, dbname="faraday", user="faraday", password="faraday")
    cur = conn.cursor()
    cur.execute("SELECT conname, pg_get_constraintdef(c.oid) FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace WHERE conrelid = 'vulnerability'::regclass;")
    rows = cur.fetchall()
    for r in rows:
        print(r)
except Exception as e:
    print(f"Error: {e}")
