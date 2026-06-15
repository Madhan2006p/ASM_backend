import psycopg2
try:
    conn = psycopg2.connect(host="localhost", port=5435, dbname="faraday", user="faraday", password="faraday")
    cur = conn.cursor()
    cur.execute("DELETE FROM vulnerability WHERE external_id LIKE '%asm-%';")
    conn.commit()
    print("Deleted.")
except Exception as e:
    print(f"Error: {e}")
