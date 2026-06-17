import psycopg2
try:
    conn = psycopg2.connect(host="localhost", port=5435, dbname="faraday", user="faraday", password="faraday")
    cur = conn.cursor()
    cur.execute("SELECT external_id, name, host_id FROM vulnerability WHERE external_id LIKE '%asm-%';")
    rows = cur.fetchall()
    print(f"Total asm vulns in Faraday: {len(rows)}")
    with open("faraday_asm_vulns.txt", "w") as f:
        for r in rows:
            f.write(f"{r}\n")
except Exception as e:
    print(f"Error: {e}")
