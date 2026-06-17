import requests
res = requests.post("http://localhost:8000/api/scans/quick/", json={"domain": "hackersinfotech.com"}, headers={"Authorization": "Bearer ..."})
# Actually, I don't have the auth token.
