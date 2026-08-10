import subprocess
import json

cmd = ["testssl.sh", "--fast", "-U", "--jsonfile", "/tmp/test.json", "example.com"]
subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

with open("/tmp/test.json") as f:
    data = json.load(f)

for item in data:
    if "cert" in item.get("id", "") or "grade" in item.get("id", "") or "ip" in item.get("id", "") or "cipher" in item.get("id", ""):
        print(f"{item.get('id')}: {item.get('finding')}")
