import subprocess
out = subprocess.run(["journalctl", "-u", "celery", "-n", "100", "--no-pager"], capture_output=True, text=True)
print(out.stdout)
