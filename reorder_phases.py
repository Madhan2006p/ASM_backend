import re

with open('/home/madhan/Desktop/ASM-New/integrated_backend/attacksurface/services.py', 'r') as f:
    content = f.read()

# I will just write a specific script that reads the chunks based on known comments.
# Then I'll stitch them back together in the new order.
# Or simpler: I will use sed/awk/python to just replace the whole run_full_scan function?
# The function is lines 1500 to 2100. Let's just output the whole new function.

