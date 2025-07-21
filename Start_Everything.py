#!/usr/bin/env python3
import time
import subprocess
import sys
import os

python_exec = sys.executable

# Start tunnelandflask.py in the background
tunnel_proc = subprocess.Popen([python_exec, "tunnelandflask.py"])

# Wait a few seconds to give the server time to start
time.sleep(5)

# Continue with other scripts
subprocess.run([python_exec, "fb_registration.py"])
controller = subprocess.Popen([python_exec, "controller.py"])

# Optional: Wait for tunnelandflask.py to finish at the end
# tunnel_proc.wait()
try:
    input("🔄 Server is running. Press Enter to stop it...\n")
except KeyboardInterrupt:
    print("🛑 Terminating server...")
else:
    print("🛑 Terminating server...")
finally:
    tunnel_proc.terminate()
    tunnel_proc.wait()
    controller.terminate()
    controller.wait()
    print("✅ Server terminated.")