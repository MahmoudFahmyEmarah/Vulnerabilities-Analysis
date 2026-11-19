"""Launcher for hosting the dashboard as a Cloudera Machine Learning (CML) Application.

In CML: Applications -> New Application -> Script: cml_app.py
CML gives the application a port in CDSW_APP_PORT and proxies it; the app must listen
on 127.0.0.1 at that port. Outside CML this starts the app on port 8100.
"""
import os
import subprocess
import sys

try:
    project_dir = os.path.dirname(os.path.abspath(__file__))
except NameError:  # CML can run the script without __file__; it starts in the project folder
    project_dir = os.getcwd()

port = os.environ.get("CDSW_APP_PORT", "8100")
subprocess.run(
    [sys.executable, "-m", "streamlit", "run", "app.py",
     "--server.port", port,
     "--server.address", "127.0.0.1",
     "--server.headless", "true",
     "--browser.gatherUsageStats", "false"],
    cwd=project_dir,
    check=True,
)
