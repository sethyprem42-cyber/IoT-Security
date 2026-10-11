# Virtual Security Simulator

A local Streamlit application for practicing cybersecurity monitoring with
synthetic events and virtual devices. It stores device inventory, events, and
alerts in a local SQLite database.

> **Important:** This is an educational simulator. It does not capture network
> traffic, inspect or control physical devices, block connections, or provide
> production security protection.

## Requirements

- Python 3.10 or newer
- pip

## Run on Windows

Open PowerShell in the project directory and run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
py -m streamlit run app.py
```

Open the local URL printed in the terminal (usually
`http://localhost:8501`). Keep the terminal open while using the dashboard.
Press `Ctrl+C` in the terminal to stop the server.

If PowerShell blocks environment activation, skip activation and use the Python
launcher directly:

```powershell
py -m pip install -r requirements.txt
py -m streamlit run app.py
```

## Run on macOS or Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

## Features

- Overview of virtual device status, events, and alert severity.
- Add virtual devices using validated IPv4 addresses and change their status.
- Generate normal telemetry, failed logins, traffic spikes, and unknown
  destinations for a selected online device.
- Adjust the failed-login count and simulated packet-size thresholds.
- See immediate feedback after each simulation, including generated security
  alerts and confirmation that the event was saved.
- Automatically record and classify synthetic events and alerts in SQLite.
- Review and filter the complete event history and download it as CSV.
- Acknowledge pending alerts.

The default SQLite database is created in the `data` folder when the app first
runs. Database files are intentionally excluded from Git; each local
installation keeps its own event history.

Normal telemetry is recorded without generating a security alert when it is
within policy. Simulated failed logins, traffic spikes that exceed the selected
packet-size limit, and unknown destinations generate alerts.

## Run tests

Install the app dependencies, then run:

```powershell
py -m unittest discover -s tests -v
```

Tests use temporary databases and do not modify your local dashboard database.

## Project files

- `app.py` — Streamlit user interface.
- `security_core.py` — SQLite persistence, input validation, and detection rules.
- `tests/` — isolated unit tests for the persistence and detection logic.
- `.github/workflows/tests.yml` — automated tests on pushes and pull requests.

## GitHub

The public source repository is hosted on
[GitHub](https://github.com/sethyprem42-cyber/IoT-Security).
