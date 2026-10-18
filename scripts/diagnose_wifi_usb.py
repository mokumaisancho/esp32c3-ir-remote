#!/usr/bin/env python3
"""Read-only ESP32-C3 USB/STA/AP diagnostic; no reset, flashing or Wi-Fi changes."""
import glob
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request
from datetime import datetime

DURATION = int(os.environ.get("IR_DIAG_SECONDS", "55"))
LOGDIR = Path.home() / "Library/Logs/esp32c3-ir-remote"
LOGDIR.mkdir(parents=True, exist_ok=True)
LOG = LOGDIR / ("wifi-diagnostic-" + datetime.now().strftime("%Y%m%dT%H%M%S") + ".log")
REPO = "mokumaisancho/esp32c3-ir-remote"
BASE = Path.home() / "Library/Application Support/ESP Hardware Dev Console"
SENSITIVE = re.compile(r"(?i)(password|token|secret|api[_-]?key)\s*[:=]\s*[^\s,]+")
sta_ip = None

def emit(msg):
    msg = SENSITIVE.sub(r"\1=[REDACTED]", str(msg))
    print(msg, flush=True)
    with LOG.open("a", encoding="utf-8") as f: f.write(msg + "\n")

def run(cmd, timeout=5, env=None):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except Exception as exc:
        return type("Result", (), {"returncode": -1, "stdout": "", "stderr": repr(exc)})()

def choose_python():
    for path in [BASE / "repo/.venv/bin/python", BASE / "repo/venv/bin/python",
                 BASE / ".venv/bin/python", Path(sys.executable)]:
        if path.exists() and run([str(path), "-c", "import serial"], timeout=4).returncode == 0:
            return str(path)
    return None

def usb_devices():
    return sorted(set(sum((glob.glob(pattern) for pattern in
        ("/dev/cu.usbmodem*", "/dev/cu.usbserial*", "/dev/cu.wchusbserial*", "/dev/cu.SLAB_USBtoUART*")), [])))

def probe_http(addr):
    url = "http://" + addr + "/api/status"
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(url, timeout=2) as response:
            data = json.loads(response.read(8192).decode("utf-8"))
        if isinstance(data, dict) and data.get("profile") and "sta_connected" in data:
            emit("HTTP_OK " + addr + " " + json.dumps(
                {k:data.get(k) for k in ("wifi_phase","sta_connected","sta_ip","sta_status",
                        "sta_retry_count","setup_ap_ready","setup_ap_ip","mdns_ready")}, ensure_ascii=False))
            return data
        emit("HTTP_UNEXPECTED " + addr)
    except Exception as exc:
        emit("HTTP_FAIL " + addr + " " + type(exc).__name__ + ": " + str(exc)[:200])
    return None

def main():
    global sta_ip
    emit("DIAGNOSTIC_START " + datetime.now().isoformat())
    emit("READ_ONLY=true RESET=false FLASH=false")
    emit("MAC_NETWORK " + run(["/sbin/route", "-n", "get", "default"]).stdout.strip()[-350:])
    emit("MAC_USB_PORTS " + repr(usb_devices()))
    py = choose_python()
    if not py:
        emit("BLOCKED: no existing Python with pyserial")
        return 2
    if sys.executable != py:
        os.execv(py, [py, __file__])
    import serial
    last_ports = None
    serial_obj = None
    next_http = 0
    next_try = 0
    lines = 0
    deadline = time.monotonic() + DURATION
    while time.monotonic() < deadline:
        ports = usb_devices()
        if ports != last_ports:
            emit("USB_ENUMERATION " + repr(ports))
            last_ports = ports
        if serial_obj is None and ports and time.monotonic() >= next_try:
            target = next((p for p in ports if "usbmodem" in p), ports[0])
            try:
                serial_obj = serial.Serial(target, 115200, timeout=0.3, dsrdtr=False, rtscts=False)
                # Avoid programmatically toggling reset/boot pins.
                emit("SERIAL_OPEN " + target)
            except Exception as exc:
                emit("SERIAL_OPEN_FAILED " + type(exc).__name__ + " " + str(exc)[:200])
                next_try = time.monotonic() + 2
        if serial_obj:
            try:
                raw = serial_obj.readline()
                if raw:
                    line = raw.decode("utf-8", errors="replace").strip()
                    emit("UART " + line[:500])
                    lines += 1
                    match = re.search(r"STA=[^\s]+\s+\((\d+\.\d+\.\d+\.\d+)\)", line)
                    if match and match.group(1) != "0.0.0.0": sta_ip = match.group(1)
            except (serial.SerialException, OSError) as exc:
                emit("SERIAL_READ_LOST " + type(exc).__name__ + " " + str(exc)[:200])
                try: serial_obj.close()
                except Exception: pass
                serial_obj = None
                next_try = time.monotonic() + 1
        if time.monotonic() >= next_http:
            for host in [sta_ip, "esp32-ir.local"]:
                if host:
                    data = probe_http(host)
                    if data and data.get("sta_ip"): sta_ip = data["sta_ip"]
            next_http = time.monotonic() + 12
        time.sleep(0.1)
    if serial_obj:
        try: serial_obj.close()
        except Exception: pass
    emit("DIAGNOSTIC_END UART_LINES=" + str(lines) + " STA_IP=" + str(sta_ip))
    emit("LOG_FILE=" + str(LOG))
    # Upload summary of non-secret state, not raw UART lines which may contain credentials.
    lines_list = LOG.read_text(encoding="utf-8").splitlines()
    safe = [s for s in lines_list if not s.startswith("UART ") and not s.startswith("MAC_NETWORK ")]
    body = "## Wi-Fi / USB read-only diagnostic\n\n" + "\n".join("    " + s for s in safe[-85:])
    env = dict(os.environ)
    env.pop("GH_TOKEN", None); env.pop("GITHUB_TOKEN", None)
    check = run(["gh", "auth", "status"], timeout=7, env=env)
    if check.returncode == 0:
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".md", delete=False) as f:
            f.write(body + "\n"); tempname = f.name
        sent = run(["gh","issue","comment","1","-R",REPO,"--body-file",tempname], timeout=15, env=env)
        os.unlink(tempname)
        emit("GITHUB_RECEIPT=" + ("PASS" if sent.returncode == 0 else "FAILED"))
    else:
        emit("GITHUB_RECEIPT=SKIPPED_AUTH; local log retained")
    return 0

if __name__ == "__main__":
    sys.exit(main())
