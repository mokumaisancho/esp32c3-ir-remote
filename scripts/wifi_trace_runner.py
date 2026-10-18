#!/usr/bin/env python3
"""Read-only C3 USB/Wi-Fi diagnosis. Downloaded by the stable launcher."""
import glob
import json
import urllib.request
import urllib.error
import re
import pathlib
import serial
import time
from datetime import datetime

logdir = pathlib.Path.home() / "Library/Logs/esp32c3-ir-remote"
logdir.mkdir(parents=True, exist_ok=True)
log = logdir / ("wifi-trace-" + datetime.now().strftime("%Y%m%dT%H%M%S") + ".log")
def emit(s):
    s = datetime.now().astimezone().isoformat(timespec="milliseconds") + " " + s
    print(s, flush=True)
    with log.open("a", encoding="utf-8") as f:
        f.write(s + "\n")
def devices():
    return sorted(set(glob.glob("/dev/cu.usbmodem*") + glob.glob("/dev/cu.usbserial*")))
def open_port(p):
    s = serial.Serial(port=None, baudrate=115200, timeout=0.3, dsrdtr=False, rtscts=False)
    s.dtr = False
    s.rts = False
    s.port = p
    s.open()
    return s

emit("WIFI_TRACE_START read_only=true flash=false reset=false mode=FULL_UART_UNFILTERED")
emit("DO_NOT_PRESS_RESET; detect automatic USB resets separately")
end = time.monotonic() + 75
opened = 0
errors = 0
events = 0
outcomes = []
http_results = []
last_progress = -1
last_ports = None
ser = None
next_open = 0
while time.monotonic() < end:
    now = time.monotonic()
    progress = int(end-now)
    if progress // 10 != last_progress and progress >= 0:
        last_progress = progress // 10
        emit("PROGRESS remaining_seconds=%d" % progress)
    ports = devices()
    if ports != last_ports:
        emit("USB_PORTS=" + repr(ports))
        last_ports = ports
    if ser is None and ports and now >= next_open:
        if opened >= 2:
            emit("STOP_SERIAL_REOPEN_LIMIT")
            break
        p = next((x for x in ports if "usbmodem" in x), ports[0])
        try:
            ser = open_port(p)
            opened += 1
            emit(f"SERIAL_OPEN count={opened} port={p}")
        except (serial.SerialException, OSError) as ex:
            emit(f"SERIAL_OPEN_ERROR {type(ex).__name__}: {ex}")
            next_open = now + 8
    if ser:
        try:
            raw = ser.readline()
            if raw:
                line = raw.decode("utf-8", "replace").strip()
                # Complete UART output. Do not filter by prefix or truncate.
                emit("UART " + line)
                if "WIFI_TRACE" in line or "WIFI_DIAG_RESULT" in line:
                    events += 1
                if "WIFI_DIAG_RESULT" in line:
                    match = re.search(r"outcome=([A-Z0-9_]+)", line)
                    if match: outcomes.append(match.group(1))
        except (serial.SerialException, OSError) as ex:
            emit(f"SERIAL_INVALID {type(ex).__name__}: {ex}")
            errors += 1
            try: ser.close()
            except Exception: pass
            ser = None
            next_open = time.monotonic() + 8
    time.sleep(0.1)
if ser:
    try: ser.close()
    except Exception: pass
emit(f"RESULT opens={opened} errors={errors} wifi_events={events}")
if outcomes:
    emit("AUTO_DIAG_OUTCOME=" + outcomes[-1] + " source=firmware_event")
else:
    emit("AUTO_DIAG_OUTCOME=UNDETERMINED source=usb_log")
if not events:
    emit("BLOCKED: no Wi-Fi trace observed; serial path cannot establish STA outcome")
# Probe both advertised entrypoints once, without changing Wi-Fi settings.
# Failure to reach the recovery AP from the Mac's current network is not proof
# that the ESP32 AP is down.
http_status = {}
for host in ("esp32-ir.local", "192.168.4.1"):
    for port, path in ((8080, "/api/diagnostics"), (80, "/")):
        key = "%s:%d%s" % (host, port, path)
        try:
            with urllib.request.urlopen("http://%s:%d%s" % (host, port, path), timeout=2) as response:
                raw = response.read(32768)
                http_status[key] = {"http_code": response.status, "bytes": len(raw)}
                if port == 8080 and response.status == 200:
                    try:
                        js = json.loads(raw)
                        if isinstance(js, dict):
                            http_status[key]["connected"] = js.get("sta_connected")
                            http_status[key]["outcome"] = js.get("outcome")
                    except (ValueError, UnicodeDecodeError):
                        pass
        except (urllib.error.URLError, TimeoutError, OSError) as ex:
            http_status[key] = {"error": type(ex).__name__}
emit("HTTP_CHECK=" + json.dumps(http_status, sort_keys=True))
emit("LOCAL_LOG=" + str(log))
result = {"schema": 1, "result": "OBSERVED" if outcomes else "UNDETERMINED", "outcome": outcomes[-1] if outcomes else None, "uart_events": events, "serial_open_count": opened, "serial_errors": errors, "log_path": str(log), "firmware_diagnostic_seen": bool(outcomes), "http_checks": http_status}
receipt = log.with_suffix(".json")
receipt.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
emit("JSON_RECEIPT=" + str(receipt))
