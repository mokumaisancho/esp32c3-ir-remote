#!/usr/bin/env python3
"""Read-only C3 USB/Wi-Fi diagnosis. Downloaded by the stable launcher."""
import glob
import pathlib
import serial
import time
from datetime import datetime

logdir = pathlib.Path.home() / "Library/Logs/esp32c3-ir-remote"
logdir.mkdir(parents=True, exist_ok=True)
log = logdir / ("wifi-trace-" + datetime.now().strftime("%Y%m%dT%H%M%S") + ".log")
def emit(s):
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

emit("WIFI_TRACE_START read_only=true flash=false reset=false")
emit("DO_NOT_PRESS_RESET; detect automatic USB resets separately")
end = time.monotonic() + 75
opened = 0
errors = 0
events = 0
last_ports = None
ser = None
next_open = 0
while time.monotonic() < end:
    now = time.monotonic()
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
                if any(k in line for k in ("WIFI_TRACE", "STA_RETRY", "IR network:", "IR UI ready:",
                                             "wifi:", "rst:", "boot:", "Brownout", "Guru Meditation")):
                    emit("UART " + line[:400])
                    if "WIFI_TRACE" in line:
                        events += 1
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
if not events:
    emit("BLOCKED: no Wi-Fi trace observed; serial path cannot establish STA outcome")
emit("LOCAL_LOG=" + str(log))
