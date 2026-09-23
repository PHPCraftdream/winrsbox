#!/usr/bin/env python3
"""DBWIN OutputDebugString capture — same-session, no admin, no DebugView needed.

hook.dll's fail_log() writes IPC-failure diagnostics via OutputDebugStringW
only (the IPC pipe that would carry a JSONL event is exactly what's down on
that path). This script implements the classic DBWIN_BUFFER protocol
(DebugView's own mechanism) to capture those strings live.

Usage: python winrsbox/scripts/dbgcap.py [--filter TEXT] [--out FILE]
Ctrl+C to stop. Prints "[pid] message" per line; --out also appends to a file.
"""
import argparse
import ctypes
from ctypes import wintypes
import datetime
import sys

k32 = ctypes.windll.kernel32

INVALID_HANDLE_VALUE = wintypes.HANDLE(-1)
PAGE_READWRITE = 0x04
FILE_MAP_READ = 0x0004
WAIT_OBJECT_0 = 0x0
WAIT_TIMEOUT = 0x102
BUF_SIZE = 4096
MSG_VIEW_SIZE = 512

k32.CreateEventW.restype = wintypes.HANDLE
k32.CreateFileMappingW.restype = wintypes.HANDLE
k32.MapViewOfFile.restype = wintypes.LPVOID


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--filter", default="", help="only print lines containing this substring")
    ap.add_argument("--out", default="", help="also append captured lines to this file")
    args = ap.parse_args()

    ev_buffer_ready = k32.CreateEventW(None, False, False, "DBWIN_BUFFER_READY")
    if not ev_buffer_ready:
        sys.exit(f"CreateEvent(DBWIN_BUFFER_READY) failed: {ctypes.get_last_error()}")
    ev_data_ready = k32.CreateEventW(None, False, False, "DBWIN_DATA_READY")
    if not ev_data_ready:
        sys.exit(f"CreateEvent(DBWIN_DATA_READY) failed: {ctypes.get_last_error()}")
    h_map = k32.CreateFileMappingW(INVALID_HANDLE_VALUE, None, PAGE_READWRITE, 0, BUF_SIZE, "DBWIN_BUFFER")
    if not h_map:
        sys.exit(f"CreateFileMapping(DBWIN_BUFFER) failed: {ctypes.get_last_error()}")
    p_buf = k32.MapViewOfFile(h_map, FILE_MAP_READ, 0, 0, MSG_VIEW_SIZE)
    if not p_buf:
        sys.exit(f"MapViewOfFile failed: {ctypes.get_last_error()}")

    out_fh = open(args.out, "a", encoding="utf-8") if args.out else None
    print("[dbgcap] listening for OutputDebugString(A/W) — Ctrl+C to stop", flush=True)
    k32.SetEvent(ev_buffer_ready)
    try:
        while True:
            rc = k32.WaitForSingleObject(ev_data_ready, 1000)
            if rc == WAIT_TIMEOUT:
                continue
            if rc != WAIT_OBJECT_0:
                break
            pid = ctypes.cast(p_buf, ctypes.POINTER(wintypes.DWORD))[0]
            msg_bytes = ctypes.string_at(p_buf + ctypes.sizeof(wintypes.DWORD), MSG_VIEW_SIZE - 4)
            msg = msg_bytes.split(b"\x00", 1)[0].decode("mbcs", errors="replace")
            k32.SetEvent(ev_buffer_ready)
            if args.filter and args.filter not in msg:
                continue
            line = f"{datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]} [pid {pid}] {msg}"
            print(line, flush=True)
            if out_fh:
                out_fh.write(line + "\n")
                out_fh.flush()
    except KeyboardInterrupt:
        pass
    finally:
        if out_fh:
            out_fh.close()


if __name__ == "__main__":
    main()
