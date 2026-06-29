"""
Minimal repro for os error 4395 (STATUS_REPARSE_POINT_ENCOUNTERED)
during removal of pywin32-311.data directory.

Run inside the sandbox:
  winrsbox.exe --cwd <project_root> -- python repro_rmdir.py

Expected (bug present): exits 1 with os error 4395
Expected (bug fixed):   exits 0
"""
import shutil
import sys
import os

DATA_DIR = r"C:\users\computer\appdata\local\hermes\hermes-agent\venv\Lib\site-packages\pywin32-311.data"

def main():
    print(f"[repro] Target: {DATA_DIR}")
    print(f"[repro] Exists: {os.path.exists(DATA_DIR)}")

    if not os.path.exists(DATA_DIR):
        print("[repro] SKIP: directory does not exist (sandbox not pre-seeded)")
        sys.exit(0)

    # Walk the tree and report any reparse points
    for root, dirs, files in os.walk(DATA_DIR):
        for name in dirs + files:
            fullpath = os.path.join(root, name)
            try:
                st = os.lstat(fullpath)
                attrs = getattr(st, 'st_file_attributes', 0)
                is_reparse = bool(attrs & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT
                print(f"[repro]   {fullpath}  attrs=0x{attrs:x}  reparse={is_reparse}")
            except Exception as e:
                print(f"[repro]   {fullpath}  ERROR: {e}")

    print(f"[repro] Attempting shutil.rmtree({DATA_DIR!r})")
    try:
        shutil.rmtree(DATA_DIR)
        print("[repro] SUCCESS: rmtree completed without error")
        sys.exit(0)
    except OSError as e:
        print(f"[repro] FAIL: {e}")
        print(f"[repro] errno={e.errno}  winerror={getattr(e, 'winerror', None)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
