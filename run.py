#!/usr/bin/env python3
"""Startup script for Ares backend."""
import subprocess
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).parent / "backend"


def main():
    subprocess.run(
        [sys.executable, "-m", "uvicorn", "main:app", "--reload", "--port", "8000"],
        cwd=BACKEND_DIR,
    )


if __name__ == "__main__":
    main()
