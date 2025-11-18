# logger.py
from datetime import datetime


def log(level: str, message: str):
    COLORS = {"ERROR": "\033[91m", "SUCCESS": "\033[92m", "INFO": "\033[94m"}
    RESET = "\033[0m"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    color = COLORS.get(level.upper(), "")
    print(f"{color}[{timestamp}] [{level.upper()}] {message}{RESET}")
