# coding=utf-8
import os

from core import HackingTool
from core import HackingToolsCollection
from core.utils import run_command


class TheFatRat(HackingTool):
    TITLE = "The FatRat"
    DESCRIPTION = "TheFatRat Provides An Easy way to create Backdoors and \n" \
                  "Payload which can bypass most anti-virus"
    INSTALL_COMMANDS = [
        dict(cmd="sudo git clone https://github.com/Screetsec/TheFatRat.git"),
        dict(cmd="sudo chmod +x setup.sh", cwd="TheFatRat"),
    ]
    RUN_COMMANDS = ["cd TheFatRat && sudo bash setup.sh"]
    PROJECT_URL = "https://github.com/Screetsec/TheFatRat"

    def __init__(self):
        super(TheFatRat, self).__init__([('Update', self.update),
                                         ('Troubleshoot', self.troubleshoot)])

    def update(self):
        run_command("bash update && chmod +x setup.sh", cwd="TheFatRat")
        run_command("bash setup.sh", cwd="TheFatRat")

    def troubleshoot(self):
        run_command("sudo chmod +x chk_tools", cwd="TheFatRat")
        run_command("./chk_tools", cwd="TheFatRat")


class Brutal(HackingTool):
    TITLE = "Brutal"
    DESCRIPTION = "Brutal is a toolkit to quickly create various payload," \
                  "powershell attack,\nvirus attack and launch listener for " \
                  "a Human Interface Device"
    INSTALL_COMMANDS = [
        dict(cmd="sudo git clone https://github.com/Screetsec/Brutal.git"),
        dict(cmd="sudo chmod +x Brutal.sh", cwd="Brutal"),
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo bash Brutal.sh", cwd="Brutal"),
    ]
    PROJECT_URL = "https://github.com/Screetsec/Brutal"

    def show_info(self):
        super(Brutal, self).show_info()
        print("""
        [!] Requirement
            >> Arduino Software (I used v1.6.7)
            >> TeensyDuino
            >> Linux udev rules
            >> Copy and paste the PaensyLib folder inside your Arduino\libraries
    
        [!] Kindly Visit below link for Installation for Arduino 
            >> https://github.com/Screetsec/Brutal/wiki/Install-Requirements 
        """)


class Stitch(HackingTool):
    TITLE = "Stitch"
    DESCRIPTION = "Stitch is Cross Platform Python Remote Administrator Tool\n\t" \
                  "[!] Refer Below Link For Wins & MAc Os"
    INSTALL_COMMANDS = [
        dict(cmd="sudo git clone https://github.com/nathanlopez/Stitch.git"),
        dict(cmd="sudo pip install -r lnx_requirements.txt", cwd="Stitch")
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo python main.py", cwd="Stitch"),
    ]
    PROJECT_URL = "https://nathanlopez.github.io/Stitch"


class MSFVenom(HackingTool):
    TITLE = "MSFvenom Payload Creator"
    DESCRIPTION = "MSFvenom Payload Creator (MSFPC) is a wrapper to generate \n" \
                  "multiple types of payloads, based on users choice.\n" \
                  "The idea is to be as simple as possible (only requiring " \
                  "one input) \nto produce their payload."
    INSTALL_COMMANDS = [
        dict(cmd="sudo git clone https://github.com/g0tmi1k/msfpc.git"),
        dict(cdm="sudo chmod +x msfpc.sh", cwd="msfpc"),
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo bash msfpc.sh -h -v", cwd="msfpc"),
    ]
    PROJECT_URL = "https://github.com/g0tmi1k/msfpc"


class Venom(HackingTool):
    TITLE = "Venom Shellcode Generator"
    DESCRIPTION = "venom 1.0.11 (malicious_server) was build to take " \
                  "advantage of \n apache2 webserver to deliver payloads " \
                  "(LAN) using a fake webpage writen in html"
    INSTALL_COMMANDS = [
        dict(cmd="sudo git clone https://github.com/r00t-3xp10it/venom.git"),
        dict(cmd="sudo chmod -R 775 venom*/"),
        dict(cmd="sudo bash setup.sh", cwd="venom/aux"),
        dict(cmd="sudo ./venom.sh -u"),
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo ./venom.sh", cwd="venom"),
    ]
    PROJECT_URL = "https://github.com/r00t-3xp10it/venom"


class Spycam(HackingTool):
    TITLE = "Spycam"
    DESCRIPTION = "Script to generate a Win32 payload that takes the webcam " \
                  "image every 1 minute and send it to the attacker"
    INSTALL_COMMANDS = [
<<<<<<< HEAD
        dict(
            cmd="sudo git clone https://github.com/thelinuxchoice/spycam.git"),
        dict(cmd="bash install.sh", cwd="spycam"),
        dict(cmd="chmod +x spycam", cwd="spycam"),
    ]
    RUN_COMMANDS = [
        dict(cmd="./spycam", cwd="spycam"),
    ]
    PROJECT_URL = "https://github.com/thelinuxchoice/spycam"
=======
        "sudo git clone https://github.com/indexnotfound404/spycam.git",
        "cd spycam && bash install.sh && chmod +x spycam"
    ]
    RUN_COMMANDS = ["cd spycam && ./spycam"]
    PROJECT_URL = "https://github.com/indexnotfound404/spycam"
>>>>>>> master


class MobDroid(HackingTool):
    TITLE = "Mob-Droid"
    DESCRIPTION = "Mob-Droid helps you to generate metasploit payloads in " \
                  "easy way\n without typing long commands and save your time"
    INSTALL_COMMANDS = [
        dict(cmd="git clone https://github.com/kinghacker0/mob-droid.git"),
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo python mob-droid.py", cwd="mob-droid"),
    ]
    PROJECT_URL = "https://github.com/kinghacker0/Mob-Droid"


class Enigma(HackingTool):
    TITLE = "Enigma"
    DESCRIPTION = "Enigma is a Multiplatform payload dropper"
    INSTALL_COMMANDS = [
        dict(cmd="sudo git clone https://github.com/UndeadSec/Enigma.git"),
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo python enigma.py", cwd="Enigma"),
    ]
    PROJECT_URL = "https://github.com/UndeadSec/Enigma"


class PayloadCreatorTools(HackingToolsCollection):
    TITLE = "Payload creation tools"
    TOOLS = [
        TheFatRat(),
        Brutal(),
        Stitch(),
        MSFVenom(),
        Venom(),
        Spycam(),
        MobDroid(),
        Enigma()
    ]
