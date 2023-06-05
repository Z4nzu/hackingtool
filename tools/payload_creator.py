import os

from core import HackingTool
from core import HackingToolsCollection


class TheFatRat(HackingTool):
    TITLE = "The FatRat"
    DESCRIPTION = "TheFatRat Provides An Easy way to create Backdoors and \n" \
                  "Payload which can bypass most anti-virus"
    INSTALL_COMMANDS = [
        "sudo git clone https://github.com/Screetsec/TheFatRat.git",
        "cd TheFatRat && sudo chmod +x setup.sh"
    ]
    RUN_COMMANDS = ["cd TheFatRat && sudo bash setup.sh"]
    PROJECT_URL = "https://github.com/Screetsec/TheFatRat"

    def __init__(self):
        super(TheFatRat, self).__init__([
            ('Update', self.update),
            ('Troubleshoot', self.troubleshoot)
        ])

    def update(self):
        os.system(
            "cd TheFatRat && bash update && chmod +x setup.sh && bash setup.sh")

    def troubleshoot(self):
        os.system("cd TheFatRat && sudo chmod +x chk_tools && ./chk_tools")


class Brutal(HackingTool):
    TITLE = "Brutal"
    DESCRIPTION = "Brutal is a toolkit to quickly create various payload," \
                  "powershell attack,\nvirus attack and launch listener for " \
                  "a Human Interface Device"
    INSTALL_COMMANDS = [
        "sudo git clone https://github.com/Screetsec/Brutal.git",
        "cd Brutal && sudo chmod +x Brutal.sh"
    ]
    RUN_COMMANDS = ["cd Brutal && sudo bash Brutal.sh"]
    PROJECT_URL = "https://github.com/Screetsec/Brutal"

    def show_info(self):
        super(Brutal, self).show_info()
        print("""
        [!] Requirement
            >> Arduino Software (I used v1.6.7)
            >> TeensyDuino
            >> Linux udev rules
            >> Copy and paste the PaensyLib folder inside your Arduino libraries
    
        [!] Kindly Visit below link for Installation for Arduino 
            >> https://github.com/Screetsec/Brutal/wiki/Install-Requirements 
        """)


class Stitch(HackingTool):
    TITLE = "Stitch"
    DESCRIPTION = "Stitch is Cross Platform Python Remote Administrator Tool\n\t" \
                  "[!] Refer Below Link For Wins & MAc Os"
    INSTALL_COMMANDS = [
        "sudo git clone https://github.com/nathanlopez/Stitch.git",
        "cd Stitch && sudo pip install -r lnx_requirements.txt"
    ]
    RUN_COMMANDS = ["cd Stitch && sudo python main.py"]
    PROJECT_URL = "https://nathanlopez.github.io/Stitch"


class MSFVenom(HackingTool):
    TITLE = "MSFvenom Payload Creator"
    DESCRIPTION = "MSFvenom Payload Creator (MSFPC) is a wrapper to generate \n" \
                  "multiple types of payloads, based on users choice.\n" \
                  "The idea is to be as simple as possible (only requiring " \
                  "one input) \nto produce their payload."
    INSTALL_COMMANDS = [
        "sudo git clone https://github.com/g0tmi1k/msfpc.git",
        "cd msfpc;sudo chmod +x msfpc.sh"
    ]
    RUN_COMMANDS = ["cd msfpc;sudo bash msfpc.sh -h -v"]
    PROJECT_URL = "https://github.com/g0tmi1k/msfpc"


class Venom(HackingTool):
    TITLE = "Venom Shellcode Generator"
    DESCRIPTION = "venom 1.0.11 (malicious_server) was build to take " \
                  "advantage of \n apache2 webserver to deliver payloads " \
                  "(LAN) using a fake webpage written in html"
    INSTALL_COMMANDS = [
        "sudo git clone https://github.com/r00t-3xp10it/venom.git",
        "sudo chmod -R 775 venom*/ && cd venom*/ && cd aux && sudo bash setup.sh",
        "sudo ./venom.sh -u"
    ]
    RUN_COMMANDS = ["cd venom && sudo ./venom.sh"]
    PROJECT_URL = "https://github.com/r00t-3xp10it/venom"


class Spycam(HackingTool):
    TITLE = "Spycam"
    DESCRIPTION = "Script to generate a Win32 payload that takes the webcam " \
                  "image every 1 minute and send it to the attacker"
    INSTALL_COMMANDS = [
        "sudo git clone https://github.com/indexnotfound404/spycam.git",
        "cd spycam && bash install.sh && chmod +x spycam"
    ]
    RUN_COMMANDS = ["cd spycam && ./spycam"]
    PROJECT_URL = "https://github.com/indexnotfound404/spycam"


class MobDroid(HackingTool):
    TITLE = "Mob-Droid"
    DESCRIPTION = "Mob-Droid helps you to generate metasploit payloads in " \
                  "easy way\n without typing long commands and save your time"
    INSTALL_COMMANDS = [
        "git clone https://github.com/kinghacker0/mob-droid.git"]
    RUN_COMMANDS = ["cd mob-droid;sudo python mob-droid.py"]
    PROJECT_URL = "https://github.com/kinghacker0/Mob-Droid"


class Enigma(HackingTool):
    TITLE = "Enigma"
    DESCRIPTION = "Enigma is a Multiplatform payload dropper"
    INSTALL_COMMANDS = [
        "sudo git clone https://github.com/UndeadSec/Enigma.git"]
    RUN_COMMANDS = ["cd Enigma;sudo python enigma.py"]
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
