# coding=utf-8
import os

from core import HackingTool
from core import HackingToolsCollection
from core.utils import run_command


class WIFIPumpkin(HackingTool):
    TITLE = "WiFi-Pumpkin"
    DESCRIPTION = "The WiFi-Pumpkin is a rogue AP framework to easily create " \
                  "these fake networks\n" \
                  "all while forwarding legitimate traffic to and from the " \
                  "unsuspecting target."
    INSTALL_COMMANDS = [
        dict(cmd="sudo apt install libssl-dev libffi-dev build-essential"),
        dict(cmd="sudo git clone https://github.com/P0cL4bs/wifipumpkin3.git"),
        dict(cmd="chmod -R 755 wifipumpkin3 && cd wifipumpkin3"),
        dict(cmd="sudo apt install python3-pyqt5"),
        dict(cmd="sudo python3 setup.py install"),
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo wifipumpkin3"),
    ]
    PROJECT_URL = "https://github.com/P0cL4bs/wifipumpkin3"


class pixiewps(HackingTool):
    TITLE = "pixiewps"
    DESCRIPTION = "Pixiewps is a tool written in C used to bruteforce offline " \
                  "the WPS pin\n " \
                  "exploiting the low or non-existing entropy of some Access " \
                  "Points, the so-called pixie dust attack"
    INSTALL_COMMANDS = [
        dict(cmd="sudo git clone https://github.com/wiire/pixiewps.git"),
        dict(cmd="sudo apt-get -y install build-essential"),
        dict(cmd="make", cwd="pixiewps"),
        dict(cmd="sudo make install", cwd="pixiewps"),
        dict(cmd="wget https://pastebin.com/y9Dk1Wjh", cwd="pixiewps"),
    ]
    PROJECT_URL = "https://github.com/wiire/pixiewps"

    def run(self):
        run_command(
            'echo "'
            '1.> Put your interface into monitor mode using '
            '\'airmon-ng start {wireless interface}\n'
            '2.> wash -i {monitor-interface like mon0}\'\n'
            '3.> reaver -i {monitor interface} -b {BSSID of router} -c {router channel} -vvv -K 1 -f"'
            '| boxes -d boy')
        print("You Have To Run Manually By USing >>pixiewps -h ")


class BluePot(HackingTool):
    TITLE = "Bluetooth Honeypot GUI Framework"
    DESCRIPTION = "You need to have at least 1 bluetooh receiver " \
                  "(if you have many it will work with those, too).\n" \
                  "You must install/libbluetooth-dev on " \
                  "Ubuntu/bluez-libs-devel on Fedora/bluez-devel on openSUSE"
    INSTALL_COMMANDS = [
        dict(
            cmd=
            "wget https://github.com/andrewmichaelsmith/bluepot/raw/master/bin/bluepot-0.1.tar.gz"
        ),
        dict(cmd="tar xfz bluepot-0.1.tar.gz"),
        dict(cmd="sudo java -jar bluepot/BluePot-0.1.jar"),
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo java -jar bluepot/BluePot-0.1.jar", cwd="bluepot-0.1"),
    ]
    PROJECT_URL = "https://github.com/andrewmichaelsmith/bluepot"


class Fluxion(HackingTool):
    TITLE = "Fluxion"
    DESCRIPTION = "Fluxion is a wifi key cracker using evil twin attack..\n" \
                  "you need a wireless adaptor for this tool"
    INSTALL_COMMANDS = [
        dict(cmd="git clone https://github.com/thehackingsage/Fluxion.git"),
        dict(cmd="sudo chmod +x install.sh", cwd="Fluxion/install"),
        dict(cmd="sudo bash install.sh", cwd="Fluxion/install"),
        dict(cmd="sudo chmod +x fluxion.sh", cwd="Fluxion"),
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo bash fluxion.sh", cwd="Fluxion"),
    ]
    PROJECT_URL = "https://github.com/thehackingsage/Fluxion"


class Wifiphisher(HackingTool):
    TITLE = "Wifiphisher"
    DESCRIPTION = """
        Wifiphisher is a rogue Access Point framework for conducting red team engagements or Wi-Fi security testing. 
        Using Wifiphisher, penetration testers can easily achieve a man-in-the-middle position against wireless clients by performing 
        targeted Wi-Fi association attacks. Wifiphisher can be further used to mount victim-customized web phishing attacks against the
        connected clients in order to capture credentials (e.g. from third party login pages or WPA/WPA2 Pre-Shared Keys) or infect the 
        victim stations with malware..\n
        For More Details Visit >> https://github.com/wifiphisher/wifiphisher
    """
    INSTALL_COMMANDS = [
        dict(cmd="git clone https://github.com/wifiphisher/wifiphisher.git"),
        dict(cmd="sudo python3 setup.py install", cwd="wifiphisher"),
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo wifiphisher", cwd="wifiphisher"),
    ]
    PROJECT_URL = "https://github.com/wifiphisher/wifiphisher"


class Wifite(HackingTool):
    TITLE = "Wifite"
    INSTALL_COMMANDS = [
        dict(cmd="sudo git clone https://github.com/derv82/wifite2.git"),
        dict(cmd="sudo python3 setup.py install", cwd="wifite2"),
        dict(cmd="sudo pip3 install -r requirements.txt", cwd="wifite2"),
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo wifite", cwd="wifite2"),
    ]
    PROJECT_URL = "https://github.com/derv82/wifite2"


class EvilTwin(HackingTool):
    TITLE = "EvilTwin"
    DESCRIPTION = "Fakeap is a script to perform Evil Twin Attack, by getting" \
                  " credentials using a Fake page and Fake Access Point"
    INSTALL_COMMANDS = [
        dict(cmd="sudo git clone https://github.com/Z4nzu/fakeap.git"),
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo bash fakeap.sh", cwd="fakeap"),
    ]
    PROJECT_URL = "https://github.com/Z4nzu/fakeap"


class Fastssh(HackingTool):
    TITLE = "Fastssh"
    DESCRIPTION = "Fastssh is an Shell Script to perform multi-threaded scan" \
                  " \n and brute force attack against SSH protocol using the " \
                  "most commonly credentials."
    INSTALL_COMMANDS = [
        dict(cmd="sudo git clone https://github.com/Z4nzu/fastssh.git"),
        dict(cmd="sudo chmod +x fastssh.sh", cwd="fastssh"),
        dict(cmd="sudo apt-get install -y sshpass netcat"),
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo bash fastssh.sh --scan", cwd="fastssh"),
    ]
    PROJECT_URL = "https://github.com/Z4nzu/fastssh"


class Howmanypeople(HackingTool):
    TITLE = "Howmanypeople"
    DESCRIPTION = "Count the number of people around you by monitoring wifi " \
                  "signals.\n" \
                  "[@] WIFI ADAPTER REQUIRED* \n[*]" \
                  "It may be illegal to monitor networks for MAC addresses, \n" \
                  "especially on networks that you do not own. " \
                  "Please check your country's laws"
    INSTALL_COMMANDS = [
        dict(cmd="sudo apt-get install tshark"),
        dict(cmd="sudo python3 -m pip install howmanypeoplearearound"),
    ]
    RUN_COMMANDS = [
        dict(cmd="howmanypeoplearearound"),
    ]


class WirelessAttackTools(HackingToolsCollection):
    TITLE = "Wireless attack tools"
    DESCRIPTION = ""
    TOOLS = [
        WIFIPumpkin(),
        pixiewps(),
        BluePot(),
        Fluxion(),
        Wifiphisher(),
        Wifite(),
        EvilTwin(),
        Fastssh(),
        Howmanypeople()
    ]
