# coding=utf-8
from core import HackingTool
from core import HackingToolsCollection


class WifiJammerNG(HackingTool):
    TITLE = "WifiJammer-NG"
    DESCRIPTION = "Continuously jam all wifi clients and access points within range."
    INSTALL_COMMANDS = [
        dict(cmd=
             "sudo git clone https://github.com/MisterBianco/wifijammer-ng.git"
             ),
        dict(cmd="sudo pip3 install -r requirements.txt", cwd="wifijammer-ng")
    ]
    RUN_COMMANDS = [
        dict(cmd='''
        echo "python wifijammer.py [-a AP MAC] [-c CHANNEL] [-d] [-i INTERFACE] 
        [-m MAXIMUM] [-k] [-p PACKETS] [-s SKIP] [-t TIME INTERVAL] [-D]"| boxes | lolcat
        '''),
        dict(cmd="sudo python3 wifijammer.py", cwd="wifijammer-ng")
    ]
    PROJECT_URL = "https://github.com/MisterBianco/wifijammer-ng"


class KawaiiDeauther(HackingTool):
    TITLE = "KawaiiDeauther"
    DESCRIPTION = "Kawaii Deauther is a pentest toolkit whose goal is to perform \n " \
                  "jam on WiFi clients/routers and spam many fake AP for testing purposes."
    INSTALL_COMMANDS = [
        dict(
            cmd="sudo git clone https://github.com/aryanrtm/KawaiiDeauther.git"
        ),
        dict(cmd="sudo bash install.sh", cwd="KawaiiDeauther")
    ]
    RUN_COMMANDS = [
        dict(cmd="sudo KawaiiDeauther.sh", cwd="KawaiiDeauther"),
    ]
    PROJECT_URL = "https://github.com/aryanrtm/KawaiiDeauther"


class WifiJammingTools(HackingToolsCollection):
    TITLE = "Wifi Deauthenticate"
    TOOLS = [WifiJammerNG(), KawaiiDeauther()]
