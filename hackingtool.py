##!/usr/bin/env python3
# -*- coding: UTF-8 -*-
import os
import sys
import webbrowser
import time
import socket
import requests
from getpass import getpass
from os import path
from platform import system
Logo="""\033[33m

   ▄█    █▄       ▄████████  ▄████████    ▄█   ▄█▄  ▄█  ███▄▄▄▄      ▄██████▄           ███      ▄██████▄   ▄██████▄   ▄█       
  ███    ███     ███    ███ ███    ███   ███ ▄███▀ ███  ███▀▀▀██▄   ███    ███      ▀█████████▄ ███    ███ ███    ███ ███       
  ███    ███     ███    ███ ███    █▀    ███▐██▀   ███▌ ███   ███   ███    █▀          ▀███▀▀██ ███    ███ ███    ███ ███       
 ▄███▄▄▄▄███▄▄   ███    ███ ███         ▄█████▀    ███▌ ███   ███  ▄███                 ███   ▀ ███    ███ ███    ███ ███       
▀▀███▀▀▀▀███▀  ▀███████████ ███        ▀▀█████▄    ███▌ ███   ███ ▀▀███ ████▄           ███     ███    ███ ███    ███ ███       
  ███    ███     ███    ███ ███    █▄    ███▐██▄   ███  ███   ███   ███    ███          ███     ███    ███ ███    ███ ███       
  ███    ███     ███    ███ ███    ███   ███ ▀███▄ ███  ███   ███   ███    ███          ███     ███    ███ ███    ███ ███▌    ▄ 
  ███    █▀      ███    █▀  ████████▀    ███   ▀█▀ █▀    ▀█   █▀    ████████▀          ▄████▀    ▀██████▀   ▀██████▀  █████▄▄██ 
                                         ▀                                                                            ▀                             

                                    \033[97m[!] https://github.com/Z4nzu/hackingtool \n
                                    \033[91m[X] Please Don't Use For illegal Activity [X]
\033[97m """
def menu():
    print(Logo + """\033[0m 
     \033[97m
    [00]AnonSurf                  
    [01]Information Gathering
    [02]Wordlist Generator 
    [03]Wireless Attack
    [04]SQL Injection Tools 
    [05]Phishing Attack 
    [06]Web Attack Tool
    [07]Post exploitation
    [08]Forensic Tools
    [09]Payload Creator
    [10]Exploit Frameworks
    [11]Wifi Jamming
    [12]Ddos Attack Tools 
    [13]SocialMedia Finder 
    [14]XSS Attack Tools
    [15]Steganography
    [16]More Tools 
    [17]Update or Uninstall | Hackingtool
    [99]Exit
    """)
    
    choice = input("Z4nzu  =>> ")
    if choice == "0" or choice == "00":
        clearScr()
        anonsurf()
    elif choice == "1" or choice == "01":
        clearScr()
        info()
    elif choice == "2" or choice == "02":
        clearScr()
        passwd()
    elif choice == "3" or choice == "03":
        clearScr()
        wire()
    elif choice == "4" or choice == "04":
        clearScr()
        sqltool()    
    elif choice == "5" or choice == "05":
        clearScr()
        phishattack()
    elif choice == "6" or choice == "06":
        clearScr()
        webAttack()        
    elif choice == "7" or choice == "07":
        clearScr()
        postexp()
    elif choice == "8" or choice == "08" :
        clearScr()
        forensic()
    elif choice == "9" or choice == "09" :
        clearScr()
        payloads()       
    elif choice == "10":
        clearScr()
        routexp()
    elif choice == "11" :
        clearScr()
        wifijamming()
    elif choice == "12" :
        clearScr()
        Ddos()    
    elif choice == "13" :
        clearScr()
        socialfinder()
    elif choice == "14":
        clearScr()
        xsstools()
    elif choice == "15":
        clearScr()
        steganography()
    elif choice == "16":
        clearScr()
        print(Logo)
        others()
    elif choice == "17":
        clearScr()
        print(Logo)
        update()
    elif choice == "99" :
        print("Happy Hacking...")
        time.sleep(1)
        clearScr()
        sys.exit()
    elif choice == "":
        menu()
    else:
        print("\n ERROR: Wrong Input")
        time.sleep(2)
        menu()

def anonsurf():
    os.system("figlet -f standard -c Anonmously Hiding Tool | lolcat")
    print("""
        [1]  Anonmously Surf
        [2]  Multitor
        [99] Back
    """)
    choice = input("Z4nzu =>>")
    if choice == "1":
        clearScr()
        ansurf()
    elif choice == "2":
        clearScr()
        multitor()
    elif choice == "99":
        menu()
    else :
        menu()

def ansurf():
    os.system("echo \"It automatically overwrites the RAM when\nthe system is shutting down AnD AlSo change Ip. \" |boxes -d boy | lolcat")
    anc=input("[1]install [2]Run [3]Stop [99]Main Menu >> ")
    if anc == "1":
        os.system("sudo git clone https://github.com/Und3rf10w/kali-anonsurf.git")
        os.system("cd kali-anonsurf && sudo ./installer.sh && cd .. && sudo rm -r kali-anonsurf")
        anonsurf()
    elif anc=="2":
        os.system("sudo anonsurf start")
    elif anc == "3":
        os.system("sudo anonsurf stop")
    elif anc == "99":
        anonsurf()
    else :
        menu()

def multitor():
    os.system("echo \"How to stay in multi places at the same time \" | boxes -d boy | lolcat")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/thelinuxchoice/multitor.git")
        anonsurf()
    elif userchoice == "2":
        os.system("cd multitor && bash multitor.sh")
    elif userchoice == "99":
        anonsurf()
    else :
        menu()

def info():
    clearScr()
    os.system("figlet -f standard -c Information Gathering Tools | lolcat")
    print("""
            [1]  Nmap 
            [2]  Dracnmap
            [3]  Port Scanning
            [4]  Host To IP
            [5]  Xerosploit
            [6]  RED HAWK (All In One Scanning)
            [7]  ReconSpider(For All Scaning)
            [8]  IsItDown (Check Website Down/Up)
            [9]  Infoga - Email OSINT
            [10] ReconDog
            [11] Striker
            [12] SecretFinder (like API & etc)
            [13] Find Info Using Shodan
            [14] Port Scanner
            [15] Breacher
            [99] Back To Main Menu 
        """)
    choice2 = input("Z4nzu =>> ")
    if choice2 == "1":
        nmap()
    if choice2 == "2":
        clearScr()
        Dracnmap()
    if choice2 == "3":
        clearScr()
        ports()
    if choice2 == "4":
        clearScr()
        h2ip()
    if choice2 == "5":
        clearScr()
        xerosploit()
    if choice2 == "6":
        clearScr()
        redhawk()
    elif choice2 == "7":
        clearScr()
        reconspider()
    elif choice2 == "8":
        clearScr()
        isitdown()
    elif choice2 == "9":
        clearScr()
        infogaemail()
    elif choice2 == "99":
        clearScr()
        menu()
    elif choice2 == "10":
        clearScr()
        recondog()
    elif choice2 == "11":
        clearScr()
        striker()
    elif choice2 == "12":
        clearScr()
        secretfinder()
    elif choice2 == "13":
        clearScr()
        shodantool()
    elif choice2 == "14":
        clearScr()
        portscanner()
    elif choice2 == "15":
        clearScr()
        breacher()
    elif choice2 == "":
        menu()
    else:
        menu()

def breacher():
    os.system("echo \"An advanced multithreaded admin panel finder written in python.\n Usage : python breacher -u example.com \n\t [!]https://github.com/s0md3v/Breacher \"|boxes -d boy | lolcat")
    choice = input("[1]Install [99]Back >> ")
    if choice == "1":
        os.system("git clone https://github.com/s0md3v/Breacher.git")
        info()
    elif choice == "99":
        info()
    else :
        menu()


def portscanner():
    os.system("echo \"rang3r is a python script which scans in multi thread\n all alive hosts within your range that you specify.\n\t [!]https://github.com/floriankunushevci/rang3r \"|boxes -d boy | lolcat")
    choice = input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("git clone https://github.com/floriankunushevci/rang3r;sudo pip install termcolor")
    elif choice == "2":
        ipinput=input("Enter Ip >> ")
        os.system("cd rang3r;sudo python rang3r.py --ip {0}".format(ipinput))
    elif choice == "99":
        info()
    else :
        menu()

def shodantool():
    os.system("echo \"Get ports,vulnerabilities,informations,banners,..etc \n for any IP with Shodan (no apikey! no rate limit!)\n[X]Don't use this tool because your ip will be blocked by Shodan![X] \n\t [!]https://github.com/m4ll0k/Shodanfy.py \"|boxes -d boy | lolcat")
    choice = input("[1]Install [99]Back >> ")
    if choice == "1":
        os.system("git clone https://github.com/m4ll0k/Shodanfy.py.git")
        info()
    elif choice == "99":
        info()
    else :
        menu()

def isitdown():
    os.system("echo \"Check Website Is Online or Not \"|boxes -d boy | lolcat")
    choice = input("[1]Open [99]Back >> ")
    if choice == "1":
        webbrowser.open_new_tab("https://www.isitdownrightnow.com/")
    elif choice == "99":
        info()
    else :
        menu()

def secretfinder():
    os.system("echo \"SecretFinder - A python script for find sensitive data \nlike apikeys, accesstoken, authorizations, jwt,..etc \n and search anything on javascript files.\n\n Usage: python SecretFinder.py -h \n\t [*]https://github.com/m4ll0k/SecretFinder \"|boxes -d boy | lolcat")
    choice = input("[1]Install [99]Back >> ")
    if choice == "1":
        os.system("git clone https://github.com/m4ll0k/SecretFinder.git secretfinder")
        os.system("cd secretfinder; sudo pip3 install -r requirements.txt")
        info()
    elif choice == "99":
        info()
    else :
        menu()


def nmap():
    nmapchoice = input("[1]Install [99]BAck >> ")
    if nmapchoice == "1" :
        os.system("sudo git clone https://github.com/nmap/nmap.git")
        os.system("sudo chmod -R 755 nmap && cd nmap && sudo ./configure && make && sudo make install")
        info()
    elif nmapchoice == "99":
        info()
    else:
        menu()

def striker():
    os.system("echo \"Recon & Vulnerability Scanning Suite [!]https://github.com/s0md3v/Striker \"|boxes -d boy | lolcat")
    choice = input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("git clone https://github.com/s0md3v/Striker.git")
        os.system("cd Striker && pip3 install -r requirements.txt")
        info()
    elif choice == "2":
        tsite= input("Enter Site Name (example.com) >> ")
        os.system("cd Striker && sudo python3 striker.py {0}".format(tsite))
    elif choice == "99":
        info()
    else :
        menu()


def redhawk():
    os.system("echo \"All in one tool for Information Gathering and Vulnerability Scanning. \n [!]https://github.com/Tuhinshubhra/RED_HAWK \n\n [!]Please Use command [FIX] After Running Tool first time \" | boxes -d boy | lolcat")
    choice = input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("git clone https://github.com/Tuhinshubhra/RED_HAWK")
        info()
    elif choice == "2":
        os.system("cd RED_HAWK;php rhawk.php")
    elif choice == "99":
        info()
    else :
        menu()

def infogaemail():
    os.system("echo \"Infoga is a tool gathering email accounts informations\n(ip,hostname,country,...) from different public source \n[!]https://github.com/m4ll0k/Infoga \"| boxes -d boy |lolcat")
    choice = input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("git clone https://github.com/m4ll0k/Infoga.git")
        os.system("cd infoga;sudo python setup.py install")
        info()
    elif choice == "2":
        os.system("cd infoga;python infoga.py")
    elif choice == "99":
        info()
    else :
        menu()

def recondog():
    os.system("echo \"ReconDog Information Gathering Suite  \n[!]https://github.com/s0md3v/ReconDog \"|boxes -d boy | lolcat")
    choice = input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("git clone https://github.com/s0md3v/ReconDog.git ")
        info()
    elif choice == "2":
        os.system("cd ReconDog;sudo python dog")
    elif choice == "99":
        info()
    else :
        menu()

def Dracnmap():
    os.system("echo \"Dracnmap is an open source program which is using to \nexploit the network and gathering information with nmap help \n [!]https://github.com/Screetsec/Dracnmap \" | boxes -d boy | lolcat")
    dracnap = input("[1]Install [99]Back >> ")
    if dracnap == "1":
        os.system("sudo git clone https://github.com/Screetsec/Dracnmap.git ")
        os.system("cd Dracnmap && chmod +x Dracnmap.sh")
        info()
    elif dracnap == "99":
        info()
    else :
        menu()    

def h2ip():
    host = input("Enter host name(www.google.com) :-  ")
    ips = socket.gethostbyname(host)
    print(ips)

def ports():
    clearScr()
    target = input('Select a Target IP : ')
    os.system("sudo nmap -O -Pn %s" % target)
    sys.exit()

def xerosploit():
    os.system("echo \"Xerosploit is a penetration testing toolkit whose goal is to perform \n man-in-th-middle attacks for testing purposes\"|boxes -d boy | lolcat")
    xeros=input("[1]Install [2]Run [99]Back >>")
    if xeros == "1":
        os.system("git clone https://github.com/LionSec/xerosploit")
        os.system("cd xerosploit && sudo python install.py")
        info()
    elif xeros == "2":
        os.system("sudo xerosploit")
    elif xeros == "99":
        info()
    else :
        menu()

def reconspider():
    os.system("echo \" ReconSpider is most Advanced Open Source Intelligence (OSINT) Framework for scanning IP Address, Emails, \nWebsites, Organizations and find out information from different sources.\n :~python3 reconspider.py \n\t [!]https://github.com/bhavsec/reconspider \" | boxes -d boy | lolcat")
    userchoice = input("[1]Install [99]Back >> ")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/bhavsec/reconspider.git")
        os.system("sudo apt install python3 python3-pip && cd reconspider && sudo python3 setup.py install")
        info()
    # elif userchoice == "2":
    #     os.system("cd reconspider && python3 reconspider.py")
    elif userchoice == "99":
        info()
    else :
        menu()

def setoolkit():
    os.system("echo \"The Social-Engineer Toolkit is an open-source penetration\ntesting framework designed for social engineering\"| boxes -d boy | lolcat")
    choiceset = input("[1]Install [2]Run [99]BAck >>")
    if choiceset == "1":
        os.system("git clone https://github.com/trustedsec/social-engineer-toolkit.git")
        os.system("python social-engineer-toolkit/setup.py")
        phishattack()
    if choiceset == "2":
        clearScr()
        os.system("sudo setoolkit")
    elif choiceset == "99":
        phishattack()
    else:
        menu()

def passwd():
    clearScr()
    os.system("figlet -f standard -c Wordlist Generator | lolcat")
    print("""   
                [01]Cupp
                [02]WordlistCreator
                [03]Goblin WordGenerator
                [04]Credential reuse attacks
                [05]Password list((1.4 Billion Clear Text Password))
                [99]Back To Main Menu
       """)
    passchoice = input("Z4nzu ==>> ")
    if passchoice == "1" or passchoice == "01":
        clearScr()
        cupp()
    elif passchoice == "2" or passchoice == "02":
        clearScr()
        wlcreator()
    elif passchoice == "3" or passchoice == "03":
        clearScr()
        goblinword()
    elif passchoice == "4" or passchoice == "04":
        clearScr()
        credentialattack()
    elif passchoice == "5" or passchoice == "05":
        clearScr()
        showme()
    elif passchoice == "99":
        clearScr()
        menu()
    elif passchoice == "":
        menu()
    else:
        menu()

def cupp():
    os.system("echo \"Common User Password Generator..!!\"| boxes -d boy | lolcat ")
    cc=input("[1]Install [99]Back >> ")
    if cc == "1":
        os.system("git clone https://github.com/Mebus/cupp.git")
        passwd()
    elif cc == "2":
        # os.system("cd cupp && ./cupp.py -h")
        pass
    elif cc == "99" :
        passwd()
    else :
        menu()

def wlcreator():
    os.system("echo \" WlCreator is a C program that can create all possibilities of passwords,\n and you can choose Lenght, Lowercase, Capital, Numbers and Special Chars\" | boxes -d boy | lolcat")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/Z4nzu/wlcreator")
        passwd()
    elif userchoice == "2":
        os.system("cd wlcreator && sudo gcc -o wlcreator wlcreator.c && ./wlcreator 5")
    elif userchoice == "99":
        passwd()
    else :
        menu()

def goblinword():
    os.system("echo \" GoblinWordGenerator \" | boxes -d boy | lolcat")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/UndeadSec/GoblinWordGenerator.git")
        passwd()
    elif userchoice == "2":
        os.system("cd GoblinWordGenerator && python3 goblin.py")
    elif userchoice == "99":
        passwd()
    else :
        menu()

def credentialattack():
    os.system("echo \"[!]Check if the targeted email is in any leaks and then use the leaked password to check it against the websites.\n[!]Check if the target credentials you found is reused on other websites/services.\n[!]Checking if the old password you got from the target/leaks is still used in any website.\n[#]This Tool Available in MAC & Windows Os \n\t[!] https://github.com/D4Vinci/Cr3dOv3r\" | boxes -d boy | lolcat")
    userchoice = input("[1]Install [2]Run [99]Back >> ")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/D4Vinci/Cr3dOv3r.git")
        os.system("cd Cr3dOv3r && python3 -m pip install -r requirements.txt")
        passwd()
    elif userchoice == "2" :
        os.system("cd Cr3dOv3r && sudo python3 Cr3d0v3r.py -h")
    elif userchoice == "99":
        passwd()
    else :
        menu()

def wire():
    clearScr()
    os.system("figlet -f standard -c Wireless Attack Tools | lolcat")
    print("""  
                [1] WiFi-Pumpkin
                [2] pixiewps
                [3] Bluetooth Honeypot GUI Framework
                [4] Fluxion
                [5] Wifiphisher
                [6] Wifite
                [7] EvilTwin 
                [8] Howmanypeople
                [99]Back To The Main Menu """)
    choice4 = input("Z4nzu ==>> ")
    if choice4 == "1":
        clearScr()
        wifipumkin()
    if choice4 == "2":
        clearScr()
        pixiewps()
    if choice4 == "3":
        clearScr()
        bluepot()
    if choice4 == "4":
        clearScr()
        fluxion()
    if choice4 == "5":
        clearScr()
        wifiphisher()
    elif choice4 == "6":
        clearScr()
        wifite()
    elif choice4 == "7":
        clearScr()
        eviltwin()
    elif choice4== "8":
        clearScr()
        howmanypeople()
    elif choice4 == "99":
        menu()
    elif choice4 == "":
        menu()
    else:
        menu()

def howmanypeople():
    os.system("echo \"Count the number of people around you by monitoring wifi signals.\n[@]WIFI ADAPTER REQUIRED* \n[*]It may be illegal to monitor networks for MAC addresses, \nespecially on networks that you do not own. Please check your country's laws\n\t [!]https://github.com/An0nUD4Y/howmanypeoplearearound \"|boxes -d boy | lolcat")
    choice = input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("sudo apt-get install tshark;sudo pip install howmanypeoplearearound")
        wire()
    elif choice == "2":
        os.system("sudo howmanypeoplearearound")
    elif choice == "99":
        wire()
    else :
        menu()


def wifipumkin():
    os.system("echo \"The WiFi-Pumpkin is a rogue AP framework to easily create these fake networks\nall while forwarding legitimate traffic to and from the unsuspecting target.\"| boxes -d boy | lolcat")
    wp=input("[1]Install [2]Run [99]Back >>")
    if wp == "1":
        os.system("sudo apt install libssl-dev libffi-dev build-essential")
        os.system("sudo git clone https://github.com/P0cL4bs/wifipumpkin3.git")
        os.system("chmod -R 755 wifipumpkin3 && cd wifipumpkin3")
        os.system("sudo apt install python3-pyqt5 ")
        os.system("sudo python3 setup.py install")
        wire()
    elif wp == "2":
        clearScr()
        os.system("sudo wifipumpkin3")
    elif wp == "99":
        wire()
    else :
        menu()

def pixiewps():
    os.system("echo \"Pixiewps is a tool written in C used to bruteforce offline the WPS pin\n exploiting the low or non-existing entropy of some Access Points, the so-called pixie dust attack\"| boxes -d boy | lolcat")
    choicewps = input("[1]Install [2]Run [99]Back >> ")
    if choicewps == "1":
        os.system("sudo git clone https://github.com/wiire/pixiewps.git && apt-get -y install build-essential")
        os.system("cd pixiewps*/ && make ")
        os.system("cd pixiewps*/ && sudo make install && wget https://pastebin.com/y9Dk1Wjh")
    if choicewps == "2":
        os.system("echo \"1.>Put your interface into monitor mode using 'airmon-ng start {wireless interface}\n2.>wash -i {monitor-interface like mon0}'\n3.>reaver -i {monitor interface} -b {BSSID of router} -c {router channel} -vvv -K 1 -f\"| boxes -d boy")
        print("You Have To Run Manually By USing >>pixiewps -h ")
        pass
    elif choicewps == "99":
        wire()
    else:
        menu()

def bluepot():
    os.system("echo \"you need to have at least 1 bluetooh receiver (if you have many it will work wiht those, too).\nYou must install/libbluetooth-dev on Ubuntu/bluez-libs-devel on Fedora/bluez-devel on openSUSE\"|boxes -d boy | lolcat")
    choice = input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("wget https://github.com/andrewmichaelsmith/bluepot/raw/master/bin/bluepot-0.1.tar.gz && tar xfz bluepot-0.1.tar.gz && sudo java -jar bluepot/BluePot-0.1.jar")
        time.sleep(3)
        wire()
    elif choice == "2":
        os.system("cd bluepot-0.1 && sudo java -jar bluepot/BluePot-0.1.jar")
    elif choice == "99":
        wire()
    else:
        menu()

def fluxion():
    os.system("echo \"Fluxion is a wifi key cracker using evil twin attack..\nyou need a wireless adaptor for this tool\"| boxes -d boy | lolcat")
    choice = input("[1]Install [2]Run [99]Back >>")
    if choice == "1":
        os.system("git clone https://github.com/thehackingsage/Fluxion.git") 
        os.system("cd Fluxion && cd install && sudo chmod +x install.sh && sudo bash install.sh")
        os.system("cd .. ; sudo chmod +x fluxion.sh")
        time.sleep(2)
        wire()
    elif choice == "2":
        os.system("cd Fluxion;sudo bash fluxion.sh")
    elif choice == "99" :
        wire()
    else:
        menu()

def wifiphisher():
    print("""
    Wifiphisher is a rogue Access Point framework for conducting red team engagements or Wi-Fi security testing. 
    Using Wifiphisher, penetration testers can easily achieve a man-in-the-middle position against wireless clients by performing 
    targeted Wi-Fi association attacks. Wifiphisher can be further used to mount victim-customized web phishing attacks against the
    connected clients in order to capture credentials (e.g. from third party login pages or WPA/WPA2 Pre-Shared Keys) or infect the 
    victim stations with malware..
    """)
    print("For More Details Visit >> https://github.com/wifiphisher/wifiphisher")
    wchoice=input("[1]Install [2]Run [99]Back >> ")
    if wchoice == "1":
        os.system("git clone https://github.com/wifiphisher/wifiphisher.git")
        os.system("cd wifiphisher && sudo python3 setup.py install")   
        wire()
    if wchoice == "2":
        os.system("cd wifiphisher && sudo wifiphisher")
    elif wchoice == "99" :
        wire()
    else :
        menu()

def wifite():
    os.system("echo \"[!]https://github.com/derv82/wifite2 \"|boxes -d boy | lolcat")
    wc=input("[1]Install [2]Run [99]Back >> ")
    if wc == "1":
        os.system("sudo git clone https://github.com/derv82/wifite2.git")
        os.system("cd wifite2 && sudo python3 setup.py install ; sudo pip3 install -r requirements.txt")
        time.sleep(3)
        wire()
    elif wc =="2":
        os.system("cd wifite2 && sudo wifite")
    elif wc == "99":
        wire()
    else :
        menu()

def eviltwin():
    os.system("echo \"Fakeap is a script to perform Evil Twin Attack, by getting credentials using a Fake page and Fake Access Point \" | boxes -d boy | lolcat")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/Z4nzu/fakeap")
        wire()
    elif userchoice == "2":
        os.system("cd fakeap && sudo bash fakeap.sh")
    elif userchoice == "99":
        wire()
    else :
        menu()

def socialattack():
    clearScr()
    os.system("figlet -f standard SocialMedia Attack | lolcat")
    print("""
        [1] Instagram Attack
        [2] AllinOne SocialMedia Attack 
        [3] Facebook Attack
        [4] Application Checker
        [99]Back To Menu
    """)
    choice=input("Z4nzu >> ")
    if choice == "1":
        clearScr()
        instabrute()
    elif choice == "2":
        clearScr()
        bruteforce()
    elif choice == "3":
        clearScr()
        faceshell()
    elif choice == "4" :
        clearScr()
        appcheck()
    elif choice == "99" :
        others()
    else :
        menu()

def instabrute():
    os.system("echo \"Brute force attack against Instagram \n\t [!]https://github.com/chinoogawa/instaBrute \"| boxes -d boy | lolcat")
    instachoice=input("[1]install [2]Run [99]Back >> ")
    if instachoice == "1":
        os.system("sudo git clone https://github.com/chinoogawa/instaBrute.git ")
        os.system("cd instaBrute;sudo pip install -r requirements.txt")
        socialattack()
    elif instachoice == "2":
        uname = input("Enter Username >> ")
        passinput=input("Enter wordword list >> ")
        os.system("cd instaBrute;sudo python instaBrute.py -u {0} -d {1}".format(uname,passinput))
    elif instachoice == "99":
        socialattack()
    else :
        menu()

def bruteforce():
    os.system("echo \"Brute_Force_Attack Gmail Hotmail Twitter Facebook Netflix \n[!]python3 Brute_Force.py -g <Account@gmail.com> -l <File_list> \n\t[!]https://github.com/Matrix07ksa/Brute_Force \"|boxes -d boy | lolcat")
    choice = input ("[1]Install [2]Run [99]BAck >> ")
    if choice == "1":
        os.system("sudo git clone https://github.com/Matrix07ksa/Brute_Force.git")
        os.system("cd Brute_Force ;sudo pip3 install proxylist;pip3 install mechanize")
        socialattack()
    elif choice == "2":
        os.system("cd Brute_Force;python3 Brute_Force.py -h")
    elif choice == "99":
        socialattack()
    else :
        menu()

def faceshell():
    os.system("echo \" Facebook BruteForcer[!]https://github.com/Matrix07ksa/Brute_Force \"|boxes -d boy | lolcat")
    choice = input ("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("sudo git clone https://github.com/Matrix07ksa/Brute_Force.git")
        os.system("cd Brute_Force ;sudo pip3 install proxylist;pip3 install mechanize")
        socialattack()
    elif choice == "2":
        uname=input("Enter Username >> ")
        passinput=input("Enter Wordlist >> ")
        os.system("cd Brute_Force;python3 Brute_Force.py -f {0} -l {1}".format(uname,passinput))
    elif choice == "99":
        socialattack()
    else :
        menu()

def appcheck():
    os.system("echo \"Tool to check if an app is installed on the target device through a link.\"|boxes -d boy | lolcat")
    userchoice = input("[1]Install [2]Run [99]Back >> ")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/jakuta-tech/underhanded")
        os.system("cd underhanded && sudo chmod +x underhanded.sh")
        socialattack()
    elif userchoice == "2":
        os.system("cd underhanded ; sudo bash underhanded.sh")
    elif userchoice == "99":
        socialattack()
    else :
        menu()

def phishattack():
    clearScr()
    os.system("figlet -f standard -c Phishing Attack Tools | lolcat")
    print("""
       [1] Setoolkit 
       [2] SocialFish
       [3] HiddenEye
       [4] Evilginx2
       [5] I-See_You(Get Location using phishing attack) 
       [6] SayCheese (Grab target's Webcam Shots)
       [7] QR Code Jacking
       [8] ShellPhish 
       [99]Back To Main Menu
       """)
    choice = input("Z4nzu ==>> ")
    if choice == "1":
        clearScr()
        setoolkit()
    if choice == "2":
        clearScr()
        socialfish()
    if choice == "3":
        clearScr()
        hiddeneye()
    if choice == "4":
        clearScr()
        evilginx()
    elif choice == "5":
        clearScr()
        iseeyou()
    elif choice == "6":
        clearScr()
        saycheese()
    elif choice == "7":
        clearScr()
        qrjacking()
    elif choice == "8":
        clearScr()
        shellphish()
    elif choice == "99":
        clearScr()
        menu()
    elif choice == "":
        menu()
    else:
        menu()

def socialfish():
    os.system("echo \"Automated Phishing Tool & Information Collector \n\t[!]https://github.com/UndeadSec/SocialFish \"|boxes -d boy | lolcat")
    choice=input("[1]install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("sudo git clone https://github.com/UndeadSec/SocialFish.git && sudo apt-get install python3 python3-pip python3-dev -y")
        os.system("cd SocialFish && sudo python3 -m pip install -r requirements.txt")
        time.sleep(2)
        phishattack()
    elif choice =="2":
        os.system("cd SocialFish && sudo python3 SocialFish.py root pass")
    elif choice =="99":
        phishattack()
    else :
        menu()

def hiddeneye():
    os.system("echo \"Modern Phishing Tool With Advanced Functionality And Multiple Tunnelling Services \n\t [!]https://github.com/DarkSecDevelopers/HiddenEye \"|boxes -d boy | lolcat ")
    choice=input("[1]install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("sudo git clone https://github.com/DarkSecDevelopers/HiddenEye.git ;sudo chmod 777 HiddenEye")
        os.system("cd HiddenEye;sudo pip3 install -r requirements.txt;sudo pip3 install requests;pip3 install pyngrok")
        phishattack()
    elif choice =="2":
        os.system("cd HiddenEye;sudo python3 HiddenEye.py")
    elif choice =="99":
        phishattack()
    else :
        menu()

def evilginx():
    os.system("echo \"evilginx2 is a man-in-the-middle attack framework used for phishing login credentials along with session cookies,\nwhich in turn allows to bypass 2-factor authentication protection.\n\n\t [+]Make sure you have installed GO of version at least 1.14.0 \n[+]After installation, add this to your ~/.profile, assuming that you installed GO in /usr/local/go\n\t [+]export GOPATH=$HOME/go \n [+]export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin \n[+]Then load it with source ~/.profiles.\n [*]https://github.com/An0nUD4Y/evilginx2 \"|boxes -d boy | lolcat")
    choice=input("[1]install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("sudo apt-get install git make;go get -u github.com/kgretzky/evilginx2")
        os.system("cd $GOPATH/src/github.com/kgretzky/evilginx2;make")
        os.system("sudo make install;sudo evilginx")
        time.sleep(2)
        phishattack()
    elif choice =="2":
        os.system("sudo evilginx")
    elif choice =="99":
        phishattack()
    else :
        menu()

def shellphish():
    os.system("echo \"Phishing Tool for 18 social media \n [!]https://github.com/An0nUD4Y/shellphish \"|boxes -d boy | lolcat")
    choice = input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("git clone https://github.com/An0nUD4Y/shellphish")
    elif choice == "2":
        os.system("cd shellphish;sudo bash shellphish.sh")
    elif choice == "99":
        phishattack()
    else :
        menu()


def iseeyou():
    os.system("echo \"[!] ISeeYou is a tool to find Exact Location of Victom By User SocialEngineering or Phishing Engagment..\n[!]Users can expose their local servers to the Internet and decode the location coordinates by looking at the log file\"|boxes -d boy | lolcat")
    userchoice = input("[1]Install [2]Run [99]Back >> ")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/Viralmaniar/I-See-You.git")
        os.system("cd I-See-You && sudo chmod u+x ISeeYou.sh")
        phishattack()
    elif userchoice == "2":
        os.system("cd I-See-You && sudo bash ISeeYou.sh")
    elif userchoice == "99":
        phishattack()
    else :
        menu()

def saycheese():
    os.system("echo \"Take webcam shots from target just sending a malicious link\"|boxes -d boy | lolcat")
    userchoice = input("[1]Install [2]Run [99]Back >> ")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/hangetzzu/saycheese")
        phishattack()
    elif userchoice == "2":
        os.system("cd saycheese && sudo bash saycheese.sh")
    elif userchoice == "99":
        phishattack()
    else :
        menu()

def qrjacking():
    os.system("echo \"QR Code Jacking (Any Website) \" | boxes -d boy | lolcat")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/cryptedwolf/ohmyqr && sudo apt-get install scrot")
        phishattack()
    elif userchoice == "2":
        os.system("cd ohmyqr && sudo bash ohmyqr.sh")
    elif userchoice == "99":
        phishattack()
    else :
        menu()

def socialfinder():
    clearScr()
    os.system("figlet -f standard SocialMedia Finder | lolcat")
    print("""
        [1]Find SocialMedia By Facial Recognation System
        [2]Find SocialMedia By UserName
        [3]Sherlock
        [4]SocialScan | Username or Email
        [99]Back To Main Menu
    """)
    choice =input("Z4nzu =>>")
    if choice == "1":
        clearScr()
        facialfind()
    elif choice == "2":
        clearScr()
        finduser()
    elif choice == "3":
        clearScr()
        sherlock()
    elif choice == "4":
        clearScr()
        socialscan()
    elif choice == "99":
        menu()
    else :
        menu()

def socialscan():
    os.system("echo \"Check email address and username availability on online platforms with 100% accuracy \n\t[*]https://github.com/iojw/socialscan \"|boxes -d boy | lolcat")
    choice = input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("sudo pip install socialscan")
    elif choice == "2":
        uname =input("Enter Username or Emailid (if both then please space between email & username) >>")
        os.system("sudo socialscan {0}".format(uname))
    elif choice == "99":
        socialfinder()
    else :
        menu()


def sherlock():
    os.system("echo \"Hunt down social media accounts by username across social networks \n For More Usege \n\t >>python3 sherlock --help \n [!]https://github.com/sherlock-project/sherlock \"|boxes -d boy | lolcat")
    choice = input("[1]Install [99]Back >> ")
    if choice == "1":
        os.system("git clone https://github.com/sherlock-project/sherlock.git")
        os.system("cd sherlock ;sudo python3 -m pip install -r requirements.txt")
    elif choice == "2":
        uname= input("Enter Username >> ")
        os.system("cd sherlock ;sudo python3 sherlock {0}".format(uname))
    elif choice == "99":
        socialfinder()
    else :
        menu()

def facialfind():
    os.system("echo \"A Social Media Mapping Tool that correlates profiles\n via facial recognition across different sites. \n\t[!]https://github.com/Greenwolf/social_mapper \"|boxes -d boy | lolcat")
    choice=input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("sudo add-apt-repository ppa:mozillateam/firefox-next && sudo apt update && sudo apt upgrade")
        os.system("sudo git clone https://github.com/Greenwolf/social_mapper.git")
        os.system("cd social_mapper/setup")
        os.system("sudo python3 -m pip install --no-cache-dir -r requirements.txt")
        os.system("echo \"[!]Now You have To do some Manually\n[!]Install the Geckodriver for your operating system\n[!]Copy & Paste Link And Download File As System Configuration\n[#]https://github.com/mozilla/geckodriver/releases\n[!!]On Linux you can place it in /usr/bin \"| boxes | lolcat")
    elif choice == "2":
        os.system("cd social_mapper/setup")
        os.system("sudo python social_mapper.py -h")
        print("""\033[95m 
                You have to set Username and password of your AC Or Any Fack Account
                [#]Type in Terminal nano social_mapper.py
        """)
        os.system("echo \"python social_mapper.py -f [<imageFoldername>] -i [<imgFolderPath>] -m fast [<AcName>] -fb -tw\"| boxes | lolcat")
    elif choice == "99" :
        socialfinder()
    else :
        menu()

def finduser():
    os.system("echo \"Find usernames across over 75 social networks \n [!]https://github.com/xHak9x/finduser \"|boxes -d boy | lolcat")
    userchoice = input("[1]Install [2]Run [99]Back >> ")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/xHak9x/finduser.git")
        os.system("cd finduser && sudo chmod +x finduser.sh")
        time.sleep(3)
        socialfinder()
    elif userchoice == "2":
        os.system("cd finduser && sudo bash finduser.sh")
    elif userchoice == "99":
        socialfinder()
    else :
        menu()

def forensic():
    clearScr()
    os.system("figlet -f standard Forensic Tools | lolcat ")
    print("""
        [1] Autopsy
        [2] Wireshark
        [3] Bulk_extractor 
        [4] Disk Clone and ISO Image Aquire
        [5] Toolsley
        [99]Back to Menu
    """)
    choice = input("Z4nzu ==>>")
    if choice == "3" :
        bulkextractor()
    elif choice == "4":
        clearScr()
        guymager()
    elif choice == "1":
        clearScr()
        autopsy()
    elif choice == "2":
        clearScr()
        wireshark()
    elif choice == "5":
        clearScr()
        toolsley()
    elif choice == "99":
        menu()
    elif choice == "":
        menu()
    else :
        menu()

def bulkextractor():
    print("""
        [1]GUI Mode(Download required)
        [2]CLI Mode
        [99]BAck
    """)
    choice = input("Z4nzu >> ")
    if choice == "1":
        os.system("sudo git clone https://github.com/simsong/bulk_extractor.git")
        os.system("ls src/ && cd .. && cd java_gui && ./BEViewer")
        print("If you getting error after clone go to /java_gui/src/ And Compile .Jar file && run ./BEViewer")
        print("Please Visit For More Details About Installation >> https://github.com/simsong/bulk_extractor ")
    elif choice =="2":
        os.system("sudo apt-get install bulk_extractor")
        print("bulk_extractor and options")
        os.system("bulk_extractor")
        os.system("echo \"bulk_extractor [options] imagefile\" | boxes -d headline | lolcat")
    elif choice == "99":
        forensic()
    elif choice =="":
        forensic()
    else :
        menu()

def guymager():
    os.system("echo \"Guymager is a free forensic imager for media acquisition.\n [!]https://guymager.sourceforge.io/ \"|boxes -d boy | lolcat")
    choice = input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("sudo apt install guymager")
        forensic()
    elif choice == "2":
        clearScr()
        os.system("sudo guymager")
    elif choice == "99":
        forensic()
    elif choice == "":
        forensic()
    else :
        menu()

def autopsy():
    os.system("echo \"Autopsy is a platform that is used by Cyber Investigators.\n[!] Works in any Os\n[!]Recover Deleted Files from any OS & MEdia \n[!]Extract Image Metadata \"|boxes -d boy | lolcat")
    choice=input(" [1]Run [99]Back >> ")
    if choice == "1":
        os.system("sudo autopsy")
    if choice == "":
        forensic()
    elif choice =="99":
        forensic()
    else :
        menu()

def wireshark():
    os.system("echo \" Wireshark is a network capture and analyzer \ntool to see what’s happening in your network.\n And also investigate Network related incident \" | boxes -d boy | lolcat")
    choice = input("[1]Run [99]Back >> ")
    if choice == "1":
        os.system("sudo wireshark")
    elif choice == "99":
        forensic()
    elif choice == "":
        forensic()
    else :
        menu()

def toolsley():
    os.system("echo \" Toolsley got more than ten useful tools for investigation.\n[+]File signature verifier\n[+]File identifier \n[+]Hash & Validate \n[+]Binary inspector \n [+]Encode text \n[+]Data URI generator \n[+]Password generator \" | boxes -d boy | lolcat")
    userchoice = input("[1]Open [99]Back >> ")
    if userchoice == "1":
        print("Trying to open WebBrowser ")
        time.sleep(3)
        webbrowser.open_new_tab('https://www.toolsley.com/') 
    elif userchoice == "99":
        forensic()
    elif userchoice == "":
        forensic()
    else :
        menu()

def postexp():
    clearScr()
    os.system("figlet -f standard post explotations | lolcat")
    print("""
        [1] Vegile - Ghost In The Shell
        [2] Chrome Keylogger
        [99]Back 
    """)
    expchoice = input("Z4nzu =>> ")
    if expchoice == "1":
        clearScr()
        vegile()
    if expchoice == "2":
        clearScr()
        chromekeylogger()
    elif expchoice == "99":
        menu()
    elif expchoice == "":
        postexp()
    else :
        menu()

def vegile():
    os.system("echo \"[!]This tool will set up your backdoor/rootkits when backdoor is already setup it will be \nhidden your specific process,unlimited your session in metasploit and transparent.\"|boxes -d boy | lolcat")
    vegilechoice = input("[1]Install [2]Run [99]Back >> ")
    if vegilechoice == "1":
        os.system("sudo git clone https://github.com/Screetsec/Vegile.git")
        os.system("cd Vegile && sudo chmod +x Vegile")
        postexp()
    elif vegilechoice == "2":
        os.system("echo \"You can Use Command  : \n[!]Vegile -i / --inject [backdoor/rootkit] \n[!]Vegile -u / --unlimited [backdoor/rootkit] \n[!]Vegile -h / --help\"|boxes -d parchment")
        os.system("cd Vegile && sudo bash Vegile ")
        pass
    elif vegilechoice == "99":
        postexp()
    else :
        menu()

def chromekeylogger():
    os.system("echo \" Hera Chrome Keylogger \" | boxes -d boy | lolcat")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/UndeadSec/HeraKeylogger.git")
        os.system("cd HeraKeylogger && sudo apt-get install python3-pip -y && sudo pip3 install -r requirements.txt ")
        postexp()
    elif userchoice == "2":
        os.system("cd HeraKeylogger && sudo python3 hera.py ")
    elif userchoice == "99":
        postexp()
    else :
        menu()

def routexp():
    clearScr()
    os.system("figlet -f standard Exploit Framework | lolcat ")
    print("""
        [1] RouterSploit
        [2] WebSploit
        [3] Commix
        [4] Web2Attack
        [5] Fastssh 
        [99]Back to menu
    """)
    choice=input("Z4nzu =>> ")
    if choice == "1":
        clearScr()
        routersploit()
    elif choice=="99":
        menu()
    elif choice=="5":
        clearScr()
        fastssh()
    elif choice == "3":
        clearScr()
        commix()
    elif choice == "4":
        clearScr()
        web2attack()
    elif choice == "2":
        clearScr()
        websploit()
    elif choice== "":
        routexp()
    else :
        print("Error Wrong Input..")
        routexp()

def commix():
    os.system("echo \"Automated All-in-One OS command injection and exploitation tool.\nCommix can be used from web developers, penetration testers or even security researchers\n in order to test web-based applications with the view to find bugs,\n errors or vulnerabilities related to command injection attacks.\n Usage: python commix.py [option(s)] \n\n\t[!]https://github.com/commixproject/commix  \"|boxes -d boy | lolcat")
    choice = input("[1]Install [99]Back >> ")
    if choice == "1":
        os.system("git clone https://github.com/commixproject/commix.git commix")
    elif choice == "99":
        routexp()
    else :
        menu()

def websploit():
    os.system("echo \"Websploit is an advanced MITM framework.\n\t [!]https://github.com/The404Hacking/websploit \"|boxes -d boy | lolcat")
    choice = input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("https://github.com/The404Hacking/websploit.git")
    elif choice == "2":
        os.system("cd websploit;python3 websploit.py")
    elif choice == "99":
        routexp()
    else :
        menu()

def routersploit():
    os.system("echo \"The RouterSploit Framework is an open-source exploitation framework dedicated to embedded devices\"|boxes -d boy | lolcat")
    choice=input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("sudo git clone https://www.github.com/threat9/routersploit")
        os.system("cd routersploit && sudo python3 -m pip install -r requirements.txt")
        routexp()
    elif choice == "2":
        os.system("cd routersploit && sudo python3 rsf.py")
    elif choice == "99":
        routexp()
    elif choice == "":
        routexp()
    else :
        menu()

def fastssh():
    os.system("echo \"Fastssh is an Shell Script to perform multi-threaded scan \n and brute force attack against SSH protocol using the most commonly credentials. \" | boxes -d boy | lolcat")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/Z4nzu/fastssh && cd fastssh && sudo chmod +x fastssh.sh")
        os.system("sudo apt-get install -y sshpass netcat")
    elif userchoice == "2":
        os.system("cd fastssh && sudo bash fastssh.sh --scan")
    elif userchoice == "99":
        routexp()
    else :
        menu()

def webAttack():
    clearScr()
    os.system("figlet 'Web Attack Tools' -f standard -c | lolcat")
    print("""
        [1] Web2Attack
        [2] Skipfish
        [3] SubDomain Finder
        [4] CheckURL
        [5] Blazy(Also Find ClickJacking)
        [6] Sub-Domain TakeOver
        [99]Back To Menu
    """)
    choice = input("Z4nzu >> ")
    if choice == "1":
        web2attack()
    elif choice == "2":
        skipfish()
    elif choice == "3":
        subdomain()
    elif choice == "4":
        clearScr()
        checkurl()
    elif choice == "5":
        clearScr()
        blazy()
    elif choice == "6":
        clearScr()
        subdomaintakeover()
    elif choice == "99":
        menu()
    else :
        print("Wrong Input..")
        webAttack()

def subdomaintakeover():
    os.system("echo \"Sub-domain takeover vulnerability occur when a sub-domain \n (subdomain.example.com) is pointing to a service (e.g: GitHub, AWS/S3,..)\nthat has been removed or deleted.\nUsage :python3 takeover.py -d www.domain.com -v \n\t[!]https://github.com/m4ll0k/takeover \"|boxes -d boy | lolcat")
    choice = input("[1]Install [99]Back >> ")
    if choice == "1":
        os.system("git clone https://github.com/m4ll0k/takeover.git")
        os.system("cd takeover;sudo python3 setup.py install")
        webAttack()
    elif choice == "99":
        webAttack()
    else :
        menu()

def web2attack():
    os.system("echo \"Web hacking framework with tools, exploits by python \n[!]https://github.com/santatic/web2attack \"| boxes -d boy | lolcat")
    userchoice = input("[1]Install [2]Run [99]Back >> ")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/santatic/web2attack.git")
        menu()
    elif userchoice == "2":
        os.system("cd web2attack && sudo bash w2aconsole")
    elif userchoice == "99":
        webAttack()
    else :
        menu()

def skipfish():
    os.system("echo \"Skipfish – Fully automated, active web application security reconnaissance tool \n Usage : skipfish -o [FolderName] targetip/site \n[!]https://tools.kali.org/web-applications/skipfish \"|boxes -d headline | lolcat")
    userchoice = input("[1]Run [99]Back >> ")
    if userchoice == "1":
        os.system("sudo skipfish -h")
        os.system("echo \"skipfish -o [FolderName] targetip/site\"|boxes -d headline | lolcat")
    elif userchoice == "99":
        webAttack()
    else :
        menu()
    
def subdomain():
    os.system("echo \"Sublist3r is a python tool designed to enumerate subdomains of websites using OSINT \n Usage:\n\t[1]python sublist3r.py -d example.com \n[2]python sublist3r.py -d example.com -p 80,443\"| boxes -d boy | lolcat")
    choice=input("[1]install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("sudo pip install requests argparse dnspython")
        os.system("sudo git clone https://github.com/aboul3la/Sublist3r.git ")
        os.system("cd Sublist3r && sudo pip install -r requirements.txt") 
        webAttack()
    elif choice == "2":
        os.system("cd Sublist3r && python sublist3r.py -h")
    elif choice == "99" :
        webAttack()
    else :
        menu()

def checkurl():
    os.system("echo \" Detect evil urls that uses IDN Homograph Attack.\n\t[!]python3 checkURL.py --url google.com \" | boxes -d boy | lolcat")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/UndeadSec/checkURL.git")
        webAttack()
    elif userchoice == "2":
        os.system("cd checkURL && python3 checkURL.py --help")
    elif userchoice == "99":
        webAttack()
    else :
        menu()

def blazy():
    os.system("echo \"Blazy is a modern login page bruteforcer \" | boxes -d boy | lolcat")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/UltimateHackers/Blazy")
        os.system("cd Blazy && sudo pip install -r requirements.txt")
        webAttack()
    elif userchoice == "2":
        os.system("cd Blazy && sudo python blazy.py")
    elif userchoice == "99":
        webAttack()
    else :
        menu()

def androidhack():
    clearScr()
    os.system("figlet -f standard -c Android Hacking Tools | lolcat")
    print("""
        [1] Keydroid 
        [2] MySMS
        [3] Lockphish (Grab target LOCK PIN)
        [4] DroidCam (Capture Image)
        [5] EvilApp (Hijack Session)
        [99]Main Menu
    """)
    choice = input("Z4nzu =>>")
    if choice == "1":
        clearScr()
        keydroid()
    elif choice == "2":
        clearScr()
        mysms()
    # elif choice == "3":
    #     print("Sorry This Tool Not Available")
    #     time.sleep(1)
    #     androidhack()
    #     # getdroid()
    elif choice == "3":
        clearScr()
        lock()
    # elif choice == "4":
    #     print("Sorry This Tool Not Available")
    #     time.sleep(1)
    #     androidhack()
    #     # droidfile()
    # elif choice  == "6":
    #     clearScr()
    #     whatshack()
    elif choice == "4":
        clearScr()
        droidcam()
    elif choice == "5":
        clearScr()
        evilapp()
    elif choice == "99":
        others()
    else :
        menu()

def keydroid():
    os.system("echo \"Android Keylogger + Reverse Shell\n[!]You have to install Some Manually Refer Below Link :\n [+]https://github.com/F4dl0/keydroid \" | boxes -d boy | lolcat")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/F4dl0/keydroid")
        androidhack()
    elif userchoice == "2":
        os.system("cd keydroid && bash keydroid.sh")
    elif userchoice == "99":
        androidhack()
    else :
        menu()

def mysms():
    os.system("echo \" Script that generates an Android App to hack SMS through WAN \n[!]You have to install Some Manually Refer Below Link :\n\t [+]https://github.com/papusingh2sms/mysms \" | boxes -d boy | lolcat")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/papusingh2sms/mysms")
        androidhack()
    elif userchoice == "2":
        os.system("cd mysms && bash mysms.sh")
    elif userchoice == "99":
        androidhack()
    else :
        menu()

# def getdroid():
#     os.system("echo \"FUD Android Payload (Reverse Shell) and Listener using Serveo.net (no need config port forwarding) \" | boxes -d boy | lolcat")
#     userchoice = input("[1]Install [2]Run [99]Back >>")
#     if userchoice == "1":
#         os.system("sudo git clone https://github.com/thelinuxchoice/getdroid && apt-get install android-sdk apksigner -y")
#         androidhack()
#     elif userchoice == "2":
#         os.system("cd getdroid && bash getdroid.sh")
#     elif userchoice == "99":
#         androidhack()
#     else :
#         menu()

def lock():
    os.system("echo \"Lockphish it's the first tool for phishing attacks on the lock screen, designed to\n Grab Windows credentials,Android PIN and iPhone Passcode using a https link. \"| boxes -d boy | lolcat")
    userchoice = input("[1]Install [2]Run [99]Back >> ")
    if userchoice == "1":
        os.system("sudo git clone git clone https://github.com/JasonJerry/lockphish")
        androidhack()
    elif userchoice == "2":
        os.system("cd lockphish && bash lockphish.sh")
    elif userchoice == "99":
        androidhack()
    else :
        menu()

# def droidfile():
#     os.system("echo \"Get files from Android directories\"|boxes -d boy | lolcat")
#     userchoice = input("[1]Install [2]Run [3] Packges Install(Required) [99]Back >>")
#     if userchoice == "1":
#         os.system("sudo git clone https://github.com/thelinuxchoice/droidfiles")
#     elif userchoice == "2":
#         os.system("cd droidfiles && bash droidfiles.sh")
#     elif userchoice == "3":
#         os.system("apt-get install default-jdk apksigner")
#         os.system("apt-get install libc6-dev-i386 lib32z1")
#         os.system("wget https://dl.google.com/android/repository/sdk-tools-linux-4333796.zip && mkdir -p $HOME/Android/Sdk && unzip sdk-tools-linux* -d $HOME/Android/Sdk")
#         os.system("curl -s \"https://get.sdkman.io\" | bash && source $HOME/.sdkman/bin/sdkman-init.sh && echo \"Y\" | sdk install java 8.0.191-oracle && sdk use java 8.0.191-oracle && sdk install gradle 2.14.1 && sdk use gradle 2.14.1")
#     elif userchoice == "99":
#         androidhack()
#     else :
#         menu()

# def whatshack():
#     os.system("echo \"Script to generate Android App to Hack All WhatsApp Media Files.\n\t[!]Download Android Studio:\n[+]https://developer.android.com/studio \n\t[!]Installing Android Studio:\n[+]unzip ~/Downloads/android*.zip -d /opt \nRun Android Studio: \n[+] cd /opt/android-studio/bin \n[+] ./studio.sh \n[!]Go to SDK Manager (Configure -> SDK Manager) and Download:\n[!]Android SDK Build-tools, Android SDK-tools, Android SDK platform-tools, Support Repository\" | boxes -d shell | lolcat")
#     userchoice = input("[1]Install [2]Run [99]Back >>")
#     if userchoice == "1":
#         os.system("sudo git clone https://github.com/thelinuxchoice/whatshack")
#         time.sleep(5)
#         print("Installing Required Packges..!! It Take More Time ")
#         time.sleep(3)
#         os.system("apt-get install openjdk-8-jdk && apt-get install gradle")
#         os.system("update-alternatives --list java")
#         os.system("update-alternatives --set java /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java")
#         time.sleep(2)
#         androidhack()
#     elif userchoice == "2":
#         os.system("echo \"[#]On First Time, Choose \"n\" when asks to build, then open the project on Android Studio:\n[!]cd /opt/android-studio/bin \n[!]./studio.sh \n[#]Import Gradle Project:\n[!]Choose whatshack app folder: whatshack/app/ \n[#]Wait all dependencies downloading, if you got errors, click on showed links to solve. \n[#]Try build from Android Studio: Build > build APK's \n[#]Click on showed links if you got errors. \n[#]Close Android after building successfully.\n[#]open with any Text Editor the file app/build.gradle\n[!]remove \"google\" \n[#]change gradle version from: 3.4.1 to: 2.2.0 \n[!]save and exit. \n[#]After this Run Script As Root: \n[!]bash whatshack.sh \"| boxes -d shell")
#         os.system("echo \"If still getting error please visit \n\t[#]https://github.com/thelinuxchoice/whatshack\"|boxes -d shell")
#         os.system("cd whatshack/ && bash whatshack.sh")
#     elif userchoice == "99":
#         androidhack()
#     elif userchoice=="":
#         androidhack()
#     else :
#         menu()

def droidcam():
    os.system("echo \"Powerful Tool For Grab Front Camera Snap Using A Link  \n[+]https://github.com/kinghacker0/WishFish \"| boxes -d boy | lolcat")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/kinghacker0/WishFish; sudo apt install php wget openssh")
        androidhack()
    elif userchoice == "2":
        os.system("cd wishfish && sudo bash wishfish.sh")
    elif userchoice == "99":
        androidhack()
    else :
        menu()

def evilapp():
    os.system("echo \"EvilApp is a script to generate Android App that can hijack authenticated sessions in cookies.\n [!]https://github.com/crypticterminal/EvilApp \" | boxes -d boy | lolcat")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/crypticterminal/EvilApp")
        androidhack()
    elif userchoice == "2":
        os.system("cd evilapp && bash evilapp.sh")
    elif userchoice == "99":
        androidhack()
    else :
        menu()

def payloads():
    clearScr()
    os.system("figlet -f standard -c Payloads | lolcat")
    print("""
        [1] The FatRat*
        [2] Brutal
        [3] Stitch
        [4] MSFvenom Payload Creator
        [5] Venom Shellcode Generator 
        [6] Spycam
        [7] Mob-Droid
        [99]Back 
    """)
    choice =input("Z4nzu >> ")
    if choice == "1":
        clearScr()
        thefatrat()
    elif choice == "2":
        clearScr()
        Brutal()
    elif choice == "7":
        clearScr()
        mobdroid()
    elif choice == "3":
        clearScr()
        stitch()
    elif choice == "4":
        clearScr()
        MSFvenom()
    elif choice == "5":
        clearScr()
        venom()
    elif choice == "6":
        clearScr()
        spycam()
    elif choice == "99":
        menu()
    elif choice == "":
        payloads()
    else :
        menu()

def mobdroid():
    os.system("echo \"Mob-Droid helps you to generate metasploit payloads in easy way\n without typing long commands and save your time.\n[!]https://github.com/kinghacker0/Mob-Droid \"|boxes -d boy | lolcat")
    choice = input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("git clone https://github.com/kinghacker0/mob-droid")
    elif choice == "2":
        os.system("cd Mob-Droid;sudo python mob-droid.py")
    elif choice == "99":
        payloads()
    else :
        menu()


def thefatrat():
    os.system("echo \"TheFatRat Provides An Easy way to create Backdoors and \nPayload which can bypass most anti-virus\"|boxes -d boy | lolcat")
    choice = input("[1]Install [2] Run [3]Update [4]TroubleShoot(if not run) [99]Back >>  ")
    if choice == "1":
        os.system("sudo git clone https://github.com/Screetsec/TheFatRat.git") 
        os.system("cd TheFatRat && sudo chmod +x setup.sh")
        payloads()
    elif choice == "2":
        os.system("cd TheFatRat && sudo bash setup.sh")
    elif choice == "3":
        os.system("cd TheFatRat && bash update && chmod +x setup.sh && bash setup.sh")
    elif choice == "4":
        os.system("cd TheFatRat && sudo chmod +x chk_tools && ./chk_tools")
        time.sleep(2)
        payloads()
    elif choice == "99":
        payloads()
    else :
        menu()

def Brutal():
    os.system("echo \"Brutal is a toolkit to quickly create various payload,powershell attack,\nvirus attack and launch listener for a Human Interface Device\"|boxes -d boy | lolcat")
    print("""
    [!]Requirement
        >>Arduino Software ( I used v1.6.7 )
        >>TeensyDuino
        >>Linux udev rules
        >>Copy and paste the PaensyLib folder inside your Arduino\libraries
    [!]Kindly Visit below link for Installation for Arduino 
        >> https://github.com/Screetsec/Brutal/wiki/Install-Requirements 
    """)
    choice = input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("sudo git clone https://github.com/Screetsec/Brutal.git")
        os.system("cd Brutal && sudo chmod +x Brutal.sh ")
        payloads()
    elif choice == "2":
        os.system("cd Brutal && sudo bash Brutal.sh")
    elif choice == "99":
        payloads()
    else :
        menu()

def stitch():
    os.system("echo \"Stitch is Cross Platform Python Remote Administrator Tool\n\t[!]Refer Below Link For Wins & MAc Os\n\t(!)https://nathanlopez.github.io/Stitch \" | boxes -d boy | lolcat")
    choice = input("[1]Install [2]Run [99]Back >>" )
    if choice == "1":
        os.system("sudo git clone https://github.com/nathanlopez/Stitch.git")
        os.system("cd Stitch && sudo pip install -r lnx_requirements.txt")
        payloads()
    elif choice == "2":
        os.system("cd Stitch && sudo python main.py")
    elif choice == "99":
        payloads()
    else :
        menu()

def MSFvenom():
    os.system("echo \"MSFvenom Payload Creator (MSFPC) is a wrapper to generate \nmultiple types of payloads, based on users choice.\nThe idea is to be as simple as possible (only requiring one input) \nto produce their payload. [!]https://github.com/g0tmi1k/msfpc \" |boxes -d boy | lolcat ")
    choice= input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("sudo git clone https://github.com/g0tmi1k/msfpc.git")
        os.system("cd msfpc;sudo chmod +x msfpc.sh")
        payloads()
    elif choice == "2":
        os.system("cd msfpc;sudo bash msfpc.sh -h -v")
    elif choice == "99":
        payloads()
    elif choice == "":
        payloads()
    else :
        menu()

def venom():
    os.system("echo \"venom 1.0.11 (malicious_server) was build to take advantage of \n apache2 webserver to deliver payloads (LAN) using a fake webpage writen in html\"| boxes -d boy| lolcat")
    choice =input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("sudo git clone https://github.com/r00t-3xp10it/venom.git")
        os.system("sudo chmod -R 775 venom*/ && cd venom*/ && cd aux && sudo bash setup.sh")
        os.system("sudo ./venom.sh -u")
        payloads()
    elif choice == "2":
        os.system("cd venom && sudo ./venom.sh")
    elif choice == "99":
        payloads()
    else :
        menu()

def spycam():
    os.system("echo \"Script to generate a Win32 payload that takes the webcam image every 1 minute and send it to the attacker\"|boxes -d boy | lolcat")
    userchoice = input("[1]Install [2]Run [99]Back >> ")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/thelinuxchoice/spycam ")
        os.system("cd spycam && bash install.sh && chmod +x spycam")
        payloads()
    elif userchoice == "2":
        os.system("cd spycam && ./spycam")
    elif userchoice == "99":
        payloads()
    elif userchoice == "":
        payloads()
    else :
        menu()

def wifijamming():
    clearScr()
    os.system("figlet -f standard -c Wifi Deautheticate | lolcat")
    print("""
        [1]WifiJammer-NG
        [2] Using Airmon
        [99]Back
    """)
    choice = input("Z4nzu =>> ")
    if choice == "1":
        clearScr()
        wifijammingng()
    elif choice == "2":
        clearScr()
        airmon()
    elif choice == "99":
        menu()
    else :
        menu()

def wifijammingng():
    os.system("echo \"Continuously jam all wifi clients and access points within range.\n\t [!]https://github.com/MisterBianco/wifijammer-ng \"|boxes -d boy | lolcat")
    choice = input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("sudo git clone https://github.com/MisterBianco/wifijammer-ng.git")
        os.system("cd wifijammer-ng;sudo pip3 install -r requirements.txt")
    elif choice == "2":
        os.system("echo \"python wifijammer.py [-a AP MAC] [-c CHANNEL] [-d] [-i INTERFACE] [-m MAXIMUM] [-k] [-p PACKETS] [-s SKIP] [-t TIME INTERVAL] [-D]\"| boxes | lolcat")
        os.system("cd wifijammer-ng;sudo python3 wifijammer.py")
    elif choice == "99":
        wifijamming()
    else :
        menu()


def airmon():
    print(Logo)
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        print("In Working")
        time.sleep(5)
        menu()
    elif userchoice == "2":
        print("""
            ###########################################################################                                                                                          
            #     [!] Follow Below steps for Jamming [!]                              #                                                                                          
            #     [1]iwconfig                                                         #                                                                                          
            #     [2]airmon-ng                                                        #                                                                                          
            #     [3]airmon-ng start InterfaceName                                    #                                                                                          
            #     [4]airodump-ng InterfaceName                                        #                                                                                          
            #     [5]airodump-ng -c [CH no.] --bssid [MAC address] InterfaceName      #                                                                                          
            #     [6]aireply-ng -0 0 -a [mac address] InterfaceName                   #                                                                                          
            #     [+]After Complete monitor mode return your interface in normal mode #                                                                                          
            #     [7]airmon-ng stop InterfaceName                                     #                                                                                          
            ########################################################################### 
        """)
        os.system("sudo airmon-ng")
    elif userchoice == "99":
        wifijamming()
    elif userchoice == "":
        wifijamming()
    else :
        menu()  

def steganography():
    clearScr()
    os.system("figlet -f standard -c SteganoGraphy | lolcat")
    print("""
        [1] SteganoHide
        [2] StegnoCracker
        [3] WhiteSpace
        [99]Back
    """)
    choice = input("Z4nz =>> ")
    if choice == "1":
        steganohide()
    elif choice == "2":
        clearScr()
        stegnocracker()
    elif choice == "3":
        clearScr()
        whitespace()
    elif choice == "99":
        menu()
    else :
        menu()

def steganohide():
    choice = input("[1]Install [2]Run [99] >> ")
    if choice == "1":
        os.system("sudo apt-get install steghide -y ")
        steganography()
    elif choice == "2":
        choice1=input("[1]Hide [2]Extract >> ")
        if choice1 =="1":
            filehide=input("Enter Filename you want to Embed(1.txt) >> ")
            filetobehide=input("Enter Cover Filename(test.jpeg) >> ")
            os.system("steghide embed -cf {0} -ef {1}".format(filetobehide,filehide))
        elif choice1 =="2":
            fromfile=input("Enter Filename From Extract Data >> ")
            os.system("steghide extract -sf {0}".format(fromfile))
    elif choice == "99":
        steganography()
    else :
        menu()

def stegnocracker():
    os.system("echo \"SteganoCracker is a tool that uncover hidden data inside files\n using brute-force utility  \"|boxes -d boy| lolcat")
    choice = input("[1]Install [2]Run [99]Back  >> ")
    if choice == "1":
        os.system("pip3 install stegcracker && pip3 install stegcracker -U --force-reinstall")
        steganography()
    elif choice =="2":
        file1=input("Enter Filename :- ")
        passfile=input("Enter Wordlist Filename :- ")
        os.system("stegcracker {0} {1} ".format(file1,passfile))
    elif choice == "99":
        steganography()
    else :
        menu()

def whitespace():
    os.system("echo \"Use whitespace and unicode chars for steganography \n\t [!]https://github.com/beardog108/snow10 \"|boxes -d boy | lolcat")
    choice =input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("sudo git clone https://github.com/beardog108/snow10.git ")
        os.system("sudo chmod -R 755 snow10")
        steganography()
    elif choice == "2":
        os.system("cd snow10 && firefox index.html")
    elif choice == "99":
        steganography()
    else :
        menu()

def sqltool():
    clearScr()
    os.system("figlet -f standard -c Sql Tools | lolcat")
    print("""
        [1] Sqlmap tool
        [2] NoSqlMap
        [3] Damn Small SQLi Scanner
        [4] Explo
        [5] Blisqy - Exploit Time-based blind-SQL injection
        [6] Leviathan - Wide Range Mass Audit Toolkit 
        [7] SQLScan
        [99]Back
    """)
    choice =input("\033[96m Z4nzu =>> ")
    if choice == "1":
        clearScr()
        sqlmap()
    elif choice == "2":
        clearScr()
        nosqlmap()
    elif choice == "3":
        clearScr()
        sqliscanner()
    elif choice == "4":
        clearScr()
        explo()
    elif choice == "5":
        clearScr()
        blisqy()
    elif choice == "6":
        clearScr()
        leviathan()
    elif choice == "7":
        clearScr()
        sqlscan()
    elif choice == "99":
        menu()
    else :
        menu()

def leviathan():
    os.system("echo \"Leviathan is a mass audit toolkit which has wide range service discovery,\nbrute force, SQL injection detection and running custom exploit capabilities. \n [*]It Requires API Keys \n More Usage [!]https://github.com/utkusen/leviathan/wiki \"|boxes -d boy | lolcat ")
    choice = input("[1]Install [2]Run [99]BAck >> ")
    if choice == "1":
        os.system("git clone https://github.com/leviathan-framework/leviathan.git")
        os.system("cd leviathan;sudo pip install -r requirements.txt")
        sqltool()
    elif choice == "2":
        os.system("cd leviathan;python leviathan.py")
    elif choice == "99":
        sqltool()
    else :
        menu()

def sqlscan():
    os.system("echo \"sqlscan is quick web scanner for find an sql inject point. not for educational, this is for hacking. \n [!]https://github.com/Cvar1984/sqlscan \"|boxes -d boy | lolcat")
    choice = input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("sudo apt install php php-bz2 php-curl php-mbstring curl")
        os.system("sudo curl https://raw.githubusercontent.com/Cvar1984/sqlscan/dev/build/main.phar --output /usr/local/bin/sqlscan")
        os.system("chmod +x /usr/local/bin/sqlscan")
        sqltool()
    elif choice == "2":
        os.system("sudo sqlscan")
    elif choice == "99":
        sqltool()
    else :
        menu()


def blisqy():
    os.system("echo \"Blisqy is a tool to aid Web Security researchers to find Time-based Blind SQL injection \n on HTTP Headers and also exploitation of the same vulnerability.\n For Usage >> [!]https://github.com/JohnTroony/Blisqy \"|boxes -d boy | lolcat")
    choice =input("[1]Install [99]Back >> ")
    if choice == "1":
        os.system("git clone https://github.com/JohnTroony/Blisqy.git ")
        sqltool()
    elif choice == "99":
        sqltool()
    else :
        menu()

def explo():
    os.system("echo \"explo is a simple tool to describe web security issues in a human and machine readable format.\n Usage :- \n [1]explo [--verbose|-v] testcase.yaml \n [2]explo [--verbose|-v] examples/*.yaml \n[*]https://github.com/dtag-dev-sec/explo \"|boxes -d boy | lolcat")
    choice =input("[1]Install [99]Back >> ")
    if choice == "1":
        os.system("git clone https://github.com/dtag-dev-sec/explo ")
        os.system("cd explo ;sudo python setup.py install")
        sqltool()
    elif choice == "99":
        sqltool()
    else :
        menu()

def sqliscanner():
    os.system("echo \"Damn Small SQLi Scanner (DSSS) is a fully functional SQL injection\nvulnerability scanner also supporting GET and POST parameters.\n[*]python3 dsss.py -h[help] | -u[URL] \n\tMore Info [!]https://github.com/stamparm/DSSS \"|boxes -d boy | lolcat")
    choice =input("[1]Install [99]Back >> ")
    if choice == "1":
        os.system("git clone https://github.com/stamparm/DSSS.git")
        sqltool()
    elif choice == "99":
        sqltool()
    else :
        menu()


def sqlmap():
    os.system("echo \"sqlmap is an open source penetration testing tool that automates the process of \ndetecting and exploiting SQL injection flaws and taking over of database servers \n [!]python sqlmap.py -u [<http://example.com>] --batch --banner \n More Usage [!]https://github.com/sqlmapproject/sqlmap/wiki/Usage \"|boxes -d boy | lolcat")
    userchoice = input("[1]Install [99]Back >> ")
    if userchoice == "1":
        os.system("sudo git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev")
        print("Downloaded Successfully..!!")
        sqltool()
    elif userchoice == "99":
        sqltool()
    else :
        menu()

def nosqlmap():
    os.system("echo \"NoSQLMap is an open source Python tool designed to \n audit for as well as automate injection attacks and exploit.\n \033[91m [*]Please Install MongoDB \n More Info[!]https://github.com/codingo/NoSQLMap \"|boxes -d boy | lolcat")
    choice =input("[1]install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("git clone https://github.com/codingo/NoSQLMap.git")
        os.system("sudo chmod -R 755 NoSQLMap;cd NoSQLMap;python setup.py install ")
        sqltool()
    elif choice == "2":
        os.system("python NoSQLMap")
    elif choice =="99":
        sqltool()
    else :
        menu()

def others():
    clearScr()
    print(Logo + """
    [1] SocialMedia Attack 
    [2] Android Hack
    [3] HatCloud(Bypass CloudFlare for IP)
    [4] IDN Homograph Attack Tools
    [5] Email Verifier
    [6] Hash Cracking Tools
    [99]Main Menu
    """)
    choice = input("Z4nzu =>>")
    if choice == "1":
        clearScr()
        socialattack()
    elif choice == "2":
        clearScr()
        androidhack()
    elif choice == "3":
        clearScr()
        hatcloud()
    elif choice == "4":
        clearScr()
        homograph()
    elif choice == "5":
        clearScr()
        emailverify()
    elif choice == "6":
        clearScr()
        hashcracktool()
    elif choice == "99":
        menu()
    elif choice == "":
        others()
    else :
        menu()

def showme():
    print("""
    
    [*] This tool allows you to perform OSINT and reconnaissance on an organisation or an individual. 
        It allows one to search 1.4 Billion clear text credentials which was dumped as part of BreachCompilation 
        leak This database makes finding passwords faster and easier than ever before.
            """)
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/Viralmaniar/SMWYG-Show-Me-What-You-Got.git")
        os.system("cd SMWYG-Show-Me-What-You-Got && pip3 install -r requirements.txt ")
        passwd()
    elif userchoice == "2":
        os.system("cd SMWYG-Show-Me-What-You-Got && python SMWYG.py")
    elif userchoice == "99":
        passwd()
    else :
        menu()

def hatcloud():
    os.system("echo \"HatCloud build in Ruby. It makes bypass in CloudFlare for discover real IP.\n\b [!]https://github.com/HatBashBR/HatCloud \"|boxes -d boy | lolcat")
    choice = input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("git clone https://github.com/HatBashBR/HatCloud.git")
        others()
    elif choice == "2":
        tsite=input("Enter Site >>")
        os.system("cd HatCloud;sudo ruby hatcloud.rb -b {0}".format(tsite))
    elif choice =="99":
        others()
    else :
        others()

def emailverify():
    clearScr()
    os.system("figlet -f standard -c Email Verify tools | lolcat")
    print("""
        [1]  KnockMail
        [99] Back
    """)
    choice =input("Z4nzu >>")
    if choice == "1":
        clearScr()
        knockmail()
    elif choice == "99":
        others()
    else :
        others()

def knockmail():
    os.system("echo \"KnockMail Tool Verify If Email Exists [!]https://github.com/4w4k3/KnockMail \"|boxes -d boy | lolcat")
    choice = input("[1]Install [99]Back >> ")
    if choice == "1":
        os.system("git clone https://github.com/4w4k3/KnockMail.git")
        os.system("cd KnockMail;sudo pip install -r requeriments.txt")
        emailverify()
    elif choice == "2":
        os.system("cd KnockMail;python knock.py")
    elif choice == "99":
        emailverify()
    else :
        menu()



def homograph():
    clearScr()
    os.system("figlet -f standard -c IDN Homograph Attack tools | lolcat")
    print("""
        [1]  EvilURL
        [99] Back
    """)
    choice =input("Z4nzu >>")
    if choice == "1":
        clearScr()
        evilurl()
    elif choice == "99":
        others()
    else :
        others()

def evilurl():
    os.system("echo \"Generate unicode evil domains for IDN Homograph Attack and detect them. \n [!]https://github.com/UndeadSec/EvilURL \"|boxes -d boy | lolcat")
    choice = input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("git clone https://github.com/UndeadSec/EvilURL.git")
        homograph()
    elif choice == "2":
        os.system("cd EvilURL;python3 evilurl.py")
    elif choice == "99":
        homograph()
    else :
        menu()

def hashcracktool():
    clearScr()
    os.system("figlet -f standard -c Hash Cracking Tools | lolcat")
    print("""
        [1] Hash Buster
        [99]Back
    """)
    choice = input("Z4nzu >> ")
    if choice == "1":
        clearScr()
        hashbuster()
    elif choice == "99":
        others()
    elif choice == "":
        others()
    else :
        menu()

def hashbuster():
    os.system("echo \"Features : \n Automatic hash type identification \n Supports MD5, SHA1, SHA256, SHA384, SHA512 \n [!]https://github.com/s0md3v/Hash-Buster \"|boxes -d boy | lolcat")
    choice = input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("git clone https://github.com/s0md3v/Hash-Buster.git")
        os.system("cd Hash-Buster;make install")
        time.sleep(2)
        hashcracktool()
    elif choice == "2":
        os.system("buster -h")
    elif choice == "99":
        hashcracktool()
    else :
        menu()


def Ddos():
    clearScr()
    os.system("figlet -f standard -c DDOS Attack Tools | lolcat")
    print("""
        [1]SlowLoris
        [2]aSYNcrone | Multifunction SYN Flood DDoS Weapon 
        [3]UFOnet
        [4]GoldenEye
        [99]Back
    """)
    choice =input("Z4nzu >> ")
    if choice == "1":
        clearScr()
        slowloris()
    elif choice == "2":
        clearScr()
        asyncrone()
    elif choice == "3":
        clearScr()
        ufonet()
    elif choice == "4":
        clearScr()
        goldeneye()
    elif choice == "99":
        menu()
    else :
        print("Invalid ...")
        menu()

def slowloris():
    os.system("echo \"Slowloris is basically an HTTP Denial of Service attack.It send lots of HTTP Request\"|boxes -d boy | lolcat")
    choice = input("[1]install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("sudo pip install slowloris")
        Ddos()
    elif choice == "2":
        ts=input("Enter Target Site :-")
        os.system("slowloris %s"%ts)
    elif choice == "99":
        Ddos()
    else :
        menu()

def asyncrone():
    os.system("echo \"aSYNcrone is a C language based, mulltifunction SYN Flood DDoS Weapon.\nDisable the destination system by sending a SYN packet intensively to the destination.\n\b [!] https://github.com/fatihsnsy/aSYNcrone \"|boxes -d boy | lolcat")
    choice = input("[1]install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("git clone https://github.com/fatih4842/aSYNcrone.git")
        os.system("cd aSYNcrone;sudo gcc aSYNcrone.c -o aSYNcrone -lpthread")
        Ddos()
    elif choice == "2":
        sport=input("Enter Source Port >> ")
        tip=input("Enter Target IP >> ")
        tport=input("Enter Target port >> ")
        os.system("cd aSYNcrone;sudo ./aSYNcrone {0} {1} {2} 1000".format(sport,tip,tport))
    elif choice == "99":
        Ddos()
    else :
        menu()

def ufonet():
    os.system("echo \"UFONet - is a free software, P2P and cryptographic -disruptive \n toolkit- that allows to perform DoS and DDoS attacks\n\b More Usage Visit [!]https://github.com/epsylon/ufonet \"|boxes -d boy | lolcat")
    choice = input("[1]install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("sudo git clone https://github.com/epsylon/ufonet.git")
        os.system("cd ufonet;sudo python setup.py install")
        Ddos()
    elif choice == "2":
        os.system("sudo ./ufonet --gui")
    elif choice == "99":
        Ddos()
    else :
        menu()
    
def goldeneye():
    os.system("echo \"GoldenEye is an python3 app for SECURITY TESTING PURPOSES ONLY!\nGoldenEye is a HTTP DoS Test Tool. \n\t [!]https://github.com/jseidl/GoldenEye \"|boxes -d boy | lolcat")
    choice = input("[1]install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("sudo git clone https://github.com/jseidl/GoldenEye.git;chmod -R 755 GoldenEye")
        Ddos()
    elif choice == "2":
        os.system("cd GoldenEye ;sudo ./goldeneye.py")
        print("\033[96m Go to Directory \n [*] USAGE: ./goldeneye.py <url> [OPTIONS] ")
    elif choice == "99":
        Ddos()
    else :
        menu()


def xsstools():
    clearScr()
    os.system("figlet -f standard -c XSS Attack Tools | lolcat")
    print("""
        [1] DalFox(Finder of XSS)
        [2] XSS Payload Generator
        [3] Extended XSS Searcher and Finder
        [4] XSS-Freak
        [5] XSpear 
        [6] XSSCon
        [7] XanXSS
        [8] Advanced XSS Detection Suite
        [99]BAck
    """)
    choice = input("Z4nzu >> ")
    if choice == "1":
        clearScr()
        dalfox()
    elif choice =="2":
        clearScr()
        xsspayload()
    elif choice == "99":
        menu()
    elif choice == "3":
        clearScr()
        xssfinder()
    elif choice == "4":
        clearScr()
        xssfreak()
    elif choice == "5":
        clearScr()
        xspear()
    elif choice == "6":
        clearScr()
        xsscon()
    elif choice == "7":
        clearScr()
        xanxss()
    elif choice == "8":
        clearScr()
        XSStrike()
    elif choice == "":
        menu()
    else :
        menu()

def XSStrike():
    os.system("echo \"XSStrike is a python script designed to detect and exploit XSS vulnerabilites. \"| boxes -d boy | lolcat")
    xc=input("[1]Install [99]Back >>")
    if xc == "1":
        os.system("sudo rm -rf XSStrike")
        os.system("git clone https://github.com/UltimateHackers/XSStrike.git && cd XSStrike && pip install -r requirements.txt")
        xsstools()
    elif xc == "99":
        xsstools()
    else :
        xsstools()

def dalfox():
    os.system("echo \"XSS Scanning and Parameter Analysis tool.\"|boxes -d boy | lolcat")
    choice = input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("sudo apt-get install golang")
        os.system("sudo git clone https://github.com/hahwul/dalfox ")
        os.system("cd dalfox;go install")
        xsstools()
    elif choice == "2":
        os.system("~/go/bin/dalfox")
        print("\033[96m You Need To Run manually by using  [!]~/go/bin/dalfox [options] ")
    elif choice =="99":
        xsstools()
    else :
        others()

def xsspayload():
    os.system("echo \" XSS PAYLOAD GENERATOR -XSS SCANNER-XSS DORK FINDER \"|boxes -d boy | lolcat")
    choice = input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("git clone https://github.com/capture0x/XSS-LOADER.git")
        os.system("cd XSS-LOADER;sudo pip3 install -r requirements.txt")
        xsstools()
    elif choice == "2":
        os.system("cd XSS-LOADER;sudo python3 payloader.py")
    elif choice =="99":
        xsstools()
    else :
        others()

def xssfinder():
    os.system("echo \"Extended XSS Searcher and Finder \n\b [*]https://github.com/Damian89/extended-xss-search \"|boxes -d boy | lolcat")
    choice = input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("git glone https://github.com/Damian89/extended-xss-search.git")
        print("""\033[96m 
        Follow This Steps After Installation :-
            \033[31m [*]Go To extended-xss-search directory,
                and Rename the example.app-settings.conf to app-settings.conf
        """)
    elif choice == "2":
            print("""\033[96m 
            You have To Add Links to scan
        \033[31m[!]Go to extended-xss-search
                [*]config/urls-to-test.txt
                [!]python3 extended-xss-search.py
        """)
    elif choice =="99":
        xsstools()
    else :
        others()

def xssfreak():
    os.system("echo \" XSS-Freak is an XSS scanner fully written in python3 from scratch\n\b [!]https://github.com/PR0PH3CY33/XSS-Freak \"|boxes -d boy | lolcat")
    choice = input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("git clone https://github.com/PR0PH3CY33/XSS-Freak.git")
        os.system("cd XSS-Freak;sudo pip3 install -r requirements.txt")
        xsstools()
    elif choice == "2":
        os.system("cd XSS-Freak;sudo python3 XSS-Freak.py")
    elif choice =="99":
        xsstools()
    else :
        others()

def xspear():
    os.system("echo \" XSpear is XSS Scanner on ruby gems\n\b [!]https://github.com/hahwul/XSpear \"|boxes -d boy | lolcat")
    choice = input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("gem install XSpear")
        xsstools()
    elif choice == "2":
        os.system("XSpear -h")
    elif choice =="99":
        xsstools()
    else :
        others()

def xsscon():
    os.system("echo \" [!]https://github.com/menkrep1337/XSSCon \"|boxes -d boy | lolcat")
    choice = input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("git clone https://github.com/menkrep1337/XSSCon")
        os.system("sudo chmod 755 -R XSSCon")
        xsstools()
    elif choice == "2":
        uinput= input("Enter Website >> ")
        os.system("cd XSSCon;python3 xsscon.py -u {0}".format(uinput))
    elif choice =="99":
        xsstools()
    else :
        others()

def xanxss():
    os.system("echo \" XanXSS is a reflected XSS searching tool\n that creates payloads based from templates\n\b [!]https://github.com/Ekultek/XanXSS \"|boxes -d boy | lolcat")
    choice = input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("git clone https://github.com/Ekultek/XanXSS.git ")
        xsstools()
    elif choice == "2":
        os.system("cd XanXSS ;python xanxss.py -h")
        print("\033[96m You Have to run it manually By Using \n [!]python xanxss.py [Options] ")
    elif choice =="99":
        xsstools()
    else :
        others()


def update():
    print("""
        [1] Update Tool or System 
        [2] Uninstall HackingTool
        [99]Back
    """)
    choice =input("Z4nzu >> ")
    if choice == "1":
        updatesys() 
    elif choice == "2":
        uninstall()
    elif choice == "99":
        menu()
    else :
        menu()

def updatesys():
    choice = input("[1]Update System [2]Update Hackingtool [99]Back >> ")
    if choice == "1":
        os.system("sudo apt update && sudo apt full-upgrade -y")
        os.system("sudo apt-get install tor openssl curl && sudo apt-get update tor openssl curl ")
        os.system("sudo apt-get install python3-pip")
    elif choice == "2":
        os.system("sudo chmod +x /etc/;sudo chmod +x /usr/share/doc;sudo rm -rf /usr/share/doc/hackingtool/;cd /etc/;sudo rm -rf /etc/hackingtool/;mkdir hackingtool;cd hackingtool;git clone https://github.com/Z4nzu/hackingtool.git;cd hackingtool;sudo chmod +x install.sh;./install.sh")
    elif choice == "99":
        menu()
    else :
        menu()

def uninstall():
    choice = input("[1]Uninstall [99]Back >> ")
    if choice == "1":
        print("hackingtool started to uninstall..")
        time.sleep(2)
        os.system("sudo chmod +x /etc/;sudo chmod +x /usr/share/doc;sudo rm -rf /usr/share/doc/hackingtool/;cd /etc/;sudo rm -rf /etc/hackingtool/;")
        time.sleep(3)
        print("Hackingtool Successfully Uninstall..")
        time.sleep(1)
        print("Happy Hacking..!!")
    elif choice == "99":
        update()
    else :
        print("Wrong Input...!!")
        uninstall()

def clearScr():
    if system() == 'Linux':
        os.system('clear')
    if system() == 'Windows':
        os.system('cls')

if __name__ == "__main__":
    try:
        if system() == 'Linux':
            fpath="/home/hackingtoolpath.txt"
            if os.path.isfile(fpath):
                file1 = open(fpath,"r")
                f=file1.readline()
                if os.path.exists("{0}".format(f)):
                    os.chdir(f)
                    file1.close()
                    menu()
                else :
                    os.mkdir("{0}".format(f))
                    os.chdir("{0}".format(f))
                    file1.close()
                    menu() 
            else :
                clearScr()
                print(Logo)
                print("""
                [@] Set Path (All your tools will be install in that directory) 
                        [1]Manual 
                        [2]Default
                """)
                choice = input("Z4nzu >> ")
                if choice == "1":
                    inpath=input("Enter Path(with Directory Name) >> ")
                    file =open(fpath,"w")
                    file.write(inpath)
                    file.close()
                    print("Successfully Path Set...!!")
                elif choice == "2":
                    autopath="/home/hackingtool/"
                    file =open(fpath,"w")
                    file.write(autopath)
                    file.close()
                    time.sleep(1)
                    print("Your Default Path Is :-"+autopath)
                    time.sleep(3)
                else :
                    print("Try Again..!!")
        else :
            fpath="/home/hackingtoolpath.txt"
            if os.path.isfile(fpath):
                file1 = open(fpath,"r")
                f=file1.readline()
                if os.path.exists("{0}".format(f)):
                    os.chdir(f)
                    file1.close()
                    menu()
                else :
                    os.mkdir("{0}".format(f))
                    os.chdir("{0}".format(f))
                    file1.close()
                    menu() 
            else :
                clearScr()
                print(Logo)
                print("""
                [@] Set Path (All your tools will be install in that directory) 
                        [1]Manual 
                        [2]Default
                """)
                choice = input("Z4nzu >> ")
                if choice == "1":
                    inpath=input("Enter Path(with Directory Name) >> ")
                    file =open(fpath,"w")
                    file.write(inpath)
                    file.close()
                    print("Successfully Path Set...!!")
                elif choice == "2":
                    autopath="/home/hackingtool/"
                    file =open(fpath,"w")
                    file.write(autopath)
                    file.close()
                    time.sleep(1)
                    print("Your Default Path Is :-"+autopath)
                    time.sleep(3)
                else :
                    print("Try Again..!!")
            print("Sorry Open New Issue..!!")
    except KeyboardInterrupt:        
        print("\n Sorry ..!!!")
        time.sleep(3)
