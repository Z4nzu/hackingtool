##!/usr/bin/env python3
# -*- coding: iso-8859-15 -*-
import os
import sys
import argparse
import threading
import webbrowser
import requests
# import urllib
import time
import http.client
import urllib.request
import sys
import json
import telnetlib
import glob
# import urllib2
import socket
import base64
from getpass import getpass
# from command import *
import subprocess
from sys import argv
import random
import queue
import subprocess
import re
import getpass
from os import path
from platform import system
from urllib.parse import urlparse
from xml.dom import minidom
from optparse import OptionParser
from time import sleep
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
        【T】【h】【i】【s】 【T】【o】【o】【l】 【C】【r】【e】【a】【t】【e】【d】 【B】【y】 【Z】【4】【n】【z】【u】
                                    
                                    \033[97m[!] https://github.com/Z4nzu
        \033[91m[!] This Tool is Only For Educational Purpose Please Don\'t use for Any illegal Activity [!]
\033[97m """
def menu():
    print(Logo + """\033[0m 
    \033[91m[!] This Tool Must Run as a Root..[!]] \033[97m
    [00]AnonSurf                  
    [01]Information Gathering
    [02]Password Attack && Wordlist Generator
    [03]Wireless Attack
    [04]SQL Injection Tools 
    [05]Phishing Attack 
    [06]Web Attack Tool
    [07]Post exploitation
    [08]Forensic Tools
    [09]Payload Creator
    [10]Router Exploit
    [11]Wifi Jamming
    [12]SocialMedia Attack
    [13]SocialMedia Finder 
    [14]Android Hack
    [15]Steganography
    [16]Other Tools 
    [17]Update System
    [99]Exit
    """)
    
    choice = input("Z4nzu  =>> ")
    if choice == "0" or choice == "00":
        clearScr()
        print(Logo)
        anonsurf()
    elif choice == "1" or choice == "01":
        clearScr()
        print(Logo)
        info()
    elif choice == "2" or choice == "02":
        clearScr()
        print(Logo)
        passwd()
    elif choice == "3" or choice == "03":
        clearScr()
        print(Logo)
        wire()
    elif choice == "4" or choice == "04":
        clearScr()
        print(Logo)
        sqltool()    
    elif choice == "5" or choice == "05":
        clearScr()
        print(Logo)
        phishattack()
    elif choice == "6" or choice == "06":
        clearScr()
        print(Logo)
        webAttack()        
    elif choice == "7" or choice == "07":
        clearScr()
        print(Logo)
        postexp()
    elif choice == "8" or choice == "08" :
        clearScr()
        print(Logo)
        forensic()
    elif choice == "9" or choice == "09" :
        clearScr()
        print(Logo)
        payloads()       
    elif choice == "10":
        clearScr()
        print(Logo)
        routexp()
    elif choice == "11" :
        clearScr()
        print(Logo)
        wifijamming()
    elif choice == "12" :
        clearScr()
        print(Logo)
        socialattack()       
    elif choice == "13" :
        clearScr()
        print(Logo)
        socialfinder()
    elif choice == "14":
        clearScr()
        print(Logo)
        androidhack()
    elif choice == "15":
        clearScr()
        print(Logo)
        steganography()
    elif choice == "16":
        clearScr()
        print(Logo)
        others()
    elif choice == "17":
        clearScr()
        print(Logo)
        updatesys()
    elif choice == "99" :
        clearScr(), sys.exit()
        exit()
    elif choice == "":
        menu()
    else:
        print("Wrong Input...!!")
        time.sleep(3)
        menu()

def anonsurf():
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
    os.system("echo  \"It automatically overwrites the RAM when\nthe system is shutting down AnD AlSo cHange Ip\" |boxes -d boy")
    anc=input("[1]install [2]Run [3]Stop [99]Main Menu >> ")
    if anc == "1":
        os.system("sudo git clone https://github.com/Und3rf10w/kali-anonsurf.git")
        os.system("cd kali-anonsurf && sudo ./installer.sh && cd .. && sudo rm -r kali-anonsurf")
        print("Successfully Installed ...!!")
    elif anc=="2":
        os.system("sudo anonsurf start")
    elif anc == "3":
        os.system("sudo anonsurf stop")
    elif anc == "99":
        anonsurf()
    else :
        menu()

def multitor():
    os.system("echo \"How to stay in multi places at the same time \" | boxes -d boy")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/thelinuxchoice/multitor.git")
    elif userchoice == "2":
        os.system("cd multitor && bash multitor.sh")
    elif userchoice == "99":
        anonsurf()
    else :
        menu()

def info():
    print("""
            [1]  Nmap 
            [2]  Dracnmap
            [3]  Port Scanning
            [4]  Host To IP
            [5]  Xerosploit
            [6]  Advanced XSS Detection Suite
            [7]  ReconSpider(For All Scaning)
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
        XSStrike()
    elif choice2 == "7":
        clearScr()
        reconspider()
    elif choice2 == "99":
        clearScr()
        menu()
    elif choice2 == "":
        menu()
    else:
        menu()

def nmap():
    nmapchoice = input("[1]Install [2]Run [99]BAck >> ")
    if nmapchoice == "1" :
        time.sleep(1)
        print("Start Downloading....!!")
        os.system("sudo git clone https://github.com/nmap/nmap.git")
        os.system("sudo chmod -R 755 nmap && cd nmap && sudo ./configure && make && sudo make install")
    elif nmapchoice == "2":
        os.system("sudo nmap")
    elif nmapchoice == "99":
        info()
    else:
        menu()
    
def Dracnmap():
    os.system("echo \"Dracnmap is an open source program which is using to \nexploit the network and gathering information with nmap help\" | boxes -d boy ")
    dracnap = input("[1]Install [2]Run [99]Back >> ")
    if dracnap == "1":
        os.system("sudo git clone https://github.com/Screetsec/Dracnmap.git && cd Dracnmap && chmod +x Dracnmap.sh")
    elif dracnap == "2":
        os.system("cd Dracnmap && sudo ./Dracnmap.sh")
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

def XSStrike():
    os.system("echo \"XSStrike is a python script designed to detect and exploit XSS vulnerabilites. \"| boxes -d boy")
    xc=input("[1]Install [2]Run [99]BAck >>")
    if xc == "1":
        os.system("sudo rm -rf XSStrike")
        os.system("git clone https://github.com/UltimateHackers/XSStrike.git && cd XSStrike && pip install -r requirements.txt")
    elif xc == "2" :
        clearScr()
        os.system("cd XSStrike && python xsstrike")
    elif xc == "99":
        info()
    else :
        info()

def xerosploit():
    os.system("echo \"Xerosploit is a penetration testing toolkit whose goal is to perform \n man-in-th-middle attacks for testing purposes\"|boxes -d boy")
    xeros=input("[1]Install [2]Run [99]Back >>")
    if xeros == "1":
        os.system("git clone https://github.com/LionSec/xerosploit")
        os.system("cd xerosploit && sudo python install.py")
    elif xeros == "2":
        os.system("sudo xerosploit")
    elif xeros == "99":
        info()
    else :
        menu()

def reconspider():
    os.system("echo \" ReconSpider is most Advanced Open Source Intelligence (OSINT) Framework for scanning IP Address, Emails, \nWebsites, Organizations and find out information from different sources.\" | boxes -d boy")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/bhavsec/reconspider.git")
        os.system("sudo apt install python3 python3-pip && cd reconspider && sudo python3 setup.py install")
    elif userchoice == "2":
        os.system("cd reconspider && python3 reconspider.py")
    elif userchoice == "99":
        info()
    else :
        menu()

def setoolkit():
    os.system("echo \"The Social-Engineer Toolkit is an open-source penetration\ntesting framework designed for social engineering\"| boxes -d boy")
    choiceset = input("[1]Install [2]Run [99]BAck >>")
    if choiceset == 1:
        os.system("git clone https://github.com/trustedsec/social-engineer-toolkit.git")
        os.system("python social-engineer-toolkit/setup.py")
        menu()
    if choiceset == 2:
        clearScr()
        os.system("sudo setoolkit")
    elif choiceset == 99:
        phishattack()
    else:
        menu()

def passwd():
    print("""   
                [01]Cupp
                [02]WordlistCreator
                [03]Goblin WordGenerator
                [04]Credential reuse attacks
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
    elif passchoice == "99":
        clearScr()
        menu()
    elif passchoice == "":
        menu()
    else:
        menu()

def cupp():
    os.system("echo \"Common User Password Generator..!!\"| boxes -d boy")
    cc=input("[1]Install [2]Run [99]Back >> ")
    if cc == "1":
        os.system("git clone https://github.com/Mebus/cupp.git")
        print("Download Successfully..!!!")
    elif cc == "2":
        os.system("cd cupp && ./cupp.py -h")
    elif cc == "99" :
        passwd()
    else :
        main()

def wlcreator():
    os.system("echo \" WlCreator is a C program that can create all possibilities of passwords,\n and you can choose Lenght, Lowercase, Capital, Numbers and Special Chars\" | boxes -d boy")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/thelinuxchoice/wlcreator")
    elif userchoice == "2":
        os.system("cd wlcreator && gcc -o wlcreator wlcreator.c && ./wlcreator 5")
    elif userchoice == "99":
        passwd()
    else :
        menu()

def goblinword():
    os.system("echo \" GoblinWordGenerator \" | boxes -d boy")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/UndeadSec/GoblinWordGenerator.git")
    elif userchoice == "2":
        os.system("cd GoblinWordGenerator && python3 goblin.py")
    elif userchoice == "99":
        passwd()
    else :
        menu()

def credentialattack():
    os.system("echo \"[!]Check if the targeted email is in any leaks and then use the leaked password to check it against the websites.\n[!]Check if the target credentials you found is reused on other websites/services.\n[!]Checking if the old password you got from the target/leaks is still used in any website.\n[#]This Tool Available in MAC & Windows Os \n\t[!] https://github.com/D4Vinci/Cr3dOv3r\" | boxes -d boy")
    userchoice = input("[1]Install [2]Run [99]Back >> ")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/D4Vinci/Cr3dOv3r.git")
        os.system("cd Cr3dOv3r && python3 -m pip install -r requirements.txt")
    elif userchoice == "2" :
        os.system("cd Cr3dOv3r && python3 Cr3d0v3r.py -h")
    elif userchoice == "99":
        passwd()
    else :
        menu()

def wire():
    print("""  
                [1] WiFi-Pumpkin
                [2] pixiewps
                [3] Bluetooth Honeypot GUI Framework
                [4] Fluxion
                [5] Wifiphisher
                [6] Wifite
                [7] EvilTwin 
                [99]Back To The Main Menu """)
    choice4 = input("Z4nzu ==>> ")
    if choice4 == 1:
        clearScr()
        wifipumkin()
    if choice4 == 2:
        clearScr()
        pixiewps()
    if choice4 == 3:
        clearScr()
        bluepot()
    if choice4 == 4:
        clearScr()
        fluxion()
    if choice4 == 5:
        clearScr()
        wifiphisher()
    elif choice4 == 6:
        clearScr()
        wifite()
    elif choice4 == 7:
        clearScr()
        eviltwin()
    elif choice4 == 99:
        menu()
    elif choice4 == "":
        menu()
    else:
        menu()

def wifipumkin():
    os.system("echo \"The WiFi-Pumpkin is a rogue AP framework to easily create these fake networks\nall while forwarding legitimate traffic to and from the unsuspecting target.\"| boxes -d boy")
    wp=input("[1]Install [2]Run [99]Back >>")
    if wp == 1:
        os.system("sudo git clone https://github.com/P0cL4bs/WiFi-Pumpkin.git")
        os.system("chmod -R 755 WiFi-Pumpkin && cd WiFi-Pumpkin")
        os.system("sudo pip install -r requirements.txt &&sudo ./installer.sh --install")
    elif wp == 2:
        clearScr()
        os.system("cd WiFi=Pumpkin && python wifi-pumpkin.py")
    elif wp == 99:
        wire()
    else :
        menu()

def pixiewps():
    os.system("echo \"Pixiewps is a tool written in C used to bruteforce offline the WPS pin\n exploiting the low or non-existing entropy of some Access Points, the so-called pixie dust attack\"| boxes -d boy")
    choicewps = input("[1]Install [2]Run [99]Back >> ")
    if choicewps == 1:
        os.system("sudo git clone https://github.com/wiire/pixiewps.git && apt-get -y install build-essential")
        os.system("cd pixiewps & make ")
        os.system("sudo make install")
        os.system("wget https://pastebin.com/y9Dk1Wjh")
    if choicewps == 2:
        os.system("echo \"1.>Put your interface into monitor mode using 'airmon-ng start {wireless interface}\n2.>wash -i {monitor-interface like mon0}'\n3.>reaver -i {monitor interface} -b {BSSID of router} -c {router channel} -vvv -K 1 -f\"| boxes -d boy")
    elif choicewps == 99:
        wire()
    else:
        menu()

def bluepot():
    os.system("echo \"you need to have at least 1 bluetooh receiver (if you have many it will work wiht those, too).\nYou must install/libbluetooth-dev on Ubuntu/bluez-libs-devel on Fedora/bluez-devel on openSUSE\"|boxes -d boy ")
    choice = input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("wget https://github.com/andrewmichaelsmith/bluepot/raw/master/bin/bluepot-0.1.tar.gz && tar xfz bluepot-0.1.tar.gz && sudo java -jar bluepot/BluePot-0.1.jar")
    elif choice == "2":
        os.system("cd bluepot-0.1 && sudo java -jar bluepot/BluePot-0.1.jar")
    elif choice == "99":
        wire()
    else:
        menu()

def fluxion():
    os.system("echo \"fluxion is a wifi key cracker using evil twin attack..\nyou need a wireless adaptor for this tool\"| boxes -d boy")
    choice = input("[1]Install [2]Run [99]Back >>")
    if choice == "1":
        os.system("git clone https://github.com/thehackingsage/Fluxion.git") 
        os.system("cd Fluxion && cd install && sudo chmod +x install.sh && sudo ./install.sh")
        os.system("cd .. && sudo chmod +x fluxion.sh")
    elif choice == "2":
        os.system("cd Fluxion && sudo ./fluxion.sh")
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
    wchoice=input("[1]Install [2]Run [99]Back >> ")
    if wchoice == 1:
        os.system("git clone https://github.com/wifiphisher/wifiphisher.git")
        os.system("cd wifiphisher && sudo python3 setup.py install")   
    if wchoice == 2:
        os.system("cd wifiphisher && sudo wifiphiser")
    elif wchoice == 99 :
        wire()
    else :
        menu()

def wifite():
    print(Logo)
    wc=input("[1]Install [2]Run [99]BAck >> ")
    if wc == 1:
        os.system("sudo git clone https://github.com/kimocoder/wifite2.git")
        os.system("cd wifite2 && sudo python3 setup.py install")
    elif wc ==2:
        os.system("cd wifite2 && sudo wifite")
    elif wc == 99:
        wire()
    else :
        menu()

def eviltwin():
    os.system("echo \"Fakeap is a script to perform Evil Twin Attack, by getting credentials using a Fake page and Fake Access Point \" | boxes -d boy")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/thelinuxchoice/fakeap ")
    elif userchoice == "2":
        os.system("cd fakeap && bash fakeap.sh")
    elif userchoice == "99":
        wire()
    else :
        menu()

def socialattack():
    print("""
        [1] Instagram Attack
        [2] Tweeter Attack
        [3] Facebook Attack
        [4] Application Checker
        [99]Back To Menu
    """)
    choice=input("Z4nzu >> ")
    if choice == "1":
        clearScr()
        instashell()
    elif choice == "2":
        clearScr()
        tweetshell()
    elif choice == "3":
        clearScr()
        faceshell()
    elif choice == "4" :
        clearScr()
        appcheck()
    elif choice == "99" :
        menu()
    else :
        menu()

def instashell():
    os.system("echo \"Instashell is an Shell Script to perform multi-threaded brute force attack against Instagram \"| boxes -d boy")
    instachoice=input("[1]install [2]Run [99]Back >> ")
    if instachoice == "1":
        os.system("sudo git clone https://github.com/thelinuxchoice/instashell && chmod +x install.sh && sudo ./install.sh")
    elif instachoice == "2":
        os.system("cd instashell && chmod +x instashell.sh && service tor start && sudo ./instashell.sh")
    elif instachoice == "99":
        socialattack()
    else :
        menu()

def tweetshell():
    os.system("echo \"Tweetshell is an Shell Script to perform multi-threaded brute force attack against Twitter\"|boxes -d boy")
    choice = input ("[1]Install [2]Run [99]BAck >> ")
    if choice == "1":
        os.system("sudo git clone https://github.com/thelinuxchoice/tweetshell && chmod -R 775 tweetshell")
        os.system("cd tweetshell && sudo ./install.sh")
    elif choice == "2":
        os.system("cd tweetshell && service tor start && sudo ./tweetshell.sh")
    elif choice == "99":
        socialattack()
    else :
        menu()

def faceshell():
    os.system("echo \"Facebash is an Shell Script to perform brute force attack against FAcebook\n [!]Facebook blocks account for 1 hour after 20 wrong passwords, so this script can perform only 20 pass/h \"|boxes -d boy")
    choice = input ("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("sudo git clone https://github.com/thelinuxchoice/facebash && chmod -R 775 facebash")
        os.system("cd facebash && sudo ./install.sh")
    elif choice == "2":
        os.system("cd facebash && service tor start && sudo ./facebash.sh")
    elif choice == "99":
        socialattack()
    else :
        menu()

def appcheck():
    os.system("echo \"Tool to check if an app is installed on the target device through a link.\"|boxes -d boy")
    userchoice = input("[1]Install [2]Run [99]Back >> ")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/thelinuxchoice/underhanded")
    elif userchoice == "2":
        os.system("cd underhanded &&chmod +x underhanded.sh && bash underhanded.sh")
    elif userchoice == "99":
        socialattack()
    else :
        menu()

def phishattack():
    print("""
       [1] Setoolkit 
       [2] SocialFish
       [3] Shellphish
       [4] BlackEye
       [5] I-See_You(Get Location using phishing attack) 
       [6] SayCheese (Grab target's Webcam Shots)
       [7] QR Code Jacking
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
        shellphish()
    if choice == "4":
        clearScr()
        blackeye()
    elif choice == "5":
        clearScr()
        iseeyou()
    elif choice == "6":
        clearScr()
        saycheese()
    elif choice == "7":
        clearScr()
        qrjacking()
    if choice == "99":
        clearScr()
        menu()
    elif choice == "":
        menu()
    else:
        menu()

def socialfish():
    choice=input("[1]install [2]Run [99]BAck >> ")
    if choice == "1":
        os.system("sudo git clone https://github.com/UndeadSec/SocialFish.git && sudo apt-get install python3 python3-pip python3-dev -y")
        os.system("cd SocialFish && sudo python3 -m pip install -r requirements.txt")
    elif choice =="2":
        os.system("cd SocialFish && python3 SocialFish.py root pass")
    elif choice =="99":
        phishattack()
    else :
        menu()

def shellphish():
    choice=input("[1]install [2]Run [99]BAck >> ")
    if choice == "1":
        os.system("sudo git clone https://github.com/thelinuxchoice/shellphish")
        print("Downloaded Successfully...!! ")
    elif choice =="2":
        os.system("cd shellphish && sudo bash shellphish.sh")
    elif choice =="99":
        phishattack()
    else :
        menu()

def blackeye():
    choice=input("[1]install [2]Run [99]BAck >> ")
    if choice == "1":
        os.system("sudo git clone https://github.com/thelinuxchoice/blackeye")
        print("Downloaded Successfully...!! ")
    elif choice =="2":
        os.system("cd blackeye && sudo bash blackeye.sh")
    elif choice =="99":
        phishattack()
    else :
        menu()

def iseeyou():
    os.system("echo \"[!] ISeeYou is a tool to find Exact Location of Victom By User SocialEngineering or Phishing Engagment..\n[!]Users can expose their local servers to the Internet and decode the location coordinates by looking at the log file\"|boxes -d boy")
    userchoice = input("[1]Install [2]Run [99]Back >> ")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/Viralmaniar/I-See-You.git")
        os.system("cd I-See-You && chmod u+x ISeeYou.sh")
        menu()
    elif userchoice == "2":
        os.system("cd I-See_You && sudo ./ISeeYou.sh")
    elif userchoice == "99":
        phishattack()
    else :
        menu()

def saycheese():
    os.system("echo \"Take webcam shots from target just sending a malicious link\"|boxes -d boy")
    userchoice = input("[1]Install [2]Run [99]Back >> ")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/thelinuxchoice/saycheese")
        print("Downloaded Successfully ..!!!")
    elif userchoice == "2":
        os.system("cd saycheese && bash saycheese.sh")
    elif userchoice == "99":
        phishattack()
    else :
        menu()

def qrjacking():
    os.system("echo \"QR Code Jacking (Any Website) \" | boxes -d boy")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/thelinuxchoice/ohmyqr")
    elif userchoice == "2":
        os.system("cd ohmyqr && bash ohmyqr.sh")
    elif userchoice == "99":
        phishattack()
    else :
        menu()

def socialfinder():
    print("""
        [1]Find SocialMedia By Facial Recognation System
        [2]Find SocialMedia By UserName
        [99]Back To Main Menu
    """)
    choice =input("Z4nzu =>>")
    if sfc == "1":
        clearScr()
        facialfind()
    elif sfc == "2":
        clearScr()
        userrecon()
    elif sfc == "99":
        menu()
    else :
        menu()

def facialfind():
    print(Logo)
    choice=input("[1]Install [2]Run [99]Back >>")
    if choice == "1":
        print("Firefox is Required So updating.....")
        os.system("sudo add-apt-repository ppa:mozillateam/firefox-next && sudo apt update && sudo apt upgrade")
        os.system("echo \"[!]Now You have To do some Manually\n[!]Install the Geckodriver for your operating system\n[!]Copy & Paste Link And Download File As System Configuration\n[#]https://github.com/mozilla/geckodriver/releases\n[!!]On Linux you can place it in /usr/bin \"| boxes -d boy")
        time.sleep(5)
        os.system("sudo git clone https://github.com/Greenwolf/social_mapper")
        os.system("cd social_mapper/setup")
        os.system("python3 -m pip install --no-cache-dir -r requirements.txt")
        print("Successfully Installed...!!!")
        menu()       
    elif choice == "2":
        os.system("cd social_mapper/setup")
        os.system("python social_mapper.py -h")
        print("""\033[95m 
                You have to set Username and password of your AC Or Any Fack Account
                {0}Type in Terminal nano social_mapper.py
        \n ]""")
        os.system("echo \"python social_mapper.py -f [<imageFoldername>] -i [<imgFolderPath>] -m fast [<AcName>] -fb -tw\"| boxes -d headline ")
    elif choice == "99" :
        socialfinder()
    else :
        menu()

def userrecon():
    print(Logo)
    userchoice = input("[1]Install [2]Run [99]Back >> ")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/thelinuxchoice/userrecon.git")
    elif userchoice == "2":
        os.system("cd userrecon && chmod +x userrecon.sh && sudo ./userrecon.sh")
    elif userchoice == "99":
        socialfinder()
    else :
        menu()

def forensic():
    print("""
        [1] Bulk_extractor
        [2] Disk Clone and ISO Image Aquire
        [3] AutoSpy 
        [99]Back to Menu
    """)
    choice = input("Z4nzu ==>>")
    if choice == "1" :
        clearScr()
        bulkextractor()
    elif choice == "2":
        clearScr()
        guymager()
    elif choice == "3":
        clearScr()
        autopsy()
    elif choice == "99":
        main()
    elif choice == "":
        main()
    else :
        main()

def bulkextractor():
    choice=input("""
        [1]GUI Mode(Download required)
        [2]CLI Mode
    """)
    if choice == "1":
        os.system("git clone https://github.com/simsong/bulk_extractor.git")
        print(os.getcwd())
        os.system("ls src/ && cd .. && cd java_gui && ./BEViewer")
        print("If you getting error after clone go to /java_gui/src/ And Compile .Jar file && run ./BEViewer")
    elif choice =="2":
        os.system("sudo apt-get install bulk_extractor")
        print("bulk_extractor and options")
        os.system("bulk_extractor")
        os.system("echo \"bulk_extractor [options] imagefile\" | boxes -d headline ")
    else :
        main()

def guymager():
    choice = input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("apt install guymager")
    elif choice == "2":
        clearScr()
        os.system("guymager")
    elif choice == "99":
        forensic()
    else :
        menu()

def autopsy():
    os.system("echo \"Autopsy is a platform that is used by Cyber Investigators.\n[!] Works in any Os\n[!]Recover Deleted Files from any OS & MEdia \n[!]Extract Image Metadata \"|boxes -d boy ")
    print("""
        [1]Linux Os
        [2]Windows Os(Download Required)
        [99]Back To Menu
    """)
    choice=input("Z4nzu >> ")
    if choice == "1":
        os.system("sudo autopsy")
    if choice == "2":
        wc=input(""" [1]64-Bit [2]32-Bit [99]Back >> """)
        if wc == "1":
            url = 'https://github.com/sleuthkit/autopsy/releases/download/autopsy-4.14.0/autopsy-4.14.0-64bit.msi'
            import requests
            r = requests.get(url)
            with open("autppsy.zip", "wb") as code:
                code.write(r.content)
            urllib.urlretrieve(url, "autopsyzip")
            print("Downloaded Successfully..!!")
        elif wc == "2":
            url = 'https://github.com/sleuthkit/autopsy/releases/download/autopsy-4.14.0/autopsy-4.14.0-32bit.msi'
            import requests
            r = requests.get(url)
            with open("autospy.zip", "wb") as code:
                code.write(r.content)
            urllib.urlretrieve(url, "autopsy.zip")
            print("Downloaded Successfully..!!")
        elif wc == "99":
            forensic()
    elif choice =="99":
        forensic()
    else :
        menu()

def postexp():
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
        menu()
    else :
        menu()

def vegile():
    os.system("echo \"[!]This tool will set up your backdoor/rootkits when backdoor is already setup it will be \nhidden your specific process,unlimited your session in metasploit and transparent.\"|boxes -d boy")
    vegilechoice = input("[1]Install [2]Run [99]Back >> ")
    if vegilechoice == "1":
        os.system("sudo git clone https://github.com/Screetsec/Vegile.git")
        os.system("cd Vegile && chmod +x Vegile")
        menu()
    elif vegilechoice == "2":
        os.system("echo \You can Use Command  : \n[!]Vegile -i / --inject [backdoor/rootkit] \n[!]Vegile -u / --unlimited [backdoor/rootkit] \n[!]Vegile -h / --help\"|boxes -d parchment")
        os.system("cd Vegila && sudo ./Vegila -h")
    elif vegilechoice == "99":
        postexp()
    else :
        menu()

def chromekeylogger():
    os.system("echo \" Hera Chrome Keylogger \" | boxes -d boy")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/UndeadSec/HeraKeylogger.git")
        os.system("cd HeraKeylogger && sudo apt-get install python3-pip -y && sudo pip3 install -r requirements.txt ")
    elif userchoice == "2":
        os.system("cd HeraKeylogger && python3 hera.py ")
    elif userchoice == "99":
        postexp()
    else :
        menu()

def routexp():
    print("""
        [1] RouterSploit
        [2] Fastssh 
        [99]Back to menu
    """)
    choice=int(input("Z4nzu =>> "))
    if choice == "1":
        clearScr()
        routersploit()
    elif choice=="99":
        menu()
    elif choice=="2":
        clearScr()
        fastssh()
    else :
        print("You Entered wrong Choice :")
        routexp()

def routersploit():
    os.system("echo \"The RouterSploit Framework is an open-source exploitation framework dedicated to embedded devices\"|boxes -d boy ")
    choice=input("[1]Install [2]Run [99]Back :")
    if choice == "1":
        os.system("git clone https://www.github.com/threat9/routersploit")
        os.system("cd routersploit && python3 -m pip install -r requirements.txt")
        os.system("python3 rsf.py")
    elif choice == "2":
        os.system("cd routersploit && python3 rsf.py")
    elif choice == "99":
        routexp()
    else :
        menu()

def fastssh():
    os.system("echo \"Fastssh is an Shell Script to perform multi-threaded scan \n and brute force attack against SSH protocol using the most commonly credentials. \" | boxes -d boy")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/thelinuxchoice/fastssh && cd fastssh && chmod +x fastssh.sh")
        os.system("apt-get install -y sshpass netcat")
    elif userchoice == "2":
        os.system("cd fastssh && ./fastssh.sh")
    elif userchoice == "99":
        routexp()
    else :
        menu()

def webAttack():
    print("""
        [1] SlowLoris
        [2] Skipfish
        [3] SubDomain Finder
        [4] CheckURL
        [5] Blazy(Also Find ClickJacking)
        [99]Back To Menu
    """)
    choice = input("Z4nzu >> ")
    if choice == "1":
        clearScr()
        slowloris()
    elif choice == "2":
        clearScr()
        skipfish()
    elif choice == "3":
        clearScr()
        subdomain()
    elif choice == "4":
        clearScr()
        checkurl()
    elif choice == "5":
        clearScr()
        blazy()
    elif choice == "99":
        menu()
    else :
        menu()

def slowloris():
    os.system("echo\"Slowloris is basically an HTTP Denial of Service attack.It send lots of HTTP Request\"|boxes -d boy ")
    choice = input("[1]install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("sudo pip install slowloris")
    elif choice == "2":
        print(Logo)
        ts=input("Enter Target Site :-")
        os.system("slowloris %s"%ts)
    elif choice == "99":
        webAttack()
    else :
        menu()

def skipfish():
    userchoice = input("[1]Run [99]Back >> ")
    if userchoice == "1":
        os.system("sudo skipfish -h")
        os.system("echo \"skipfish -o [FolderName] targetip/site\"|boxes -d headline")
    elif userchoice == "99":
        webAttack()
    else :
        menu()
    
def subdomain():
    print(Logo)
    choice=input("[1]install [2]Run [99]BAck >> ")
    if choice == "1":
        os.system("sudo pip install requests argparse dnspython")
        os.system("sudo git clone https://github.com/aboul3la/Sublist3r.git ")
        os.system("chmod -R 755 Sublist3r && cd Sublist3r && sudo pip install -r requirements.txt") 
        menu()
    elif choice == "2":
        print("Go to Sublist3r and run ./sublist3r")
        os.system("echo \" python sublist3r.py -d example.com \npython sublist3r.py -d example.com -p 80,443\"| boxes -d boy")
        os.system("cd Sublist3r && python sublist3r -h")
    elif choice == "99" :
        webAttack()
    else :
        main()

def checkurl():
    os.system("echo \" Detect evil urls that uses IDN Homograph Attack.\n\t[!]python3 checkURL.py --url google.com \" | boxes -d boy")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/UndeadSec/checkURL.git")
    elif userchoice == "2":
        os.system("cd checkURL && python3 checkURL.py --help")
    elif userchoice == "99":
        webAttack()
    else :
        menu()

def blazy():
    os.system("echo \"Blazy is a modern login page bruteforcer \" | boxes -d boy")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/UltimateHackers/Blazy")
        os.system("cd Blazy && sudo pip install -r requirements.txt")
    elif userchoice == "2":
        os.system("cd Blazy && python blazy.py")
    elif userchoice == "99":
        webAttack()
    else :
        menu()

def androidhack():
    print("""
        [1] Keydroid 
        [2] MySMS
        [3] Getdroid
        [4] DroidFiles (Get files from Android Directories)
        [5] Lockphish (Grab target LOCK PIN)
        [6] Whatsapp Attack
        [7] DroidCam (Capture Image)
        [8] EvilApp (Hijack Session)
        [99]Main Menu
    """)
    choice = input("Z4nzu =>>")
    if choice == "1":
        clearScr()
        keydroid()
    elif choice == "2":
        clearScr()
        mysms()
    elif choice == "3":
        clearScr()
        getdroid()
    elif choice == "5":
        clearScr()
        lock()
    elif choice == "4":
        clearScr()
        droidfile()
    elif choice  == "6":
        clearScr()
        whatshack()
    elif choice == "7":
        clearScr()
        droidcam()
    elif choice == "8":
        clearScr()
        evilapp()
    elif choice == "99":
        menu()
    else :
        menu()

def keydroid():
    os.system("echo \"Android Keylogger + Reverse Shell\n[!]You have to install Some Manually Refer Below Link :\n [+]https://github.com/thelinuxchoice/keydroid \" | boxes -d boy")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/thelinuxchoice/keydroid ")
    elif userchoice == "2":
        os.system("cd keydroid && bash keydroid.sh")
    elif userchoice == "99":
        androidhack()
    else :
        menu()

def mysms():
    os.system("echo \" Script that generates an Android App to hack SMS through WAN \n[!]You have to install Some Manually Refer Below Link :\n\t [+]https://github.com/thelinuxchoice/mysms \" | boxes -d boy")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/thelinuxchoice/mysms")
    elif userchoice == "2":
        os.system("cd mysms && bash mysms.sh")
    elif userchoice == "99":
        androidhack()
    else :
        menu()

def getdroid():
    os.system("echo \"FUD Android Payload (Reverse Shell) and Listener using Serveo.net (no need config port forwarding) \" | boxes -d boy")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/thelinuxchoice/getdroid && apt-get install android-sdk apksigner -y")
    elif userchoice == "2":
        os.system("cd getdroid && bash getdroid.sh")
    elif userchoice == "99":
        androidhack()
    else :
        menu()

def lock():
    os.system("echo \"Lockphish it's the first tool for phishing attacks on the lock screen, designed to\n Grab Windows credentials,Android PIN and iPhone Passcode using a https link. \"| boxes -d boy")
    userchoice = input("[1]Install [2]Run [99]Back >> ")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/thelinuxchoice/lockphish")
    elif userchoice == "2":
        os.system("cd lockphish && bash lockphish.sh")
    elif userchoice == "99":
        androidhack()
    else :
        menu()

def droidfile():
    os.system("echo \"Get files from Android directories\"|boxes -d boy")
    userchoice = input("[1]Install [2]Run [3] Packges Install(Required) [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/thelinuxchoice/droidfiles")
    elif userchoice == "2":
        os.system("cd droidfiles && bash droidfiles.sh")
    elif userchoice == "3":
        os.system("apt-get install default-jdk apksigner")
        os.system("apt-get install libc6-dev-i386 lib32z1")
        os.system("wget https://dl.google.com/android/repository/sdk-tools-linux-4333796.zip && mkdir -p $HOME/Android/Sdk && unzip sdk-tools-linux* -d $HOME/Android/Sdk")
        os.system("curl -s \"https://get.sdkman.io\" | bash && source $HOME/.sdkman/bin/sdkman-init.sh && echo \"Y\" | sdk install java 8.0.191-oracle && sdk use java 8.0.191-oracle && sdk install gradle 2.14.1 && sdk use gradle 2.14.1")
    elif userchoice == "99":
        androidhack()
    else :
        menu()

def whatshack():
    os.system("echo \"Script to generate Android App to Hack All WhatsApp Media Files.\n\t[!]Download Android Studio:\n[+]https://developer.android.com/studio \n\t[!]Installing Android Studio:\n[+]unzip ~/Downloads/android*.zip -d /opt \nRun Android Studio: \n[+] cd /opt/android-studio/bin \n[+] ./studio.sh \n[!]Go to SDK Manager (Configure -> SDK Manager) and Download:\n[!]Android SDK Build-tools, Android SDK-tools, Android SDK platform-tools, Support Repository\" | boxes -d shell")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/thelinuxchoice/whatshack")
        time.sleep(5)
        print("Installing Required Packges..!! It Take More Time ")
        time.sleep(3)
        os.system("apt-get install openjdk-8-jdk && apt-get install gradle")
        os.system("update-alternatives --list java")
        os.system("update-alternatives --set java /usr/lib/jvm/java-8-openjdk-amd64/jre/bin/java")
    elif userchoice == "2":
        os.system("echo \"[#]On First Time, Choose \"n\" when asks to build, then open the project on Android Studio:\n[!]cd /opt/android-studio/bin \n[!]./studio.sh \n[#]Import Gradle Project:\n[!]Choose whatshack app folder: whatshack/app/ \n[#]Wait all dependencies downloading, if you got errors, click on showed links to solve. \n[#]Try build from Android Studio: Build > build APK's \n[#]Click on showed links if you got errors. \n[#]Close Android after building successfully.\n[#]open with any Text Editor the file app/build.gradle\n[!]remove \"google\" \n[#]change gradle version from: 3.4.1 to: 2.2.0 \n[!]save and exit. \n[#]After this Run Script As Root: \n[!]bash whatshack.sh \"| boxes -d shell")
        os.system("echo \"If still getting error please visit \n\t[#]https://github.com/thelinuxchoice/whatshack\"|boxes -d shell")
        os.system("cd whatshack/ && bash whatshack.sh")
    elif userchoice == "99":
        androidhack()
    else :
        menu()

def droidcam():
    os.system("echo \"Script to generate an Android App to take photos from Cameras using Camera2 function on API 21\n After Installing if you getting error please go to below link \n[+]https://github.com/thelinuxchoice/DroidCam \"| boxes -d boy")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/thelinuxchoice/droidcam ")
        os.system("cd droidcam && sudo bash install.sh")
    elif userchoice == "2":
        os.system("cd droidcam && bash droidcam.sh")
    elif userchoice == "99":
        androidhack()
    else :
        menu()

def evilapp():
    os.system("echo \"EvilApp is a script to generate Android App that can hijack autenticated sessions in cookies\"")
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/thelinuxchoice/evilapp")
    elif userchoice == "2":
        os.system("cd evilapp && bash evilapp.sh")
    elif userchoice == "99":
        androidhack()
    else :
        menu()

def payloads():
    print("""
        [1] The FatRat*
        [2] Brutal
        [3] Stitch
        [4] MSFvenom Payload Creator
        [5] Venom Shellcode Generator 
        [6] Spycam
        [99]Back 
    """)
    choice =input("Z4nzu >> ")
    if choice == "1":
        clearScr()
        thefatrat()
    elif choice == "2":
        clearScr()
        Brutal()
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

def thefatrat():
    os.system("echo \"TheFatRat Provides An Easy way to create Backdoors and \nPayload which can bypass most anti-virus\"|boxes -d boy")
    choice = input("[1]Install [2] Run [3]Update [99]Back >>  ")
    if choice == "1":
        os.system("sudo git clone https://github.com/Screetsec/TheFatRat.git") 
        os.system("cd TheFatRat && chmod +x setup.sh")
        menu()
    elif choice == "2":
        os.system("cd TheFatRat && ./setup.sh")
    elif choice == "3":
        os.system("cd TheFatRat && ./update && chmod +x setup.sh && ./setup.sh")
    elif choice == "99":
        payloads()
    else :
        menu()

def Brutal():
    os.system("echo \"Brutal is a toolkit to quickly create various payload,powershell attack,\nvirus attack and launch listener for a Human Interface Device\"|boxes -d boy")
    print("""
    [!]Requirement
        >>Arduino Software ( I used v1.6.7 )
        >>TeensyDuino
        >>Linux udev rules
        >>Copy and paste the PaensyLib folder inside your Arduino\libraries
    [!]More Information 
        >> https://github.com/Screetsec/Brutal/wiki/Install-Requirements 
    """)
    choice = input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("sudo git clone https://github.com/Screetsec/Brutal.git")
        os.system("cd Brutal && chmod +x Brutal.sh ")
    elif choice == "2":
        os.system("cd Brutal && sudo ./Brutal.sh")
    elif choice == "99":
        payloads()
    else :
        menu()

def stitch():
    os.system("echo -e \"Stitch is Cross Platform Python Remote Administrator Tool\n\t[!]Refer Below Link For Wins & MAc Os\n\t(!)https://nathanlopez.github.io/Stitch \" | boxes -d boy | lolcat")
    choice = input("[1]Install [2]Run [99]Back >>" )
    if choice == "1":
        os.system("sudo git clone https://github.com/nathanlopez/Stitch.git")
        os.system("cd Stitch && pip install -r lnx_requirements.txt")
    elif choice == "2":
        os.system("cd Stitch && python main.py")
    elif choice == "99":
        payloads()
    else :
        menu()

def MSFvenom():
    print(Logo)
    choice= input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("sudo git clone https://github.com/g0tmi1k/msfpc.git && cd msfpc && chmod +x msfpc.sh")
        menu()
    elif choice == "2":
        os.system("cd msfpc && sudo bash msfpc.sh -h -v")
    elif choice == "99":
        payloads()
    else :
        menu()

def venom():
    print("echo \"venom 1.0.11 (malicious_server) was build to take advantage of \n apache2 webserver to deliver payloads (LAN) using a fake webpage writen in html\"| boxes -d boy")
    choice =input("[1]Install [2]Run [99]Back >> ")
    if choice == "1":
        os.system("sudo git clone https://github.com/r00t-3xp10it/venom.git")
        os.system("chmod -R 775 venom-main && cd venom-main && cd aux && sudo ./setup.sh")
        os.system("sudo ./venom.sh -u")
        print("Download Successfully...!!!")
        #sudo find ./ -name "*.sh" -exec chmod +x {} \; sudo find ./ -name "*.py" -exec chmod +x {} \;
        print("Give Permission to .sh & .py Files")
    elif choice == "2":
        os.system("cd venom && sudo ./venom.sh")
    elif choice == "99":
        payloads()
    else :
        menu()

def spycam():
    os.system("echo \"Script to generate a Win32 payload that takes the webcam image every 1 minute and send it to the attacker\"|boxes -d boy")
    userchoice = input("[1]Install [2]Run [99]Back >> ")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/thelinuxchoice/spycam ")
        os.system("cd spycam && bash install.sh && chmod +x spycam")
    elif userchoice == "2":
        os.system("cd spycam && ./spycam")
    elif userchoice == "99":
        payloads()
    else :
        menu()

def wifijamming():
    print("""
        [1] Using Airmon
        [99]Back
    """)
    choice = input("Z4nzu =>> ")
    if choice == "1":
        clearScr()
        airmon()
    elif choice == "99":
        menu()
    else :
        menu()

def airmon():
    # os.system("echo \" \" | boxes -d boy")
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
    else :
        menu()  
    # z=raw_input("Enter Your wifi Interface Name :- ")
    # os.system("airmon-ng && airmon-ng start %s"%z)

def steganography():
    print("""
        [1]SteganoHide
        [2]StegnoCracker
        [99]Back
    """)
    choice = input("Z4nz =>> ")
    if choice == "1":
        steganohide()
    elif choice == "2":
        stegnocracker()
    elif choice == "99":
        menu()
    else :
        menu()

def steganohide():
    choice = input("[1]Install [2]Run [99] >> ")
    if choice == "1":
        os.system("sudo apt-get install steghide -y ")
    elif choice == "2":
        choice1=input("[1]Hide [2]Extract >> ")
        if choice1 =="1":
            filehide=input("Enter Filename you want to Embed(1.txt) :- ")
            filetobehide=input("Enter Cover Filename(test.jpeg) :- ")
            os.system("steghide embed -cf {0} -ef {1}".format(filetobehide,filehide))
        elif choice1 =="2":
            fromfile=input("Enter Filename From Extract Data :- ")
            os.system("steghide extract -sf {0}".format(fromfile))
    elif choice == "99":
        steganography()
    else :
        menu()

def stegnocracker():
    os.system("echo \" SteganoCracker is a tool that uncover hidden data inside files\n using brute-force utility  \"|boxes -d boy")
    choice = ("[1]Install [2]Run [99] >> ")
    if choice == "1":
        os.system("pip3 install stegcracker && pip3 install stegcracker -U --force-reinstall")
    elif choice =="2":
        file1=input("Enter Filename :- ")
        passfile=input("Enter Wordlist Filename :- ")
        os.system("stegcracker {0} {1} ".format(file1,passfile))
    elif choice == "99":
        steganography()
    else :
        menu()

def sqltool():
    print("""
        [1]  sqlmap tool
        [99] Back
    """)
    choice =input("Z4nzu =>> ")
    if choice == "1":
        clearScr()
        sqlmap()
    elif choice == "99":
        menu()
    else :
        menu()

def sqlmap():
    os.system("echo \"[!]sqlmap is an open source penetration testing tool that automates the process of \ndetecting and exploiting SQL injection flaws and taking over of database servers\"|boxes -d boy")
    userchoice = input("[1]Install [2]Run [99]Back >> ")
    if userchoice == "1":
        os.system("sudo git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev")
        print("Downloaded Successfully..!!")
        menu()
    elif userchoice == "2":
        os.system("cd sqlmap && python sqlmap.py -h")
        print("echo \"[!]python sqlmap.py -u [<http://example.com>] --batch --banner \n[!]For More Usage : https://github.com/sqlmapproject/sqlmap/wiki/Usage\"|boxes -d boy")    
    elif userchoice == "99":
        sqltool()
    else :
        menu()

def others():
    print("""
    [1]SMWYG-Show-Me-What-You-Got (1.4 Billion Clear Text Password)
    [99]BAck
    """)
    choice = input("Z4nzu =>>")
    if choice == "1":
        clearScr()
        showme()
    elif choice == "99":
        menu()
    elif choice == "":
        others()
    else :
        menu()

def showme():
    print("""This tool allows you to perform OSINT and reconnaissance on an organisation or an individual. 
        It allows one to search 1.4 Billion clear text credentials which was dumped as part of BreachCompilation 
        leak This database makes finding passwords faster and easier than ever before.
            """)
    userchoice = input("[1]Install [2]Run [99]Back >>")
    if userchoice == "1":
        os.system("sudo git clone https://github.com/Viralmaniar/SMWYG-Show-Me-What-You-Got.git")
        os.system("cd SMWYG-Show-Me-What-You-Got && pip3 install -r requirements.txt ")
        menu()
    elif userchoice == "2":
        os.system("cd SMWYG-Show-Me-What-You-Got && python SMWYG.py")
    elif userchoice == "99":
        others()
    else :
        menu()

def updatesys():
    os.system("sudo apt update && sudo apt full-upgrade -y")
    os.system("sudo apt-get install tor openssl curl && sudo apt-get update tor openssl curl ")
    os.system("sudo apt-get install python3-pip")
    menu()

def clearScr():
    if system() == 'Linux':
        os.system('clear')
    if system() == 'Windows':
        os.system('cls')

if __name__ == "__main__":
    try:
        if system() == 'Linux':
            if path.exists("/home/"):
                os.chdir("/home/")
                if os.path.isdir('hackingtool'):
                    os.chdir("/home/hackingtool/")
                    menu()
                else :
                    os.system("mkdir hackingtool")
                    menu()
        elif path.exists('/data'):
            os.chdir("data/data/com.termux/files/home/")
            if os.path.isdir('hackingtool'):
                os.chdir("data/data/com.termux/files/home/hackingtool/")
                menu()
            else :
                os.system("mkdir hackingtoolstore")
                menu()
    except KeyboardInterrupt:
        print(" Sorry ..!!!")
        time.sleep(3)
