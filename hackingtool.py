##!/usr/bin/env python3
# -*- coding: UTF-8 -*-
# Version 1.1.0
import os
import subprocess
import sys
import webbrowser
import socket
from time import sleep
from platform import system

logo = """\033[33m
   ▄█    █▄       ▄████████  ▄████████    ▄█   ▄█▄  ▄█  ███▄▄▄▄      ▄██████▄           ███      ▄██████▄   ▄██████▄   ▄█       
  ███    ███     ███    ███ ███    ███   ███ ▄███▀ ███  ███▀▀▀██▄   ███    ███      ▀█████████▄ ███    ███ ███    ███ ███       
  ███    ███     ███    ███ ███    █▀    ███▐██▀   ███▌ ███   ███   ███    █▀          ▀███▀▀██ ███    ███ ███    ███ ███       
 ▄███▄▄▄▄███▄▄   ███    ███ ███         ▄█████▀    ███▌ ███   ███  ▄███                 ███   ▀ ███    ███ ███    ███ ███       
▀▀███▀▀▀▀███▀  ▀███████████ ███        ▀▀█████▄    ███▌ ███   ███ ▀▀███ ████▄           ███     ███    ███ ███    ███ ███       
  ███    ███     ███    ███ ███    █▄    ███▐██▄   ███  ███   ███   ███    ███          ███     ███    ███ ███    ███ ███       
  ███    ███     ███    ███ ███    ███   ███ ▀███▄ ███  ███   ███   ███    ███          ███     ███    ███ ███    ███ ███▌    ▄ 
  ███    █▀      ███    █▀  ████████▀    ███   ▀█▀ █▀    ▀█   █▀    ████████▀          ▄████▀    ▀██████▀   ▀██████▀  █████▄▄██ 
                                         ▀                                                                            ▀                             
                                    \033[34m[✔] https://github.com/Z4nzu/hackingtool   [✔]
                                    \033[34m[✔]            Version 1.1.0               [✔]
                                    \033[91m[X] Please Don't Use For illegal Activity  [X]
\033[97m """

class Main:
    def __init__(self):
        self.logo = logo

    def check_input(self, word, function, keys):
        if word == "":
            self.clear_scr()
            function()

        if not word in keys:
            print('\033[91m Unknown Value..')
            sleep(1)
            self.clear_scr()
            function()

    def menu(self):
        self.clear_scr()
        print(self.logo + """\033[0m 
        \033[97m
        [00] AnonSurf                  
        [01] Information Gathering
        [02] Wordlist Generator 
        [03] Wireless Attack
        [04] SQL Injection Tools 
        [05] Phishing Attack 
        [06] Web Attack Tool
        [07] Post exploitation
        [08] Forensic Tools
        [09] Payload Creator
        [10] Exploit Frameworks
        [11] Reverse Engineering 
        [12] Ddos Attack Tools 
        [13] Remote Administartor Tools
        [14] XSS Attack Tools
        [15] Steganography
        [16] More Tools 
        [17] Update or Uninstall | Hackingtool
        [99] Exit
        """)

        functions_menu = {
            '00':self.anonsurf,
            '01':self.info,
            '02':self.passwd,
            '03':self.wire,
            '04':self.sqltool,
            '05':self.phishattack,
            '06':self.webAttack,        
            '07':self.postexp,
            '08':self.forensic,
            '09':self.payloads,   
            '10':self.routexp,
            '11':self.reversetool,
            '12':self.ddos,    
            '13':self.rattools,
            '14':self.xsstools,
            '15':self.steganography,
            '16':self.others,
            '17':self.update,
            '99':self.exit_app
        }

        choice = input("Z4nzu =>> ")

        if len(choice) == 1:
            choice = '0' + choice

        self.check_input(choice, self.menu, functions_menu.keys())
        
        functions_menu[choice]()

    def clear_scr(self):
        if system() == 'Linux':
            os.system('clear')
        if system() == 'Windows':
            os.system('cls')

    def exit_app(self):
        print("Happy Hacking...")
        sleep(1)
        self.clear_scr()
        sys.exit()

###########OPTION[0]############
    def anonsurf(self):
        self.clear_scr()
        os.system("figlet -f standard -c Anonmously Hiding Tool | lolcat")

        print("""
            [1]  Anonmously Surf
            [2]  Multitor
            [99] Back
        """)

        functions_anonsurf = {
            '1':self.ansurf,
            '2':self.multitor,
            '99':self.menu
        }

        choice = input("Z4nzu =>> ")
        self.check_input(choice, self.anonsurf, functions_anonsurf.keys())

        functions_anonsurf[choice]()

    def ansurf(self):
        self.clear_scr()
        os.system("echo \"It automatically overwrites the RAM when\nthe system is shutting down AnD AlSo change Ip. \" |boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [3]Stop [99]Main Menu >> ")

        self.check_input(choice, self.ansurf, ['1', '2', '3', '99'])
        
        if choice == "1":
            os.system("sudo git clone https://github.com/Und3rf10w/kali-anonsurf.git")
            os.system("cd kali-anonsurf && sudo ./installer.sh && cd .. && sudo rm -r kali-anonsurf")
            self.ansurf()

        if choice == '2':
            os.system("sudo anonsurf start")
            self.ansurf()

        if choice == '3':
            os.system("sudo anonsurf stop")
            self.ansurf()

        if choice == "99":
            self.menu()

    def multitor(self):
        self.clear_scr()
        os.system("echo \"How to stay in multi places at the same time\n [!]https://github.com/trimstray/multitor \" | boxes -d boy | lolcat")
        choice = input("[1]Install [99]Back >> ")

        self.check_input(choice, self.multitor, ['1', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/trimstray/multitor")
            os.system("cd multitor;sudo bash setup.sh install")
            self.multitor()

        if choice == "99":
            self.anonsurf()

##################OPTION[1]########################
    def info(self):
        self.clear_scr()
        os.system("figlet -f standard -c Information Gathering Tools | lolcat")

        print("""
                 [1] Nmap 
                 [2] Dracnmap
                 [3] Port Scanning
                 [4] Host To IP
                 [5] Xerosploit
                 [6] RED HAWK (All In One Scanning)
                 [7] ReconSpider(For All Scaning)
                 [8] IsItDown (Check Website Down/Up)
                 [9] Infoga - Email OSINT
                [10] ReconDog
                [11] Striker
                [12] SecretFinder (like API & etc)
                [13] Find Info Using Shodan
                [14] Port Scanner
                [15] Breacher
                [99] Back To Main Menu 
            """)

        functions_info = {
            '1':self.nmap,
            '2':self.dracnmap,
            '3':self.ports,
            '4':self.h2ip,
            '5':self.xerosploit,
            '6':self.redhawk,
            '7':self.reconspider,
            '8':self.isitdown,
            '9':self.infogaemail,
            '10':self.recondog,
            '11':self.striker,
            '12':self.secretfinder,
            '13':self.shodantool,
            '14':self.portscanner,
            '15':self.breacher,
            '99':self.menu
        }

        choice = input("Z4nzu =>> ")
        self.check_input(choice, self.info, functions_info.keys())

        functions_info[choice]()

    def nmap(self):
        self.clear_scr()
        choice = input("[1]Install [99]Back >> ")

        self.check_input(choice, self.nmap, ['1', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/nmap/nmap.git")
            os.system("sudo chmod -R 755 nmap && cd nmap && sudo ./configure && make && sudo make install")
            self.nmap()

        if choice == "99":
            self.info()

    def dracnmap(self):
        self.clear_scr()
        os.system("echo \"Dracnmap is an open source program which is using to \nexploit the network and gathering information with nmap help \n [!]https://github.com/Screetsec/Dracnmap \" | boxes -d boy | lolcat")
        choice = input("[1]Install [99]Back >> ")

        self.check_input(choice, self.dracnmap, ['1', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/Screetsec/Dracnmap.git ")
            os.system("cd Dracnmap && chmod +x Dracnmap.sh")
            self.dracnmap()

        if choice == "99":
            self.info()

    def ports(self):
        self.clear_scr()
        target = input('Select a Target IP: ')
        subprocess.run(["sudo nmap", f" -O -Pn {target}"])
        input('\nPress Enter to back...')
        self.info()

    def h2ip(self):
        self.clear_scr()
        host = input("Enter host name (www.google.com):-  ")
        ips = socket.gethostbyname(host)
        print(ips)
        input('\nPress Enter to back...')
        self.info()
        
    def xerosploit(self):
        self.clear_scr()
        os.system("echo \"Xerosploit is a penetration testing toolkit whose goal is to perform \n man-in-th-middle attacks for testing purposes\"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.xerosploit, ['1', '2', '99'])

        if choice == "1":
            os.system("git clone https://github.com/LionSec/xerosploit")
            os.system("cd xerosploit && sudo python install.py")
            self.xerosploit()

        if choice == "2":
            os.system("sudo xerosploit")
            self.xerosploit()

        if choice == "99":
            self.info()

    def redhawk(self):
        self.clear_scr()
        os.system("echo \"All in one tool for Information Gathering and Vulnerability Scanning. \n [!]https://github.com/Tuhinshubhra/RED_HAWK \n\n [!]Please Use command [FIX] After Running Tool first time \" | boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.redhawk, ['1', '2', '99'])

        if choice == "1":
            os.system("git clone https://github.com/Tuhinshubhra/RED_HAWK")
            self.redhawk()

        if choice == "2":
            os.system("cd RED_HAWK;php rhawk.php")
            self.redhawk()

        if choice == "99":
            self.info()

    def reconspider(self):
        self.clear_scr()
        os.system("echo \" ReconSpider is most Advanced Open Source Intelligence (OSINT) Framework for scanning IP Address, Emails, \nWebsites, Organizations and find out information from different sources.\n:~python3 reconspider.py \n\t [!]https://github.com/bhavsec/reconspider \" | boxes -d boy | lolcat")
        choice = input("[1]Install [99]Back >> ")

        self.check_input(choice, self.reconspider, ['1', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/bhavsec/reconspider.git")
            os.system("sudo apt install python3 python3-pip && cd reconspider && sudo python3 setup.py install")
            self.reconspider()

        # elif choice == "2":
        #     os.system("cd reconspider && python3 reconspider.py")

        if choice == "99":
            self.info()

    def isitdown(self):
        self.clear_scr()
        os.system("echo \"Check Website Is Online or Not \"|boxes -d boy | lolcat")
        choice = input("[1]Open [99]Back >> ")

        self.check_input(choice, self.isitdown, ['1', '99'])

        if choice == "1":
            webbrowser.open_new_tab("https://www.isitdownrightnow.com/")
            self.isitdown()

        if choice == "99":
            self.info()

    def infogaemail(self):
        self.clear_scr()
        os.system("echo \"Infoga is a tool gathering email accounts informations\n(ip, hostname, country,...) from different public source \n[!]https://github.com/m4ll0k/Infoga \"| boxes -d boy |lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.infogaemail, ['1', '2', '99'])

        if choice == "1":
            os.system("git clone https://github.com/m4ll0k/Infoga.git")
            os.system("cd infoga;sudo python setup.py install")
            self.infogaemail()

        if choice == "2":
            os.system("cd infoga;python infoga.py")
            self.infogaemail()

        if choice == "99":
            self.info()

    def recondog(self):
        self.clear_scr()
        os.system("echo \"ReconDog Information Gathering Suite  \n[!]https://github.com/s0md3v/ReconDog \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.recondog, ['1', '2', '99'])

        if choice == "1":
            os.system("git clone https://github.com/s0md3v/ReconDog.git ")
            self.recondog()

        if choice == "2":
            os.system("cd ReconDog;sudo python dog")
            self.recondog()

        if choice == "99":
            self.info()

    def striker(self):
        self.clear_scr()
        os.system("echo \"Recon & Vulnerability Scanning Suite [!]https://github.com/s0md3v/Striker \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.striker, ['1', '2', '99'])

        if choice == "1":
            os.system("git clone https://github.com/s0md3v/Striker.git")
            os.system("cd Striker && pip3 install -r requirements.txt")
            self.striker()

        if choice == "2":
            site = input("Enter Site Name (example.com) >> ")
            os.system(f"cd Striker")
            subprocess.run(["sudo python3 striker.py", f"{site}"])
            self.striker()

        if choice == "99":
            self.info()

    def secretfinder(self):
        self.clear_scr()
        os.system("echo \"SecretFinder - A python script for find sensitive data \nlike apikeys, accesstoken, authorizations, jwt,..etc \n and search anything on javascript files.\n\n Usage: python SecretFinder.py -h \n\t [*]https://github.com/m4ll0k/SecretFinder \"|boxes -d boy | lolcat")
        choice = input("[1]Install [99]Back >> ")

        self.check_input(choice, self.secretfinder, ['1', '99'])
        
        if choice == "1":
            os.system("git clone https://github.com/m4ll0k/SecretFinder.git secretfinder")
            os.system("cd secretfinder; sudo pip3 install -r requirements.txt")
            self.secretfinder()

        if choice == "99":
            self.info()

    def shodantool(self):
        self.clear_scr()
        os.system("echo \"Get ports,vulnerabilities,informations,banners,..etc \n for any IP with Shodan (no apikey! no rate limit!)\n[X]Don't use this tool because your ip will be blocked by Shodan![X] \n\t [!]https://github.com/m4ll0k/Shodanfy.py \"|boxes -d boy | lolcat")
        choice = input("[1]Install [99]Back >> ")

        self.check_input(choice, self.shodantool, ['1', '99'])

        if choice == "1":
            os.system("git clone https://github.com/m4ll0k/Shodanfy.py.git")
            self.shodantool()

        if choice == "99":
            self.info()

    def portscanner(self):
        self.clear_scr()
        os.system("echo \"rang3r is a python script which scans in multi thread\n all alive hosts within your range that you specify.\n\t [!]https://github.com/floriankunushevci/rang3r \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.portscanner, ['1', '2', '99'])

        if choice == "1":
            os.system("git clone https://github.com/floriankunushevci/rang3r;sudo pip install termcolor")
            self.portscanner()

        if choice == "2":
            ip = input("Enter Ip >> ")
            os.system(f"cd rang3r")
            subprocess.run(["sudo python rang3r.py", f"--ip {ip}"])
            self.portscanner()

        if choice == "99":
            self.info()

    def breacher(self):
        self.clear_scr()
        os.system("echo \"An advanced multithreaded admin panel finder written in python.\n Usage: python breacher -u example.com \n\t [!]https://github.com/s0md3v/Breacher \"|boxes -d boy | lolcat")
        choice = input("[1]Install [99]Back >> ")

        self.check_input(choice, self.breacher, ['1', '99'])

        if choice == "1":
            os.system("git clone https://github.com/s0md3v/Breacher.git")
            self.breacher()

        if choice == "99":
            self.info()

## == Wordlist Functions == 
    def passwd(self):
        self.clear_scr()
        os.system("figlet -f standard -c Wordlist Generator | lolcat")

        print("""   
                     [1] Cupp
                     [2] WordlistCreator
                     [3] Goblin WordGenerator
                     [4] Password list((1.4 Billion Clear Text Password))
                     [5]
                    [99] Back To Main Menu
        """)

        functions_passwd = {
            '1':self.cupp,
            '2':self.wlcreator,
            '3':self.goblinword,
            # '4':self.credentialattack,
            '4':self.showme,
            '99':self.menu
        }

        choice = input("Z4nzu =>> ")
        self.check_input(choice, self.passwd, functions_passwd.keys())

        functions_passwd[choice]()

    def cupp(self):
        self.clear_scr()
        os.system("echo \"Common User Password Generator..!!\"| boxes -d boy | lolcat ")
        choice = input("[1]Install [99]Back >> ")

        self.check_input(choice, self.cupp, ['1', '99'])

        if choice == "1":
            os.system("git clone https://github.com/Mebus/cupp.git")
            self.cupp()

        # if choice == "2":
        #    os.system("cd cupp && ./cupp.py -h")

        if choice == "99":
            self.passwd()

    def wlcreator(self):
        self.clear_scr()
        os.system("echo \" WlCreator is a C program that can create all possibilities of passwords,\n and you can choose Lenght, Lowercase, Capital, Numbers and Special Chars\" | boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.wlcreator, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/Z4nzu/wlcreator")
            self.wlcreator()

        if choice == "2":
            os.system("cd wlcreator && sudo gcc -o wlcreator wlcreator.c && ./wlcreator 5")
            self.wlcreator()

        if choice == "99":
            self.passwd()

    def goblinword(self):
        self.clear_scr()
        os.system("echo \" GoblinWordGenerator \" | boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.goblinword, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/UndeadSec/GoblinWordGenerator.git")
            self.goblinword()

        if choice == "2":
            os.system("cd GoblinWordGenerator && python3 goblin.py")
            self.goblinword()

        if choice == "99":
            self.passwd()

    def showme(self):
        self.clear_scr()
        print("""
        [*] This tool allows you to perform OSINT and reconnaissance on an organisation or an individual. 
            It allows one to search 1.4 Billion clear text credentials which was dumped as part of BreachCompilation 
            leak This database makes finding passwords faster and easier than ever before.
                """)

        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.showme, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/Viralmaniar/SMWYG-Show-Me-What-You-Got.git")
            os.system("cd SMWYG-Show-Me-What-You-Got && pip3 install -r requirements.txt ")
            self.showme()

        if choice == "2":
            os.system("cd SMWYG-Show-Me-What-You-Got && python SMWYG.py")
            self.showme()

        if choice == "99":
            self.passwd()

                                            ##  Wireless Attack =====
    def wire(self):
        self.clear_scr()
        os.system("figlet -f standard -c Wireless Attack Tools | lolcat")

        print("""  
                [1]  WiFi-Pumpkin
                [2]  pixiewps
                [3]  Bluetooth Honeypot GUI Framework
                [4]  Fluxion
                [5]  Wifiphisher
                [6]  Wifite
                [7]  EvilTwin 
                [8]  Fastssh
                [9]  Howmanypeople
                [99] Back To The Main Menu """)

        functions_wire = {
            '1':self.wifipumkin,
            '2':self.pixiewps,
            '3':self.bluepot,
            '4':self.fluxion,
            '5':self.wifiphisher,
            '6':self.wifite,
            '7':self.eviltwin,
            '9':self.howmanypeople,
            '8':self.fastssh,
            '99':self.menu
        }

        choice = input("Z4nzu =>> ")
        self.check_input(choice, self.wire, functions_wire.keys())

        functions_wire[choice]()

    def fastssh(self):
        self.clear_scr()
        os.system("echo \"Fastssh is an Shell Script to perform multi-threaded scan \n and brute force attack against SSH protocol using the most commonly credentials. \" | boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.fastssh, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/Z4nzu/fastssh && cd fastssh && sudo chmod +x fastssh.sh")
            os.system("sudo apt-get install -y sshpass netcat")
            self.fastssh()

        if choice == "2":
            os.system("cd fastssh && sudo bash fastssh.sh --scan")
            self.fastssh()

        if choice == "99":
            self.wire()


    def wifipumkin(self):
        self.clear_scr()
        os.system("echo \"The WiFi-Pumpkin is a rogue AP framework to easily create these fake networks\nall while forwarding legitimate traffic to and from the unsuspecting target.\"| boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.wifipumkin, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo apt install libssl-dev libffi-dev build-essential")
            os.system("sudo git clone https://github.com/P0cL4bs/wifipumpkin3.git")
            os.system("chmod -R 755 wifipumpkin3 && cd wifipumpkin3")
            os.system("sudo apt install python3-pyqt5 ")
            os.system("sudo python3 setup.py install")
            self.wifipumkin()

        if choice == "2":
            os.system("sudo wifipumpkin3")
            self.wifipumkin()

        if choice == "99":
            self.wire()

    def pixiewps(self):
        self.clear_scr()
        os.system("echo \"Pixiewps is a tool written in C used to bruteforce offline the WPS pin\n exploiting the low or non-existing entropy of some Access Points, the so-called pixie dust attack\"| boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.pixiewps, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/wiire/pixiewps.git && apt-get -y install build-essential")
            os.system("cd pixiewps*/ && make ")
            os.system("cd pixiewps*/ && sudo make install && wget https://pastebin.com/y9Dk1Wjh")
            self.pixiewps()

        if choice == "2":
            os.system("echo \"1.>Put your interface into monitor mode using 'airmon-ng start {wireless interface}\n2.>wash -i {monitor-interface like mon0}'\n3.>reaver -i {monitor interface} -b {BSSID of router} -c {router channel} -vvv -K 1 -f\"| boxes -d boy")
            print("You Have To Run Manually By USing >>pixiewps -h ")
            self.pixiewps()
    
        if choice == "99":
            self.wire()

    def bluepot(self):
        self.clear_scr()
        os.system("echo \"you need to have at least 1 bluetooh receiver (if you have many it will work wiht those, too).\nYou must install/libbluetooth-dev on Ubuntu/bluez-libs-devel on Fedora/bluez-devel on openSUSE\"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.bluepot, ['1', '2', '99'])

        if choice == "1":
            os.system("wget https://github.com/andrewmichaelsmith/bluepot/raw/master/bin/bluepot-0.1.tar.gz && tar xfz bluepot-0.1.tar.gz && sudo java -jar bluepot/BluePot-0.1.jar")
            self.bluepot()

        if choice == "2":
            os.system("cd bluepot-0.1 && sudo java -jar bluepot/BluePot-0.1.jar")
            self.bluepot()

        if choice == "99":
            self.wire()

    def fluxion(self):
        self.clear_scr()
        os.system("echo \"Fluxion is a wifi key cracker using evil twin attack..\nyou need a wireless adaptor for this tool\"| boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.fluxion, ['1', '2', '99'])

        if choice == "1":
            os.system("git clone https://github.com/thehackingsage/Fluxion.git") 
            os.system("cd Fluxion && cd install && sudo chmod +x install.sh && sudo bash install.sh")
            os.system("cd .. ; sudo chmod +x fluxion.sh")
            self.fluxion()

        if choice == "2":
            os.system("cd Fluxion;sudo bash fluxion.sh")
            self.fluxion()

        if choice == "99":
            self.wire()

    def wifiphisher(self):
        self.clear_scr()
        print("""
        Wifiphisher is a rogue Access Point framework for conducting red team engagements or Wi-Fi security testing. 
        Using Wifiphisher, penetration testers can easily achieve a man-in-the-middle position against wireless clients by performing 
        targeted Wi-Fi association attacks. Wifiphisher can be further used to mount victim-customized web phishing attacks against the
        connected clients in order to capture credentials (e.g. from third party login pages or WPA/WPA2 Pre-Shared Keys) or infect the 
        victim stations with malware..\n
        For More Details Visit >> https://github.com/wifiphisher/wifiphisher
        """)

        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.wifiphisher, ['1', '2', '99'])

        if choice == "1":
            os.system("git clone https://github.com/wifiphisher/wifiphisher.git")
            os.system("cd wifiphisher;sudo python3 setup.py install")   
            self.wifiphisher()

        if choice == "2":
            os.system("cd wifiphisher;sudo wifiphisher")

        if choice == "99":
            self.wire()

    def wifite(self):
        self.clear_scr()
        os.system("echo \"[!]https://github.com/derv82/wifite2 \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.wifite, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/derv82/wifite2.git")
            os.system("cd wifite2 && sudo python3 setup.py install ; sudo pip3 install -r requirements.txt")
            self.wifite()

        if choice == "2":
            os.system("cd wifite2; sudo wifite")
            self.wifite()
        if choice == "99":
            self.wire()

    def eviltwin(self):
        self.clear_scr()
        os.system("echo \"Fakeap is a script to perform Evil Twin Attack, by getting credentials using a Fake page and Fake Access Point \" | boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.eviltwin, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/Z4nzu/fakeap")
            self.eviltwin()

        if choice == "2":
            os.system("cd fakeap && sudo bash fakeap.sh")
            self.eviltwin()

        if choice == "99":
            self.wire()

    def howmanypeople(self):
        self.clear_scr()
        os.system("echo \"Count the number of people around you by monitoring wifi signals.\n[@]WIFI ADAPTER REQUIRED* \n[*]It may be illegal to monitor networks for MAC addresses, \nespecially on networks that you do not own. Please check your country's laws\n\t [!]https://github.com/An0nUD4Y/howmanypeoplearearound \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.howmanypeople, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo apt-get install tshark;sudo pip install howmanypeoplearearound")
            self.howmanypeople()

        if choice == "2":
            os.system("sudo howmanypeoplearearound")
            self.howmanypeople()

        if choice == "99":
            self.wire()
                                                    ## PHISHING ATTACK START ###
    def phishattack(self):
        self.clear_scr()
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
         [9] BlackPhish
        [99] Back To Main Menu
        """)

        functions_phishattack = {
            '1':self.setoolkit,
            '2':self.socialfish,
            '3':self.hiddeneye,
            '4':self.evilginx,
            '5':self.iseeyou,
            '6':self.saycheese,
            '7':self.qrjacking,
            '8':self.shellphish,
            '9':self.blackphish,
            '99':self.menu
        }

        choice = input("Z4nzu =>> ")
        self.check_input(choice, self.phishattack, functions_phishattack.keys())

        functions_phishattack[choice]()

    def blackphish(self):
        self.clear_scr()
        os.system("echo \"BlackPhish  [!]https://github.com/iinc0gnit0/BlackPhish \" | boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [3]Update [99]Back >> ")

        self.check_input(choice, self.blackphish, ['1', '2','3', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/iinc0gnit0/BlackPhish ")
            os.system("cd BlackPhish;sudo bash install.sh")
            self.blackphish()

        if choice == "2":
            os.system("cd BlackPhish;sudo python3 blackphish.py")
        if choice == "3":
            os.system("cd BlackPhish;sudo bash update.sh")
        if choice == "99":
            self.phishattack()

    def setoolkit(self):
        self.clear_scr()
        os.system("echo \"The Social-Engineer Toolkit is an open-source penetration\ntesting framework designed for social engineering\"| boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.setoolkit, ['1', '2', '99'])

        if choice == "1":
            os.system("git clone https://github.com/trustedsec/social-engineer-toolkit.git")
            os.system("sudo python social-engineer-toolkit/setup.py")
            self.setoolkit()

        if choice == "2":
            self.clear_scr()
            os.system("sudo setoolkit")
            self.setoolkit()

        if choice == "99":
            self.phishattack()

    def socialfish(self):
        self.clear_scr()
        os.system("echo \"Automated Phishing Tool & Information Collector \n\t[!]https://github.com/UndeadSec/SocialFish \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.socialfish, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/UndeadSec/SocialFish.git && sudo apt-get install python3 python3-pip python3-dev -y")
            os.system("cd SocialFish && sudo python3 -m pip install -r requirements.txt")
            self.socialfish()

        if choice == "2":
            os.system("cd SocialFish && sudo python3 SocialFish.py root pass")
            self.socialfish()

        if choice == "99":
            self.phishattack()

    def hiddeneye(self):
        self.clear_scr()
        os.system("echo \"Modern Phishing Tool With Advanced Functionality And Multiple Tunnelling Services \n\t [!]https://github.com/DarkSecDevelopers/HiddenEye \"|boxes -d boy | lolcat ")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.hiddeneye, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/DarkSecDevelopers/HiddenEye.git ;sudo chmod 777 HiddenEye")
            os.system("cd HiddenEye;sudo pip3 install -r requirements.txt;sudo pip3 install requests;pip3 install pyngrok")
            self.hiddeneye()

        if choice == "2":
            os.system("cd HiddenEye;sudo python3 HiddenEye.py")
            self.hiddeneye()

        if choice == "99":
            self.phishattack()

    def evilginx(self):
        self.clear_scr()
        os.system("echo \"evilginx2 is a man-in-the-middle attack framework used for phishing login credentials along with session cookies,\nwhich in turn allows to bypass 2-factor authentication protection.\n\n\t [+]Make sure you have installed GO of version at least 1.14.0 \n[+]After installation, add this to your ~/.profile, assuming that you installed GO in /usr/local/go\n\t [+]export GOPATH=$HOME/go \n [+]export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin \n[+]Then load it with source ~/.profiles.\n [*]https://github.com/An0nUD4Y/evilginx2 \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.evilginx, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo apt-get install git make;go get -u github.com/kgretzky/evilginx2")
            os.system("cd $GOPATH/src/github.com/kgretzky/evilginx2;make")
            os.system("sudo make install;sudo evilginx")
            self.evilginx()

        if choice == "2":
            os.system("sudo evilginx")
            self.evilginx()
            
        if choice == "99":
            self.phishattack()

    def iseeyou(self):
        self.clear_scr()
        os.system("echo \"[!] ISeeYou is a tool to find Exact Location of Victom By User SocialEngineering or Phishing Engagment..\n[!]Users can expose their local servers to the Internet and decode the location coordinates by looking at the log file\"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.iseeyou, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/Viralmaniar/I-See-You.git")
            os.system("cd I-See-You && sudo chmod u+x ISeeYou.sh")
            self.iseeyou()

        if choice == "2":
            os.system("cd I-See-You && sudo bash ISeeYou.sh")
            self.iseeyou()

        if choice == "99":
            self.phishattack()

    def saycheese(self):
        self.clear_scr()
        os.system("echo \"Take webcam shots from target just sending a malicious link\"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.saycheese, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/hangetzzu/saycheese")
            self.saycheese()

        if choice == "2":
            os.system("cd saycheese && sudo bash saycheese.sh")
            self.saycheese()

        if choice == "99":
            self.phishattack()

    def qrjacking(self):
        self.clear_scr()
        os.system("echo \"QR Code Jacking (Any Website) \" | boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.qrjacking, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/cryptedwolf/ohmyqr && sudo apt-get install scrot")
            self.qrjacking()

        if choice == "2":
            os.system("cd ohmyqr && sudo bash ohmyqr.sh")
            self.qrjacking()

        if choice == "99":
            self.phishattack()

    def shellphish(self):
        self.clear_scr()
        os.system("echo \"Phishing Tool for 18 social media \n\t[!]https://github.com/An0nUD4Y/shellphish \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.shellphish, ['1', '2', '99'])

        if choice == "1":
            os.system("git clone https://github.com/An0nUD4Y/shellphish")
            self.shellphish()

        if choice == "2":
            os.system("cd shellphish;sudo bash shellphish.sh")
            self.shellphish()

        if choice == "99":
            self.phishattack()

                                                ### Forensic Tools ####
    def forensic(self):
        self.clear_scr()
        os.system("figlet -f standard Forensic Tools | lolcat ")

        print("""
             [1] Autopsy
             [2] Wireshark
             [3] Bulk_extractor 
             [4] Disk Clone and ISO Image Aquire
             [5] Toolsley
            [99] Back to Menu
        """)

        functions_forensic = {
            '1':self.autopsy,
            '2':self.wireshark,
            '3':self.bulkextractor,
            '4':self.guymager,
            '5':self.toolsley,
            '99':self.menu
        }

        choice = input("Z4nzu =>> ")
        self.check_input(choice, self.forensic, functions_forensic.keys())
        
        functions_forensic[choice]()

    def autopsy(self):
        self.clear_scr()
        os.system("echo \"Autopsy is a platform that is used by Cyber Investigators.\n[!] Works in any Os\n[!]Recover Deleted Files from any OS & MEdia \n[!]Extract Image Metadata \"|boxes -d boy | lolcat")
        choice = input("[1]Run [99]Back >> ")

        self.check_input(choice, self.autopsy, ['1', '99'])

        if choice == "1":
            os.system("sudo autopsy")
            self.autopsy()
        
        if choice =="99":
            self.forensic()

    def wireshark(self):
        self.clear_scr()
        os.system("echo \" Wireshark is a network capture and analyzer \ntool to see what’s happening in your network.\n And also investigate Network related incident \" | boxes -d boy | lolcat")
        choice = input("[1]Run [99]Back >> ")

        self.check_input(choice, self.wireshark, ['1', '99'])

        if choice == "1":
            os.system("sudo wireshark")
            self.wireshark()

        if choice == "99":
            self.forensic()

    def bulkextractor(self):
        self.clear_scr()
        print("""
            [1]  GUI Mode (Download required)
            [2]  CLI Mode
            [99] Back
        """)

        choice = input("Z4nzu =>> ")
        self.check_input(choice, self.bulkextractor, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/simsong/bulk_extractor.git")
            os.system("ls src/ && cd .. && cd java_gui && ./BEViewer")
            print("If you getting error after clone go to /java_gui/src/ And Compile .Jar file && run ./BEViewer")
            print("Please Visit For More Details About Installation >> https://github.com/simsong/bulk_extractor ")
            self.bulkextractor()

        if choice == "2":
            os.system("sudo apt-get install bulk_extractor")
            print("bulk_extractor and options")
            os.system("bulk_extractor")
            os.system("echo \"bulk_extractor [options] imagefile\" | boxes -d headline | lolcat")
            self.bulkextractor()

        if choice == "99":
            self.forensic()

    def guymager(self):
        self.clear_scr()
        os.system("echo \"Guymager is a free forensic imager for media acquisition.\n [!]https://guymager.sourceforge.io/ \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.guymager, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo apt install guymager")
            self.guymager()

        if choice == "2":
            os.system("sudo guymager")
            self.guymager()

        if choice == "99":
            self.forensic()
        
    def toolsley(self):
        self.clear_scr()
        os.system("echo \" Toolsley got more than ten useful tools for investigation.\n[+]File signature verifier\n[+]File identifier \n[+]Hash & Validate \n[+]Binary inspector \n [+]Encode text \n[+]Data URI generator \n[+]Password generator \" | boxes -d boy | lolcat")
        choice = input("[1]Open [99]Back >> ")

        self.check_input(choice, self.toolsley, ['1', '99'])

        if choice == "1":
            webbrowser.open_new_tab('https://www.toolsley.com/')
            self.toolsley()

        if choice == "99":
            self.forensic()

    def postexp(self):
        self.clear_scr()
        os.system("figlet -f standard post explotations | lolcat")

        print("""
             [1] Vegile - Ghost In The Shell
             [2] Chrome Keylogger
            [99] Back 
        """)

        functions_postexp = {
            '1':self.vegile,
            '2':self.chromekeylogger,
            '99':self.menu
        }

        choice = input("Z4nzu =>> ")
        self.check_input(choice, self.postexp, functions_postexp.keys())

        self.clear_scr()
        functions_postexp[choice]()

    def vegile(self):
        self.clear_scr()
        os.system("echo \"[!]This tool will set up your backdoor/rootkits when backdoor is already setup it will be \nhidden your specific process,unlimited your session in metasploit and transparent.\"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.vegile, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/Screetsec/Vegile.git")
            os.system("cd Vegile && sudo chmod +x Vegile")
            self.vegile()

        if choice == "2":
            os.system("echo \"You can Use Command: \n[!]Vegile -i / --inject [backdoor/rootkit] \n[!]Vegile -u / --unlimited [backdoor/rootkit] \n[!]Vegile -h / --help\"|boxes -d parchment")
            os.system("cd Vegile && sudo bash Vegile ")
            self.vegile()

        if choice == "99":
            self.postexp()

    def chromekeylogger(self):
        self.clear_scr()
        os.system("echo \" Hera Chrome Keylogger \" | boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.chromekeylogger, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/UndeadSec/HeraKeylogger.git")
            os.system("cd HeraKeylogger && sudo apt-get install python3-pip -y && sudo pip3 install -r requirements.txt ")
            self.chromekeylogger()

        if choice == "2":
            os.system("cd HeraKeylogger && sudo python3 hera.py ")
            self.chromekeylogger()

        if choice == "99":
            self.postexp()
                            #### FrameWORKS 
    def routexp(self):
        self.clear_scr()
        os.system("figlet -f standard Exploit Framework | lolcat ")

        print("""
             [1] RouterSploit
             [2] WebSploit
             [3] Commix
             [4] Web2Attack
            [99] Back to menu
        """)

        functions_routexp = {
            '1':self.routersploit,
            '2':self.websploit,
            '3':self.commix,
            '4':self.web2attack,
            '99':self.menu
        }
        
        choice = input("Z4nzu =>> ")
        self.check_input(choice, self.routexp, functions_routexp.keys())

        functions_routexp[choice]()

    def routersploit(self):
        self.clear_scr()
        os.system("echo \"The RouterSploit Framework is an open-source exploitation framework dedicated to embedded devices\"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.routersploit, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://www.github.com/threat9/routersploit")
            os.system("cd routersploit && sudo python3 -m pip install -r requirements.txt")
            self.routersploit()

        if choice == "2":
            os.system("cd routersploit && sudo python3 rsf.py")
            self.routersploit()

        if choice == "99":
            self.routexp()

    def websploit(self):
        self.clear_scr()
        os.system("echo \"Websploit is an advanced MITM framework.\n\t [!]https://github.com/The404Hacking/websploit \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.websploit, ['1', '2', '99'])

        if choice == "1":
            os.system("https://github.com/The404Hacking/websploit.git")
            self.websploit()

        if choice == "2":
            os.system("cd websploit;python3 websploit.py")
            self.websploit()

        if choice == "99":
            self.routexp()

    def commix(self):
        self.clear_scr()
        os.system("echo \"Automated All-in-One OS command injection and exploitation tool.\nCommix can be used from web developers, penetration testers or even security researchers\n in order to test web-based applications with the view to find bugs,\n errors or vulnerabilities related to command injection attacks.\n Usage: python commix.py [option(s)] \n\n\t[!]https://github.com/commixproject/commix  \"|boxes -d boy | lolcat")
        choice = input("[1]Install [99]Back >> ")

        self.check_input(choice, self.commix, ['1', '99'])

        if choice == "1":
            os.system("git clone https://github.com/commixproject/commix.git commix")
            self.commix()

        if choice == "99":
            self.routexp()
            
                            ### Web Attack Function
    def webAttack(self):
        self.clear_scr()
        os.system("figlet 'Web Attack Tools' -f standard -c | lolcat")

        print("""
             [1] Web2Attack
             [2] Skipfish
             [3] SubDomain Finder
             [4] CheckURL
             [5] Blazy(Also Find ClickJacking)
             [6] Sub-Domain TakeOver
             [7] Dirb
            [99] Back To Menu
        """)

        functions_webAttack = {
            '1':self.web2attack,
            '2':self.skipfish,
            '3':self.subdomain,
            '4':self.checkurl,
            '5':self.blazy,
            '6':self.subdomaintakeover,
            '7':self.dirb,
            '99':self.menu
        }

        choice = input("Z4nzu =>> ")
        self.check_input(choice, self.webAttack, functions_webAttack.keys())
           
        functions_webAttack[choice]()

    def dirb(self):
        self.clear_scr()
        os.system("echo \"DIRB is a Web Content Scanner. It looks for existing (and/or hidden) Web Objects.\nIt basically works by launching a dictionary based attack against \n a web server and analizing the response.\n\t [!]https://gitlab.com/kalilinux/packages/dirb \" | boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.dirb, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://gitlab.com/kalilinux/packages/dirb.git")
            os.system("cd dirb;sudo ./configure;make")
            self.dirb()

        if choice == "2":
            uinput = input("Enter Url >> ")
            os.system("sudo dirb {0}".format(uinput))

        if choice == "99":
            self.webAttack()

    def web2attack(self):
        self.clear_scr()
        os.system("echo \"Web hacking framework with tools, exploits by python \n[!]https://github.com/santatic/web2attack \"| boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.web2attack, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/santatic/web2attack.git")
            self.web2attack()

        if choice == "2":
            os.system("cd web2attack && sudo bash w2aconsole")
            self.web2attack()

        if choice == "99":
            self.webAttack()

    def skipfish(self):
        self.clear_scr()
        os.system("echo \"Skipfish – Fully automated, active web application security reconnaissance tool \n Usage: skipfish -o [FolderName] targetip/site \n[!]https://tools.kali.org/web-applications/skipfish \"|boxes -d headline | lolcat")
        choice = input("[1]Run [99]Back >> ")

        self.check_input(choice, self.skipfish, ['1', '99'])

        if choice == "1":
            os.system("sudo skipfish -h")
            os.system("echo \"skipfish -o [FolderName] targetip/site\"|boxes -d headline | lolcat")
            self.skipfish()

        if choice == "99":
            self.webAttack()
        
    def subdomain(self):
        self.clear_scr()
        os.system("echo \"Sublist3r is a python tool designed to enumerate subdomains of websites using OSINT \n Usage:\n\t[1]python sublist3r.py -d example.com \n[2]python sublist3r.py -d example.com -p 80,443\"| boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.subdomain, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo pip install requests argparse dnspython")
            os.system("sudo git clone https://github.com/aboul3la/Sublist3r.git ")
            os.system("cd Sublist3r && sudo pip install -r requirements.txt") 
            self.subdomain()

        if choice == "2":
            os.system("cd Sublist3r && python sublist3r.py -h")
            self.subdomain()

        if choice == "99":
            self.webAttack()

    def checkurl(self):
        self.clear_scr()
        os.system("echo \" Detect evil urls that uses IDN Homograph Attack.\n\t[!]python3 checkURL.py --url google.com \" | boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.checkurl, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/UndeadSec/checkURL.git")
            self.checkurl()

        if choice == "2":
            os.system("cd checkURL && python3 checkURL.py --help")
            self.checkurl()

        if choice == "99":
            self.webAttack()

    def blazy(self):
        self.clear_scr()
        os.system("echo \"Blazy is a modern login page bruteforcer \" | boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.blazy, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/UltimateHackers/Blazy")
            os.system("cd Blazy && sudo pip install -r requirements.txt")
            self.blazy()

        if choice == "2":
            os.system("cd Blazy && sudo python blazy.py")
            self.blazy()

        if choice == "99":
            self.webAttack()

    def subdomaintakeover(self):
        self.clear_scr()
        os.system("echo \"Sub-domain takeover vulnerability occur when a sub-domain \n (subdomain.example.com) is pointing to a service (e.g: GitHub, AWS/S3,..)\nthat has been removed or deleted.\nUsage:python3 takeover.py -d www.domain.com -v \n\t[!]https://github.com/m4ll0k/takeover \"|boxes -d boy | lolcat")
        choice = input("[1]Install [99]Back >> ")

        self.check_input(choice, self.subdomaintakeover, ['1', '99'])

        if choice == "1":
            os.system("git clone https://github.com/m4ll0k/takeover.git")
            os.system("cd takeover;sudo python3 setup.py install")
            self.subdomaintakeover()

        if choice == "99":
            self.webAttack()

    def payloads(self):
        self.clear_scr()
        os.system("figlet -f standard -c Payloads | lolcat")

        print("""
             [1] The FatRat 
             [2] Brutal
             [3] Stitch
             [4] MSFvenom Payload Creator
             [5] Venom Shellcode Generator 
             [6] Spycam
             [7] Mob-Droid
             [8] Enigma 
            [99] Back 
        """)

        functions_payloads = {
            '1':self.thefatrat,
            '2':self.brutal,
            '3':self.stitch,
            '4':self.msf_venom,
            '5':self.venom,
            '6':self.spycam,
            '7':self.mobdroid,
            '8':self.enigma,
            '99':self.menu
        }

        choice = input("Z4nzu =>> ")
        self.check_input(choice, self.payloads, functions_payloads.keys())

        functions_payloads[choice]()

    def thefatrat(self):
        self.clear_scr()
        os.system("echo \"TheFatRat Provides An Easy way to create Backdoors and \nPayload which can bypass most anti-virus\"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [3]Update [4]TroubleShoot (if not run) [99]Back >>  ")

        self.check_input(choice, self.thefatrat, ['1', '2', '3', '4', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/Screetsec/TheFatRat.git") 
            os.system("cd TheFatRat && sudo chmod +x setup.sh")
            self.thefatrat()

        if choice == "2":
            os.system("cd TheFatRat && sudo bash setup.sh")
            self.thefatrat()

        if choice == "3":
            os.system("cd TheFatRat && bash update && chmod +x setup.sh && bash setup.sh")
            self.thefatrat()

        if choice == "4":
            os.system("cd TheFatRat && sudo chmod +x chk_tools && ./chk_tools")
            self.thefatrat()

        if choice == "99":
            self.payloads()

    def brutal(self):
        self.clear_scr()
        os.system("echo \"Brutal is a toolkit to quickly create various payload,powershell attack,\nvirus attack and launch listener for a Human Interface Device\"|boxes -d boy | lolcat")
        
        print("""
        [!]Requirement
            >>Arduino Software (I used v1.6.7)
            >>TeensyDuino
            >>Linux udev rules
            >>Copy and paste the PaensyLib folder inside your Arduino\libraries

        [!]Kindly Visit below link for Installation for Arduino 
            >> https://github.com/Screetsec/Brutal/wiki/Install-Requirements 
        """)

        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.brutal, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/Screetsec/Brutal.git")
            os.system("cd Brutal && sudo chmod +x Brutal.sh ")
            self.brutal()

        if choice == "2":
            os.system("cd Brutal && sudo bash Brutal.sh")
            self.brutal()

        if choice == "99":
            self.payloads()

    def stitch(self):
        self.clear_scr()
        os.system("echo \"Stitch is Cross Platform Python Remote Administrator Tool\n\t[!]Refer Below Link For Wins & MAc Os\n\t(!)https://nathanlopez.github.io/Stitch \" | boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> " )

        self.check_input(choice, self.stitch, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/nathanlopez/Stitch.git")
            os.system("cd Stitch && sudo pip install -r lnx_requirements.txt")
            self.stitch()

        if choice == "2":
            os.system("cd Stitch && sudo python main.py")
            self.stitch()

        if choice == "99":
            self.payloads()

    def msf_venom(self):
        self.clear_scr()
        os.system("echo \"MSFvenom Payload Creator (MSFPC) is a wrapper to generate \nmultiple types of payloads, based on users choice.\nThe idea is to be as simple as possible (only requiring one input) \nto produce their payload. [!]https://github.com/g0tmi1k/msfpc \" |boxes -d boy | lolcat ")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.msf_venom, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/g0tmi1k/msfpc.git")
            os.system("cd msfpc;sudo chmod +x msfpc.sh")
            self.msf_venom()

        if choice == "2":
            os.system("cd msfpc;sudo bash msfpc.sh -h -v")
            self.msf_venom()

        if choice == "99":
            self.payloads()

    def venom(self):
        self.clear_scr()
        os.system("echo \"venom 1.0.11 (malicious_server) was build to take advantage of \n apache2 webserver to deliver payloads (LAN) using a fake webpage writen in html\"| boxes -d boy| lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.venom, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/r00t-3xp10it/venom.git")
            os.system("sudo chmod -R 775 venom*/ && cd venom*/ && cd aux && sudo bash setup.sh")
            os.system("sudo ./venom.sh -u")
            self.venom()

        if choice == "2":
            os.system("cd venom && sudo ./venom.sh")
            self.venom()

        if choice == "99":
            self.payloads()

    def spycam(self):
        self.clear_scr()
        os.system("echo \"Script to generate a Win32 payload that takes the webcam image every 1 minute and send it to the attacker\"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.spycam, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/thelinuxchoice/spycam ")
            os.system("cd spycam && bash install.sh && chmod +x spycam")
            self.spycam()

        if choice == "2":
            os.system("cd spycam && ./spycam")
            self.spycam()

        if choice == "99":
            self.payloads()

    def mobdroid(self):
        self.clear_scr()
        os.system("echo \"Mob-Droid helps you to generate metasploit payloads in easy way\n without typing long commands and save your \n[!]https://github.com/kinghacker0/Mob-Droid \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.mobdroid, ['1', '2', '99'])

        if choice == "1":
            os.system("git clone https://github.com/kinghacker0/mob-droid")
            self.spycam()

        if choice == "2":
            os.system("cd Mob-Droid;sudo python mob-droid.py")
            self.mobdroid()

        if choice == "99":
            self.payloads()

    def enigma(self):
        self.clear_scr()
        os.system("echo \"Enigma is a Multiplatform payload dropper \n\t [!]https://github.com/UndeadSec/Enigma \" | boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.enigma, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/UndeadSec/Enigma.git ")
            self.enigma()

        if choice == "2":
            os.system("cd Enigma;sudo python3 enigma3.py")

        if choice == "99":
            self.payloads()
    
    def fud(self):
        self.clear_scr()
        os.system("echo \"FUD Tool Use To Bypass Window 10 Defender Firewall & Bypass UAC \n\t [!]https://github.com/Ignitetch/FUD \"| boxes -d boy | lolcat ")
        choice = input("[1]Install [2]Run [99]Back >> ")
        self.check_input(choice, self.fud, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/Ignitetch/FUD.git")

        if choice == "2":
            os.system("cd FUD;bash FUD.sh")
        
        if choice == "99":
            self.payloads

                        #### Steganography Tools            
    def steganography(self):
        self.clear_scr()
        os.system("figlet -f standard -c SteganoGraphy | lolcat")

        print("""
             [1] SteganoHide
             [2] StegnoCracker
             [3] WhiteSpace
            [99] Back
        """)

        functions_steganography = {
            '1':self.steganohide,
            '2':self.stegnocracker,
            '3':self.whitespace,
            '99':self.menu
        }

        choice = input("Z4nz =>> ")
        self.check_input(choice, self.steganography, functions_steganography.keys())

        functions_steganography[choice]()

    def steganohide(self):
        self.clear_scr()
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.steganohide, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo apt-get install steghide -y ")
            self.steganohide()

        if choice == "2":
            choice_run = input("[1]Hide [2]Extract >> ")

            self.check_input(choice_run, self.self.steganohide, ['1', '2', '99'])

            if choice_run == "1":
                file_hide = input("Enter Filename you want to Embed (1.txt) >> ")
                file_to_be_hide = input("Enter Cover Filename(test.jpeg) >> ")
                subprocess.run(["steghide", "embed", f"-cf {file_to_be_hide}", f"-ef {file_hide}"])
                self.steganohide()

            if choice_run == "2":
                from_file = input("Enter Filename From Extract Data >> ")
                subprocess.run([f"steghide extract", f" -sf {from_file}"])
                self.steganohide()

            if choice_run == '99':
                self.steganohide()

        if choice == "99":
            self.steganography()

    def stegnocracker(self):
        self.clear_scr()
        os.system("echo \"SteganoCracker is a tool that uncover hidden data inside files\n using brute-force utility  \"|boxes -d boy| lolcat")
        choice = input("[1]Install [2]Run [99]Back  >> ")

        self.check_input(choice, self.stegnocracker, ['1', '2', '99'])

        if choice == "1":
            os.system("pip3 install stegcracker && pip3 install stegcracker -U --force-reinstall")
            self.stegnocracker()

        if choice == "2":
            filename = input("Enter Filename:- ")
            passfile = input("Enter Wordlist Filename:- ")
            subprocess.run(["stegcracker", f" {filename} {passfile}"])
            self.stegnocracker()

        if choice == "99":
            self.steganography()

    def whitespace(self):
        self.clear_scr()
        os.system("echo \"Use whitespace and unicode chars for steganography \n\t [!]https://github.com/beardog108/snow10 \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.whitespace, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/beardog108/snow10.git ")
            os.system("sudo chmod -R 755 snow10")
            self.whitespace()

        if choice == "2":
            os.system("cd snow10 && firefox index.html")
            self.whitespace()

        if choice == "99":
            self.steganography()

    def sqltool(self):
        self.clear_scr()
        os.system("figlet -f standard -c Sql Tools | lolcat")

        print("""
             [1] Sqlmap tool
             [2] NoSqlMap
             [3] Damn Small SQLi Scanner
             [4] Explo
             [5] Blisqy - Exploit Time-based blind-SQL injection
             [6] Leviathan - Wide Range Mass Audit Toolkit 
             [7] SQLScan
            [99] Back
        """)

        functions_sqltool = {
            '1':self.sqlmap,
            '2':self.nosqlmap,
            '3':self.sqliscanner,
            '4':self.explo,
            '5':self.blisqy,
            '6':self.leviathan,
            '7':self.sqlscan,
            '99':self.menu
        }

        choice = input("Z4nzu =>> ")
        self.check_input(choice, self.sqltool, functions_sqltool.keys())

        functions_sqltool[choice]()

    def sqlmap(self):
        self.clear_scr()
        os.system("echo \"sqlmap is an open source penetration testing tool that automates the process of \ndetecting and exploiting SQL injection flaws and taking over of database servers \n [!]python sqlmap.py -u [<http://example.com>] --batch --banner \n More Usage [!]https://github.com/sqlmapproject/sqlmap/wiki/Usage \"|boxes -d boy | lolcat")
        choice = input("[1]Install [99]Back >> ")

        self.check_input(choice, self.sqlmap, ['1', '99'])

        if choice == "1":
            os.system("sudo git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev")
            print("Downloaded Successfully..!!")
            self.sqlmap()

        if choice == "99":
            self.sqltool()

    def nosqlmap(self):
        self.clear_scr()
        os.system("echo \"NoSQLMap is an open source Python tool designed to \n audit for as well as automate injection attacks and exploit.\n \033[91m [*]Please Install MongoDB \n More Info[!]https://github.com/codingo/NoSQLMap \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.nosqlmap, ['1', '2', '99'])

        if choice == "1":
            os.system("git clone https://github.com/codingo/NoSQLMap.git")
            os.system("sudo chmod -R 755 NoSQLMap;cd NoSQLMap;python setup.py install ")
            self.nosqlmap()

        if choice == "2":
            os.system("python NoSQLMap")
            self.nosqlmap()

        if choice == "99":
            self.sqltool()

    def sqliscanner(self):
        self.clear_scr()
        os.system("echo \"Damn Small SQLi Scanner (DSSS) is a fully functional SQL injection\nvulnerability scanner also supporting GET and POST parameters.\n[*]python3 dsss.py -h[help] | -u[URL] \n\tMore Info [!]https://github.com/stamparm/DSSS \"|boxes -d boy | lolcat")
        choice = input("[1]Install [99]Back >> ")

        self.check_input(choice, self.sqliscanner, ['1', '99'])

        if choice == "1":
            os.system("git clone https://github.com/stamparm/DSSS.git")
            self.sqliscanner()

        if choice == "99":
            self.sqltool()

    def explo(self):
        self.clear_scr()
        os.system("echo \"Explo is a simple tool to describe web security issues in a human and machine readable format.\n Usage:- \n [1]explo [--verbose|-v] testcase.yaml \n [2]explo [--verbose|-v] examples/*.yaml \n[*]https://github.com/dtag-dev-sec/explo \"|boxes -d boy | lolcat")
        choice = input("[1]Install [99]Back >> ")

        self.check_input(choice, self.explo, ['1', '99'])

        if choice == "1":
            os.system("git clone https://github.com/dtag-dev-sec/explo ")
            os.system("cd explo ;sudo python setup.py install")
            self.explo()

        if choice == "99":
            self.sqltool()

    def blisqy(self):
        self.clear_scr()
        os.system("echo \"Blisqy is a tool to aid Web Security researchers to find Time-based Blind SQL injection \n on HTTP Headers and also exploitation of the same vulnerability.\n For Usage >> [!]https://github.com/JohnTroony/Blisqy \"|boxes -d boy | lolcat")
        choice = input("[1]Install [99]Back >> ")

        self.check_input(choice, self.blisqy, ['1', '99'])

        if choice == "1":
            os.system("git clone https://github.com/JohnTroony/Blisqy.git ")
            self.blisqy()

        if choice == "99":
            self.sqltool()

    def leviathan(self):
        self.clear_scr()
        os.system("echo \"Leviathan is a mass audit toolkit which has wide range service discovery,\nbrute force, SQL injection detection and running custom exploit capabilities. \n [*]It Requires API Keys \n More Usage [!]https://github.com/utkusen/leviathan/wiki \"|boxes -d boy | lolcat ")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.leviathan, ['1', '2', '99'])

        if choice == "1":
            os.system("git clone https://github.com/leviathan-framework/leviathan.git")
            os.system("cd leviathan;sudo pip install -r requirements.txt")
            self.leviathan()

        if choice == "2":
            os.system("cd leviathan;python leviathan.py")

        if choice == "99":
            self.sqltool()

    def sqlscan(self):
        self.clear_scr()
        os.system("echo \"sqlscan is quick web scanner for find an sql inject point. not for educational, this is for hacking. \n [!]https://github.com/Cvar1984/sqlscan \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.sqlscan, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo apt install php php-bz2 php-curl php-mbstring curl")
            os.system("sudo curl https://raw.githubusercontent.com/Cvar1984/sqlscan/dev/build/main.phar --output /usr/local/bin/sqlscan")
            os.system("chmod +x /usr/local/bin/sqlscan")
            self.sqlscan()

        if choice == "2":
            os.system("sudo sqlscan")
            self.sqlscan()

        if choice == "99":
            self.sqltool()

    def others(self):
        self.clear_scr()
        print(self.logo + """
         [1] SocialMedia Brutforce
         [2] Android Attack
         [3] HatCloud(Bypass CloudFlare for IP)
         [4] IDN Homograph Attack
         [5] Email Verifier
         [6] Hash Cracking Tools
         [7] Wifi Jamming
         [8] SocialMedia Finder 
         [9] Payload Injector
        [10] Web Crawling 
        [11] Mix Tools
        [99] Main Menu
        """)

        functions_others = {
            '1':self.social_attack,
            '2':self.androidhack,
            '3':self.hatcloud,
            '4':self.homograph,
            '5':self.emailverify,
            '6':self.hashcracktool,
            '7':self.wifijamming,
            '8':self.socialfinder,
            '9':self.pyinject,
            '10':self.webcrawling,
            '11':self.mixtools,
            '99':self.menu
        }

        choice = input("Z4nzu =>> ")
        self.check_input(choice, self.others, functions_others.keys())

        functions_others[choice]()
                ######  SOCIALMEDIA ATTACK TOOLS
    def social_attack(self):
        self.clear_scr()
        os.system("figlet -f standard SocialMedia Attack | lolcat")

        print("""
             [1] Instagram Attack
             [2] AllinOne SocialMedia Attack 
             [3] Facebook Attack
             [4] Application Checker
            [99] Back
        """)

        functions_social_attack = {
            '1':self.instabrute,
            '2':self.bruteforce,
            '3':self.faceshell,
            '4':self.appcheck,
            '99':self.others
        }

        choice = input("Z4nzu =>> ")
        self.check_input(choice, self.social_attack, functions_social_attack.keys())
        
        functions_social_attack[choice]()

    def instabrute(self):
        self.clear_scr()
        os.system("echo \"Brute force attack against Instagram \n\t [!]https://github.com/chinoogawa/instaBrute \"| boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.bruteforce, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/chinoogawa/instaBrute.git ")
            os.system("cd instaBrute;sudo pip install -r requirements.txt")
            self.instabrute()

        if choice == "2":
            name = input("Enter Username >> ")
            wordlist = input("Enter wordword list >> ")
            os.system(f"cd instaBrute")
            subprocess.run(["sudo python instaBrute.py", f" -u {name} -d {wordlist}"])
            self.instabrute()

        if choice == "99":
            self.social_attack()

    def bruteforce(self):
        self.clear_scr()
        os.system("echo \"Brute_Force_Attack Gmail Hotmail Twitter Facebook Netflix \n[!]python3 Brute_Force.py -g <Account@gmail.com> -l <File_list> \n\t[!]https://github.com/Matrix07ksa/Brute_Force \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.bruteforce, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/Matrix07ksa/Brute_Force.git")
            os.system("cd Brute_Force ;sudo pip3 install proxylist;pip3 install mechanize")
            self.bruteforce()

        if choice == "2":
            os.system("cd Brute_Force;python3 Brute_Force.py -h")
            self.bruteforce()

        if choice == "99":
            self.social_attack()

    def faceshell(self):
        self.clear_scr()
        os.system("echo \" Facebook BruteForcer[!]https://github.com/Matrix07ksa/Brute_Force \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.faceshell, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/Matrix07ksa/Brute_Force.git")
            os.system("cd Brute_Force ;sudo pip3 install proxylist;pip3 install mechanize")
            self.faceshell()

        if choice == "2":
            name = input("Enter Username >> ")
            wordlist = input("Enter Wordlist >> ")
            os.system("cd Brute_Force")
            subprocess.run("python3 Brute_Force.py", f" -f {name} -l {wordlist}")
            self.faceshell()

        if choice == "99":
            self.social_attack()

    def appcheck(self):
        self.clear_scr()
        os.system("echo \"Tool to check if an app is installed on the target device through a link.\"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.appcheck, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/jakuta-tech/underhanded")
            os.system("cd underhanded && sudo chmod +x underhanded.sh")
            self.appcheck()

        if choice == "2":
            os.system("cd underhanded ; sudo bash underhanded.sh")
            self.appcheck()

        if choice == "99":
            self.social_attack()

    def androidhack(self):
        self.clear_scr()
        os.system("figlet -f standard -c Android Hacking Tools | lolcat")

        print("""
             [1] Keydroid 
             [2] MySMS
             [3] Lockphish (Grab target LOCK PIN)
             [4] DroidCam (Capture Image)
             [5] EvilApp (Hijack Session)
            [99] Back
        """)
    
        functions_androidhack = {
            '1':self.keydroid,
            '2':self.mysms,
            '3':self.lock,
            '4':self.droidcam,
            '5':self.evilapp,
            '99':self.others
        }

        choice = input("Z4nzu =>> ")
        self.check_input(choice, self.androidhack, functions_androidhack.keys())

        functions_androidhack[choice]()

    def keydroid(self):
        self.clear_scr()
        os.system("echo \"Android Keylogger + Reverse Shell\n[!]You have to install Some Manually Refer Below Link:\n [+]https://github.com/F4dl0/keydroid \" | boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.keydroid, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/F4dl0/keydroid")
            self.keydroid()

        if choice == "2":
            os.system("cd keydroid && bash keydroid.sh")
            self.keydroid()

        if choice == "99":
            self.androidhack()

    def mysms(self):
        self.clear_scr()
        os.system("echo \" Script that generates an Android App to hack SMS through WAN \n[!]You have to install Some Manually Refer Below Link:\n\t [+]https://github.com/papusingh2sms/mysms \" | boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.mysms, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/papusingh2sms/mysms")
            self.mysms()

        if choice == "2":
            os.system("cd mysms && bash mysms.sh")
            self.mysms()

        if choice == "99":
            self.androidhack()

    def lock(self):
        self.clear_scr()
        os.system("echo \"Lockphish it's the first tool for phishing attacks on the lock screen, designed to\n Grab Windows credentials,Android PIN and iPhone Passcode using a https link. \"| boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.lock, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone git clone https://github.com/JasonJerry/lockphish")
            self.lock()

        if choice == "2":
            os.system("cd lockphish && bash lockphish.sh")
            self.lock()

        if choice == "99":
            self.androidhack()

    def droidcam(self):
        self.clear_scr()
        os.system("echo \"Powerful Tool For Grab Front Camera Snap Using A Link  \n[+]https://github.com/kinghacker0/WishFish \"| boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.droidcam, ['1', '2', '99'])
        
        if choice == "1":
            os.system("sudo git clone https://github.com/kinghacker0/WishFish; sudo apt install php wget openssh")
            self.droidcam()

        if choice == "2":
            os.system("cd wishfish && sudo bash wishfish.sh")
            self.droidcam()

        if choice == "99":
            self.androidhack()

    def evilapp(self):
        self.clear_scr()
        os.system("echo \"EvilApp is a script to generate Android App that can hijack authenticated sessions in cookies.\n [!]https://github.com/crypticterminal/EvilApp \" | boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.evilapp, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/crypticterminal/EvilApp")
            self.evilapp()

        if choice == "2":
            os.system("cd evilapp && bash evilapp.sh")
            self.evilapp()

        if choice == "99":
            self.androidhack()

    def hatcloud(self):
        self.clear_scr()
        os.system("echo \"HatCloud build in Ruby. It makes bypass in CloudFlare for discover real IP.\n\b [!]https://github.com/HatBashBR/HatCloud \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.hatcloud, ['1', '2', '99'])

        if choice == "1":
            os.system("git clone https://github.com/HatBashBR/HatCloud.git")
            self.hatcloud()

        if choice == "2":
            site = input("Enter Site >> ")
            os.system("cd HatCloud;sudo ruby hatcloud.rb -b {site}")
            self.hatcloud()

        if choice == "99":
            self.others()
                                ####  HOMOGRAPH TOOLS
    def homograph(self):
        self.clear_scr()
        os.system("figlet -f standard -c IDN Homograph Attack tools | lolcat")

        print("""
             [1] EvilURL
            [99] Back
        """)

        choice = input("Z4nzu =>> ")
        functions_homograph = {
            '1':self.evilurl,
            '99':self.others
        }
        self.check_input(choice, self.homograph, functions_homograph.keys())

        functions_homograph[choice]()

    def evilurl(self):
        self.clear_scr()
        os.system("echo \"Generate unicode evil domains for IDN Homograph Attack and detect them. \n [!]https://github.com/UndeadSec/EvilURL \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.evilurl, ['1', '2', '99'])

        if choice == "1":
            os.system("git clone https://github.com/UndeadSec/EvilURL.git")
            self.evilurl()

        if choice == "2":
            os.system("cd EvilURL;python3 evilurl.py")
            self.evilurl()

        if choice == "99":
            self.homograph()
                            #### EMAIL VERIFY TOOLS
    def emailverify(self):
        self.clear_scr()
        os.system("figlet -f standard -c Email Verify tools | lolcat")

        print("""
             [1] KnockMail
            [99] Back
        """)

        choice = input("Z4nzu =>> ")

        self.check_input(choice, self.emailverify, ['1', '99'])

        if choice == "1":
            self.knockmail()

        if choice == "99":
            self.others()

    def knockmail(self):
        self.clear_scr()
        os.system("echo \"KnockMail Tool Verify If Email Exists [!]https://github.com/4w4k3/KnockMail \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.knockmail, ['1', '2', '99'])

        if choice == "1":
            os.system("git clone https://github.com/4w4k3/KnockMail.git")
            os.system("cd KnockMail;sudo pip install -r requeriments.txt")
            self.knockmail()

        if choice == "2":
            os.system("cd KnockMail;python knock.py")

        if choice == "99":
            self.emailverify()

    def hashcracktool(self):
        self.clear_scr()
        os.system("figlet -f standard -c Hash Cracking Tools | lolcat")

        print("""
             [1] Hash Buster
            [99] Back
        """)

        choice = input("Z4nzu =>> ")
        self.check_input(choice, self.hashcracktool, ['1', '99'])

        if choice == "1":
            self.hashbuster()

        if choice == "99":
            self.others()

    def hashbuster(self):
        self.clear_scr()
        os.system("echo \"Features: \n Automatic hash type identification \n Supports MD5, SHA1, SHA256, SHA384, SHA512 \n [!]https://github.com/s0md3v/Hash-Buster \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.hashbuster, ['1', '2', '99'])

        if choice == "1":
            os.system("git clone https://github.com/s0md3v/Hash-Buster.git")
            os.system("cd Hash-Buster;make install")
            self.hashbuster()

        if choice == "2":
            os.system("buster -h")
            self.hashbuster()

        if choice == "99":
            self.hashcracktool()

                        #### WIFI JAMMING TOOLS
    def wifijamming(self):
        self.clear_scr()
        os.system("figlet -f standard -c Wifi Deautheticate | lolcat")

        print("""
             [1] WifiJammer-NG
             [2] KawaiiDeauther
            [99] Back
        """)

        functions_wifijamming = {
            '1':self.wifijammingng,
            '2':self.kawaiideauther,
            '99':self.others
        }

        choice = input("Z4nzu =>> ")
        self.check_input(choice, self.wifijamming, functions_wifijamming.keys())
        
        functions_wifijamming[choice]()

    def wifijammingng(self):
        self.clear_scr()
        os.system("echo \"Continuously jam all wifi clients and access points within range.\n\t [!]https://github.com/MisterBianco/wifijammer-ng \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.wifijammingng, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/MisterBianco/wifijammer-ng.git")
            os.system("cd wifijammer-ng;sudo pip3 install -r requirements.txt")
            self.wifijammingng()

        if choice == "2":
            os.system("echo \"python wifijammer.py [-a AP MAC] [-c CHANNEL] [-d] [-i INTERFACE] [-m MAXIMUM] [-k] [-p PACKETS] [-s SKIP] [-t TIME INTERVAL] [-D]\"| boxes | lolcat")
            os.system("cd wifijammer-ng;sudo python3 wifijammer.py")
            self.wifijammingng()

        if choice == "99":
            self.wifijamming()

    def kawaiideauther(self):
        self.clear_scr()
        os.system("echo \"Kawaii Deauther is a pentest toolkit whose goal is to perform \n jam on WiFi clients/routers and spam many fake AP for testing purposes. \n\t [!]https://github.com/aryanrtm/KawaiiDeauther \" | boxes -d boy | lolcat ")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.kawaiideauther, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/aryanrtm/KawaiiDeauther")
            os.system("cd KawaiiDeauther;sudo bash install.sh")
            self.kawaiideauther()
        
        if choice == "2":
            os.system("cd KawaiiDeauther;sudo KawaiiDeauther.sh")

        if choice == "99":
            self.wifijamming()

                                ### SOCIALFINDER TOOLS
    def socialfinder(self):
        self.clear_scr()
        os.system("figlet -f standard SocialMedia Finder | lolcat")

        print("""
             [1]  Find SocialMedia By Facial Recognation System
             [2]  Find SocialMedia By UserName
             [3]  Sherlock
             [4]  SocialScan | Username or Email
            [99] Back To Main Menu
        """)

        functions_socialfinder = {
            '1':self.facialfind,
            '2':self.finduser,
            '3':self.sherlock,
            '4':self.socialscan,
            '99':self.others
        }
        choice = input("Z4nzu =>> ")
        self.check_input(choice, self.socialfinder, functions_socialfinder.keys())

        functions_socialfinder[choice]()

    def facialfind(self):
        self.clear_scr()
        os.system("echo \"A Social Media Mapping Tool that correlates profiles\n via facial recognition across different sites. \n\t[!]https://github.com/Greenwolf/social_mapper \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.facialfind, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo add-apt-repository ppa:mozillateam/firefox-next && sudo apt update && sudo apt upgrade")
            os.system("sudo git clone https://github.com/Greenwolf/social_mapper.git")
            os.system("cd social_mapper/setup")
            os.system("sudo python3 -m pip install --no-cache-dir -r requirements.txt")
            os.system("echo \"[!]Now You have To do some Manually\n[!]Install the Geckodriver for your operating system\n[!]Copy & Paste Link And Download File As System Configuration\n[#]https://github.com/mozilla/geckodriver/releases\n[!!]On Linux you can place it in /usr/bin \"| boxes | lolcat")
            self.facialfind()

        if choice == "2":
            os.system("cd social_mapper/setup")
            os.system("sudo python social_mapper.py -h")

            print("""\033[95m 
                    You have to set Username and password of your AC Or Any Fack Account
                    [#]Type in Terminal nano social_mapper.py
            """)

            os.system("echo \"python social_mapper.py -f [<imageFoldername>] -i [<imgFolderPath>] -m fast [<AcName>] -fb -tw\"| boxes | lolcat")
            self.facialfind()

        if choice == "99":
            self.socialfinder()

    def finduser(self):
        self.clear_scr()
        os.system("echo \"Find usernames across over 75 social networks \n [!]https://github.com/xHak9x/finduser \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.finduser, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/xHak9x/finduser.git")
            os.system("cd finduser && sudo chmod +x finduser.sh")            
            self.finduser()

        if choice == "2":
            os.system("cd finduser && sudo bash finduser.sh")
            self.finduser()

        if choice == "99":
            self.socialfinder()

    def sherlock(self):
        self.clear_scr()
        os.system("echo \"Hunt down social media accounts by username across social networks \n For More Usege \n\t >>python3 sherlock --help \n [!]https://github.com/sherlock-project/sherlock \"|boxes -d boy | lolcat")
        choice = input("[1]Install [99]Back >> ")

        self.check_input(choice, self.sherlock, ['1', '99'])

        if choice == "1":
            os.system("git clone https://github.com/sherlock-project/sherlock.git")
            os.system("cd sherlock ;sudo python3 -m pip install -r requirements.txt")
            self.sherlock()

        if choice == "2":
            name = input("Enter Username >> ")
            os.system("cd sherlock")
            subprocess.run(["sudo python3 sherlock", f" {name}"])
            self.sherlock()

        if choice == "99":
            self.socialfinder()

    def socialscan(self):
        self.clear_scr()
        os.system("echo \"Check email address and username availability on online platforms with 100% accuracy \n\t[*]https://github.com/iojw/socialscan \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.socialscan, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo pip install socialscan")
            self.socialscan()

        if choice == "2":
            name = input("Enter Username or Emailid (if both then please space between email & username) >> ")
            subprocess.run(["sudo socialscan", f" {name}"])
            self.socialscan()

        if choice == "99":
            self.socialfinder()

                    ########### PYTHON INJECTOR TOOLS 
    def pyinject(self):
        self.clear_scr()
        os.system("figlet -f standard -c Payload Injector | lolcat ")
        print("""
             [1] Debinject 
             [2] Pixload 
            [99] Back
        """)
        functions_pyinject ={
            '1':self.debinject,
            '2':self.pixload,
            '99':self.others
        }
        choice = input(" Z4nzu >> ")
        self.check_input(choice, self.pyinject, functions_pyinject.keys())

        self.clear_scr()
        functions_pyinject[choice]()

    def debinject(self):
        self.clear_scr()
        os.system("echo \"Debinject is a tool that inject malicious code into *.debs \n\t [!]https://github.com/UndeadSec/Debinject  \" | boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")
        self.check_input(choice, self.debinject, ['1', '2', '99'])
        if choice == "1":
            os.system("sudo git clone https://github.com/UndeadSec/Debinject.git ")
            self.debinject()
        if choice == "2":
            os.system("cd Debinject;python debinject.py")
        if choice == "99":
            self.pyinject()

    def pixload(self):
        os.system("echo \"Pixload -- Image Payload Creating tools \n Pixload is Set of tools for creating/injecting payload into images.\n\t [!]https://github.com/chinarulezzz/pixload \" | boxes -d boy | lolcat")
        choice = input("[1]Install [2]How To Use [99]Back >> ")
        self.check_input(choice, self.pixload, ['1', '99'])
        if choice == "1":
            print("Installing Packeges...")
            time.sleep(2)
            os.system("sudo apt install libgd-perl libimage-exiftool-perl libstring-crc32-perl")
            print("Downloading Repository ...")
            time.sleep(1)
            os.system("sudo git clone https://github.com/chinarulezzz/pixload.git ")
            self.pixload()
        if choice == "2":
            print("Trying to open Webbrowser ...")
            time.sleep(2)
            webbrowser.open_new_tab("https://github.com/chinarulezzz/pixload")
        if choice == "99":
            self.pyinject()                    

    def webcrawling(self):
        self.clear_scr()
        os.system("figlet -f standard Web Crawling | lolcat ")
        print("""
             [1] Gospider
            [99] Back
        """)
        functions_webcrawling = {
            '1':self.gospider,
            '99':self.others
        }
        choice = input(" Z4nzu >> ")
        self.check_input(choice, self.webcrawling, functions_webcrawling.keys())

        self.clear_scr()
        functions_webcrawling[choice]()

    def gospider(self):
        os.system("echo \"Gospider - Fast web spider written in Go \n\t [!]https://github.com/jaeles-project/gospider \" | boxes -d boy | lolcat")
        choice = input("[1]Install [2]How to Use [99]Back >> ")

        self.check_input(choice, self.gospider, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo go get -u github.com/jaeles-project/gospider")
            self.gospider()

        if choice == "2":
            print("Opening Webbrowser..")
            time.sleep(2)
            webbrowser.open_new_tab("https://github.com/jaeles-project/gospider")

        if choice == "99":
            self.webcrawling()
                            #########     MIX TOOLS
    def mixtools(self):
        self.clear_scr()
        os.system("figlet -f standard -l Mix Tools | lolcat")
        print("""
             [1] Terminal Multiplexer
            [99] Back
        """)
        functions_mixtools ={
            '1':self.terminaltool,
            '99':self.others
        }
        choice = input(" Z4nzu >> ")
        self.check_input(choice, self.mixtools, functions_mixtools.keys())

        self.clear_scr()
        functions_mixtools[choice]()

    def terminaltool(self):
        self.clear_scr()
        os.system("echo \"Terminal Multiplexer is a tiling terminal emulator that allows us to open \n several terminal sessions inside one single window. \" | boxes -d boy | lolcat")
        choice = input("[1]Install [99]Back >> ")

        self.check_input(choice, self.terminaltool, ['1', '99'])

        if choice == "1":
            os.system("sudo apt-get install tilix")
            time.sleep(2)
            self.others()

        if choice == "99":
            self.mixtools()

                            ###### OPTION REVERSE ###
    def reversetool(self):
        self.clear_scr()
        os.system("figlet -f standard -l Reverse Engineering Tools | lolcat")
        print("""
             [1] Androguard
             [2] Apk2Gold
             [3] JadX
            [99] Menu
        """)
        functions_reversetool = {
            '1':self.androguard,
            '2':self.apk2gold,
            '3':self.jadx,
            '99':self.menu
        }
        choice = input(" Z4nzu >> ")
        self.check_input(choice, self.reversetool, functions_reversetool.keys())

        self.clear_scr()
        functions_reversetool[choice]()

    def androguard(self):
        self.clear_scr()
        os.system("echo \"Androguard is a Reverse engineering, Malware and goodware analysis of Android applications and more \n\t[!]https://github.com/androguard/androguard \" | boxes -d boy | lolcat")
        choice = input("[1]Install [99]Back >> ")

        self.check_input(choice, self.androguard, ['1', '99'])

        if choice == "1":
            os.system("sudo pip install -U androguard")
            self.androguard()

        if choice == "99":
            self.reversetool()

    def apk2gold(self):
        self.clear_scr()
        os.system("echo \"Apk2Gold is a CLI tool for decompiling Android apps to Java [!]https://github.com/lxdvs/apk2gold \" | boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.apk2gold, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/lxdvs/apk2gold.git")
            os.system("cd apk2gold;sudo bash make.sh")
            self.apk2gold()

        if choice == "2":
            uinput = input("Enter (.apk) File >> ")
            subprocess.run(["sudo apk2gold", " {0}".format(uinput)])

        if choice == "99":
            self.reversetool()

    def jadx(self):
        self.clear_scr()
        os.system("echo \"Jadx is Dex to Java decompiler.\n[*]decompile Dalvik bytecode to java classes from APK, dex, aar and zip files\n[*]decode AndroidManifest.xml and other resources from resources.arsc\n\t [+]https://github.com/skylot/jadx \" | boxes -d boy | lolcat")
        choice = input("[1]Install [99]Back >> ")

        self.check_input(choice, self.jadx, ['1', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/skylot/jadx.git")
            os.system("cd jadx;./gradlew dist")
            self.jadx()

        if choice == "99":
            self.reversetool()

###### OPTION[11] ###
    def ddos(self):
        self.clear_scr()
        os.system("figlet -f standard -c DDOS Attack Tools | lolcat")

        print("""
             [1] SlowLoris
             [2] Asyncrone | Multifunction SYN Flood DDoS Weapon 
             [3] UFOnet
             [4] GoldenEye
            [99] Back
        """)

        functions_ddos = {
            '1':self.slowloris,
            '2':self.asyncrone,
            '3':self.ufonet,
            '4':self.goldeneye,
            '99':self.menu
        }

        choice = input("Z4nzu =>> ")
        self.check_input(choice, self.ddos, functions_ddos.keys())

        functions_ddos[choice]()

    def slowloris(self):
        self.clear_scr()
        os.system("echo \"Slowloris is basically an HTTP Denial of Service attack.It send lots of HTTP Request\"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.slowloris, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo pip install slowloris")
            self.slowloris()

        if choice == "2":
            target_site = input("Enter Target Site:- ")
            subprocess.run(["slowloris", f" {target_site}"])
            self.slowloris()

        if choice == "99":
            self.ddos()

    def asyncrone(self):
        self.clear_scr()
        os.system("echo \"aSYNcrone is a C language based, mulltifunction SYN Flood DDoS Weapon.\nDisable the destination system by sending a SYN packet intensively to the destination.\n\b [!] https://github.com/fatihsnsy/aSYNcrone \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.asyncrone, ['1', '2', '99'])

        if choice == "1":
            os.system("git clone https://github.com/fatih4842/aSYNcrone.git")
            os.system("cd aSYNcrone;sudo gcc aSYNcrone.c -o aSYNcrone -lpthread")
            self.asyncrone()

        if choice == "2":
            source_port = input("Enter Source Port >> ")
            target_ip = input("Enter Target IP >> ")
            target_port = input("Enter Target port >> ")
            os.system(f"cd aSYNcrone")
            subprocess.run(["sudo ./aSYNcrone", f" {source_port} {target_ip} {target_port} 1000"])
            self.asyncrone()

        if choice == "99":
            self.ddos()

    def ufonet(self):
        self.clear_scr()
        os.system("echo \"UFONet - is a free software, P2P and cryptographic -disruptive \n toolkit- that allows to perform DoS and DDoS attacks\n\b More Usage Visit [!]https://github.com/epsylon/ufonet \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.ufonet, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/epsylon/ufonet.git")
            os.system("cd ufonet;sudo python setup.py install")
            self.ufonet()

        if choice == "2":
            os.system("sudo ./ufonet --gui")
            self.ufonet()

        if choice == "99":
            self.ddos()
        
    def goldeneye(self):
        self.clear_scr()
        os.system("echo \"GoldenEye is an python3 app for SECURITY TESTING PURPOSES ONLY!\nGoldenEye is a HTTP DoS Test Tool. \n\t [!]https://github.com/jseidl/GoldenEye \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.goldeneye, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/jseidl/GoldenEye.git;chmod -R 755 GoldenEye")
            self.goldeneye()

        if choice == "2":
            os.system("cd GoldenEye ;sudo ./goldeneye.py")
            print("\033[96m Go to Directory \n [*] USAGE: ./goldeneye.py <url> [OPTIONS] ")
            self.goldeneye()

        if choice == "99":
            self.ddos()

                    ###########  RAT TOOLS  #####
    def rattools(self):
        self.clear_scr()
        os.system("figlet -f standard -c RAT Tools | lolcat ")
        print("""
             [1] Stitch
             [2] Pyshell
            [99] Back 
        """)
        functions_rattools = {
            '1':self.stitch,
            '2':self.pyshell,
            '99':self.menu
        }
        choice = input(" Z4nzu >> ")
        self.check_input(choice, self.rattools, functions_rattools.keys())

        functions_rattools[choice]()

    def stitch(self):
        self.clear_scr()
        os.system("echo \"Stitch is a cross platform python framework.\nwhich allows you to build custom payloads\nFor Windows, Mac and Linux. \n\t [!]https://github.com/nathanlopez/Stitch \" | boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.stitch, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/nathanlopez/Stitch.git")
            os.system("cd Stitch;sudo pip install -r lnx_requirements.txt")
            self.stitch()

        if choice == "2":
            os.system("cd Stitch;python main.py")

        if choice == "99":
            self.rattools()        

    def pyshell(self):
        self.clear_scr()
        os.system("echo \"Pyshell is a Rat Tool that can be able to download & upload files,\n Execute OS Command and more.. \n\t [!]https://github.com/knassar702/pyshell \"| boxes -d boy | lolcat ")
        choice = input("[1]Install [2]Run [99]Back >> ")
        self.check_input(choice,self.pyshell, ['1', '2', '99'])

        if choice == "1" :
            os.system("sudo git clone https://github.com/khalednassar702/Pyshell;sudo pip install pyscreenshot python-nmap requests")
            self.pyshell()
        
        if choice == "2":
            os.system("cd Pyshell;./Pyshell")
            self.pyshell()
        if choice == "99":
            self.rattools()


                    ###########  XSS Attack Tools ##
    def xsstools(self):
        self.clear_scr()
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
             [9] RVuln
            [99] Back
        """)

        functions_xsstools = {
            '1':self.dalfox,
            '2':self.xsspayload,
            '3':self.xssfinder,
            '4':self.xssfreak,
            '5':self.xspear,
            '6':self.xsscon,
            '7':self.xanxss,
            '8':self.xss_strike,
            '9':self.rvuln,
            '99':self.menu
        }

        choice = input("Z4nzu =>> ")
        self.check_input(choice, self.xsstools, functions_xsstools.keys())

        functions_xsstools[choice]()
    def rvuln(self):
        os.system("echo \"RVuln is multi-threaded and Automated Web Vulnerability Scanner written in Rust\n\t [!]https://github.com/iinc0gnit0/RVuln \" | boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.rvuln, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo git clone https://github.com/iinc0gnit0/RVuln;curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh;source $HOME/.cargo/env")
            os.system("sudo apt install openssl-dev;sudo cp -r RVuln/ /usr/bin")
            self.rvuln()

        if choice == "2":
            os.system("RVuln")

        if choice == "99":
            self.xsstools()

    def dalfox(self):
        self.clear_scr()
        os.system("echo \"XSS Scanning and Parameter Analysis tool.\"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.dalfox, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo apt-get install golang")
            os.system("sudo git clone https://github.com/hahwul/dalfox ")
            os.system("cd dalfox;go install")
            self.dalfox()

        if choice == "2":
            os.system("~/go/bin/dalfox")
            print("\033[96m You Need To Run manually by using [!]~/go/bin/dalfox [options] ")
            self.dalfox()

        if choice == "99":
            self.xsstools()

    def xsspayload(self):
        self.clear_scr()
        os.system("echo \" XSS PAYLOAD GENERATOR -XSS SCANNER-XSS DORK FINDER \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.xsspayload, ['1', '2', '99'])

        if choice == "1":
            os.system("git clone https://github.com/capture0x/XSS-LOADER.git")
            os.system("cd XSS-LOADER;sudo pip3 install -r requirements.txt")
            self.xsspayload()

        if choice == "2":
            os.system("cd XSS-LOADER;sudo python3 payloader.py")
            self.xsspayload()

        if choice == "99":
            self.xsstools()

    def xssfinder(self):
        self.clear_scr()
        os.system("echo \"Extended XSS Searcher and Finder \n\b [*]https://github.com/Damian89/extended-xss-search \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.xssfinder, ['1', '2', '99'])

        if choice == "1":
            os.system("git glone https://github.com/Damian89/extended-xss-search.git")
            print("""\033[96m 
            Follow This Steps After Installation:-
                \033[31m [*]Go To extended-xss-search directory,
                    and Rename the example.app-settings.conf to app-settings.conf
            """)
            input('\nPress Enter to back...')
            self.xssfinder()

        if choice == "2":
            print("""\033[96m 
            You have To Add Links to scan
            \033[31m[!]Go to extended-xss-search
                [*]config/urls-to-test.txt
                [!]python3 extended-xss-search.py
            """)
            input('\nPress Enter to back...')
            self.xssfinder()

        if choice == "99":
            self.xsstools()

    def xssfreak(self):
        self.clear_scr()
        os.system("echo \" XSS-Freak is an XSS scanner fully written in python3 from scratch\n\b [!]https://github.com/PR0PH3CY33/XSS-Freak \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.xssfreak), ['1', '2', '99']

        if choice == "1":
            os.system("git clone https://github.com/PR0PH3CY33/XSS-Freak.git")
            os.system("cd XSS-Freak;sudo pip3 install -r requirements.txt")
            self.xssfreak()

        if choice == "2":
            os.system("cd XSS-Freak;sudo python3 XSS-Freak.py")
            self.xssfreak()

        if choice == "99":
            self.xsstools()

    def xspear(self):
        self.clear_scr()
        os.system("echo \" XSpear is XSS Scanner on ruby gems\n\b [!]https://github.com/hahwul/XSpear \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.xspear, ['1', '2', '99'])

        if choice == "1":
            os.system("gem install XSpear")
            self.xspear()

        if choice == "2":
            os.system("XSpear -h")
            self.xspear()

        if choice == "99":
            self.xsstools()

    def xsscon(self):
        self.clear_scr()
        os.system("echo \" [!]https://github.com/menkrep1337/XSSCon \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.xsscon, ['1', '2', '99'])

        if choice == "1":
            os.system("git clone https://github.com/menkrep1337/XSSCon")
            os.system("sudo chmod 755 -R XSSCon")
            self.xsscon()

        if choice == "2":
            website = input("Enter Website >> ")
            os.system("cd XSSCon")
            subprocess.run(["python3 xsscon.py", f" -u {website}"])
            self.xsscon()

        if choice == "99":
            self.xsstools()

    def xanxss(self):
        self.clear_scr()
        os.system("echo \" XanXSS is a reflected XSS searching tool\n that creates payloads based from templates\n\b [!]https://github.com/Ekultek/XanXSS \"|boxes -d boy | lolcat")
        choice = input("[1]Install [2]Run [99]Back >> ")

        self.check_input(choice, self.xanxss, ['1', '2', '99'])

        if choice == "1":
            os.system("git clone https://github.com/Ekultek/XanXSS.git ")
            self.xanxss

        if choice == "2":
            os.system("cd XanXSS ;python xanxss.py -h")
            print("\033[96m You Have to run it manually By Using \n [!]python xanxss.py [Options] ")
            self.xanxss()

        if choice == "99":
            self.xsstools()

    def xss_strike(self):
        self.clear_scr()
        os.system("echo \"XSStrike is a python script designed to detect and exploit XSS vulnerabilites. \"| boxes -d boy | lolcat")
        choice = input("[1]Install [99]Back >> ")
        
        self.check_input(choice, self.xss_strike, ['1', '99'])

        if choice == "1":
            os.system("sudo rm -rf XSStrike")
            os.system("git clone https://github.com/UltimateHackers/XSStrike.git && cd XSStrike && pip install -r requirements.txt")
            self.xss_strike()

        if choice == "99":
            self.xsstools()

    def update(self):
        self.clear_scr()
        print(self.logo +"""
             [1] Update Tool or System 
             [2] Uninstall HackingTool
            [99] Back
        """)

        functions_update = {
            '1':self.updatesys,
            '2':self.uninstall,
            '99':self.menu
        }

        choice = input("Z4nzu =>> ")
        self.check_input(choice, self.update, functions_update.keys())
        
        functions_update[choice]()

    def updatesys(self):
        self.clear_scr()
        choice = input("[1]Update System [2]Update Hackingtool [99]Back >> ")

        self.check_input(choice, self.updatesys, ['1', '2', '99'])

        if choice == "1":
            os.system("sudo apt update && sudo apt full-upgrade -y")
            os.system("sudo apt-get install tor openssl curl && sudo apt-get update tor openssl curl ")
            os.system("sudo apt-get install python3-pip")
            self.updatesys()

        if choice == "2":
            os.system("sudo chmod +x /etc/;sudo chmod +x /usr/share/doc;sudo rm -rf /usr/share/doc/hackingtool/;cd /etc/;sudo rm -rf /etc/hackingtool/;mkdir hackingtool;cd hackingtool;git clone https://github.com/Z4nzu/hackingtool.git;cd hackingtool;sudo chmod +x install.sh;./install.sh")
            self.updatesys()

        if choice == "99":
            self.menu()

    def uninstall(self):
        self.clear_scr()
        choice = input("[1]Uninstall [99]Back >> ")

        self.check_input(choice, self.uninstall, ['1', '99'])

        if choice == "1":
            print("hackingtool started to uninstall..\n")
            sleep(1)
            os.system("sudo chmod +x /etc/;sudo chmod +x /usr/share/doc;sudo rm -rf /usr/share/doc/hackingtool/;cd /etc/;sudo rm -rf /etc/hackingtool/;")
            print("\nHackingtool Successfully Uninstall..")
            print("Happy Hacking..!!")
            sleep(1)
            self.uninstall()

        if choice == "99":
            self.update()

if __name__ == "__main__":
    run = Main()
    try:
        if system() == 'Linux':
            fpath = "/home/hackingtoolpath.txt"
            try:
                with open(fpath, 'r') as f:
                    archive = f.readline()

                    try:
                        os.chdir(archive)
                        run.menu()

                    # If the directory does not exist
                    except FileNotFoundError:
                        os.mkdir(archive)
                        os.chdir(archive)
                        run.menu()

            except FileNotFoundError:
                os.system('clear')
                run.menu()

                print("""
                        [@] Set Path (All your tools will be install in that directory)
                        [1] Manual 
                        [2] Default
                """)

                choice = input("Z4nzu =>> ")

                if choice == "1":
                    inpath = input("Enter Path (with Directory Name) >> ")
                    with open(fpath, "w") as f:
                        f.write(inpath)

                    print("Successfully Path Set...!!")

                if choice == "2":
                    autopath = "/home/hackingtool/"
                    with open(fpath, "w") as f:
                        f.write(autopath)

                    print(f"Your Default Path Is:- {autopath}")
                    sleep(3)

                else:
                    print("Try Again..!!")

        # If not Linux and probably Windows
        elif system() == "Windows":
            print("\033[91m Please Run This Tool In Debian System For Best Result " "\e[00m")
            time.sleep(2)
            webbrowser.open_new_tab("https://tinyurl.com/y522modc")

        else :
            print("Please Check Your Sytem or Open new issue ...")

    except KeyboardInterrupt:        
        print("\nExiting ..!!!")
        sleep(2)
