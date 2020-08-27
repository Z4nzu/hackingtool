import os
import time

Y = set(['yes', 'y', 'YES', 'Y'])
N = set(['no', 'n', 'NO', 'N'])

os.system("sudo apt-get install figlet")
time.sleep(1)
os.system("figlet INSTALLATION")
agree = input("this tool needs some depedencies so are you sure you want to install those Y / N ")

def agreed():
  if agree in Y:
    print("INSTALLING")
    time.sleep(2)
    os.system("sudo apt-get update")
    os.system("sudo apt-get install python3-pip")
    os.system("pip3 install lolcat")
    os.system("pip3 install boxes")
    os.system("pip3 install flask")
    os.system("pip3 install requests")
  elif agree in N:
    print("This tool needs some depedencies so run dependencies.py")
    time.sleep(0.5)
    print("Exiting...")
    exit()
agreed
