import os
import time

Y = set(['yes', 'y' ,'YES' ,'Y'])
N = set(['no', 'n', 'NO', 'N'])

os.system("figlet INSTALLATION")
agree = input("This tool needs some depedencies are you sure you want to install it Y / N ")

def agreement():
    if agree in Y:
        print("Installing the depedecies")
        os.system("sudo apt-get install figlet")
        os.system("pip3 install lolcat")
        os.system("pip3 install boxes")
        os.system("pip3 install flask")
        os.system("requests")
        time.sleep(0.5)
        os.system("figlet INSTALLATION COMPLETED")
    elif agree in N:
        print("This tool compulsory needs some depedencies")
        time.sleep(0.5)
        print("so run depedencies.py")
        time.sleep(0.5)
        print("exiting")
        exit()
