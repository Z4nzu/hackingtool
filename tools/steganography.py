# coding=utf-8
import subprocess

from core import HackingTool
from core import HackingToolsCollection
from core import validate_input
from core.utils import run_command


class SteganoHide(HackingTool):
    TITLE = "SteganoHide"
    INSTALL_COMMANDS = [
        dict(cmd="sudo apt-get install steghide -y"),
    ]

    def run(self):
        choice_run = input("[1] Hide\n" "[2] Extract\n" "[99]Cancel\n" ">> ")
        choice_run = validate_input(choice_run, [1, 2, 99])
        if choice_run is None:
            print("Please choose a valid input")
            return self.run()

        if choice_run == 99:
            return

        if choice_run == 1:
            file_hide = input("Enter Filename you want to Embed (1.txt) >> ")
            file_to_be_hide = input("Enter Cover Filename(test.jpeg) >> ")
            run_command(
                f"steghide embed -cf {file_to_be_hide} -ef {file_hide}")

        elif choice_run == "2":
            from_file = input("Enter Filename From Extract Data >> ")
            run_command(f"steghide extract -sf {from_file}")


class StegnoCracker(HackingTool):
    TITLE = "StegnoCracker"
    DESCRIPTION = "SteganoCracker is a tool that uncover hidden data inside " \
                  "files\n using brute-force utility"
    INSTALL_COMMANDS = [
        "pip3 install stegcracker && pip3 install stegcracker -U --force-reinstall"
    ]

    def run(self):
        filename = input("Enter Filename:- ")
        passfile = input("Enter Wordlist Filename:- ")
        run_command(f"stegcracker {filename} {passfile}")


class Whitespace(HackingTool):
    TITLE = "Whitespace"
    DESCRIPTION = "Use whitespace and unicode chars for steganography"
    INSTALL_COMMANDS = [
        dict(cmd="sudo git clone https://github.com/beardog108/snow10.git"),
        dict(cmd="sudo chmod -R 755 snow10"),
    ]
    RUN_COMMANDS = [dict(cmd="firefox index.html", cwd="snow10")]
    PROJECT_URL = "https://github.com/beardog108/snow10"


class SteganographyTools(HackingToolsCollection):
    TITLE = "Steganograhy tools"
    TOOLS = [SteganoHide(), StegnoCracker(), Whitespace()]
