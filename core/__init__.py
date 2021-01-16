# coding=utf-8
import os
import sys
import webbrowser
import core.utils as utils
from platform import system
from traceback import print_exc
from typing import Any, List, Callable, Tuple
from core.utils import run_command


def clear_screen():
    if system() == "Linux":
        run_command("clear")
    if system() == "Windows":
        run_command("cls")


def validate_input(ip, val_range):
    try:
        ip = int(ip)
        if ip in val_range:
            return ip
        else:
            return None
    except:
        return None


class HackingTool(object):
    """
    About the HackingTool
    """
    TITLE: str = ""  # used to show info in the menu
    DESCRIPTION: str = ""

    INSTALL_COMMANDS: List[str or dict] = []
    INSTALLATION_DIR: str = ""

    UNINSTALL_COMMANDS: List[str or dict] = []

    RUN_COMMANDS: List[str or dict] = []

    OPTIONS: List[Tuple[str, Callable]] = []

    PROJECT_URL: str = ""

    def __init__(self,
                 options=None,
                 installable: bool = True,
                 runnable: bool = True):
        if options is None:
            options = []
        if isinstance(options, list):
            self.OPTIONS = []
            if installable:
                self.OPTIONS.append(('Install', self.install))
            if runnable:
                self.OPTIONS.append(('Run', self.run))
            self.OPTIONS.extend(options)
        else:
            raise Exception(
                "options must be a list of (option_name, option_fn) tuples")

    def show_info(self):
        desc = self.DESCRIPTION
        if self.PROJECT_URL:
            desc += '\n\t[*] '
            desc += self.PROJECT_URL
        run_command(f'echo "{desc}"|boxes -d boy | lolcat')
        # print(desc)

    def show_options(self, parent=None):
        clear_screen()
        self.show_info()
        for index, option in enumerate(self.OPTIONS):
            print("[{:2}] {}".format(index + 1, option[0]))
        if self.PROJECT_URL:
            print("[{:2}] {}".format(98, "Open project page"))
        print("[{:2}] {}".format(
            99, ("Back to " + parent.TITLE) if parent is not None else "Exit"))
        option_index = input("Select an option : ")
        try:
            option_index = int(option_index)
            if option_index - 1 in range(len(self.OPTIONS)):
                ret_code = self.OPTIONS[option_index - 1][1]()
                if ret_code != 99:
                    input("\n\nPress ENTER to continue:")
            elif option_index == 98:
                self.show_project_page()
            elif option_index == 99:
                if parent is None:
                    sys.exit()
                return 99
        except (TypeError, ValueError):
            # raise
            print("Please enter a valid option")
            input("\n\nPress ENTER to continue:")
        except Exception:
            print_exc()
            input("\n\nPress ENTER to continue:")
        return self.show_options(parent=parent)

    def before_install(self):
        pass

    def execute(self, commands):
        """
        Executes commands.
        """
        if isinstance(commands, (list, tuple)):
            for cmd in commands:
                if isinstance(cmd, str):
                    run_command(cmd)
                elif isinstance(cmd, dict):
                    cmd, cwd, sh = cmd.get('cmd', ''), cmd.get('cwd', ''), cmd.get('shell', False)
                    run_command(cmd, cwd=cwd, shell=sh)
            else:
                return True


    def install(self):
        self.before_install()
        installed = self.execute(self.INSTALL_COMMANDS)
        if installed:
            self.after_install()

    def after_install(self):
        print("Successfully installed!")

    def before_uninstall(self) -> bool:
        """ Ask for confirmation from the user and return """
        return True

    def uninstall(self):
        if self.before_uninstall():
            uninstalled = self.execute(self.UNINSTALL_COMMANDS)
            if uninstalled:
                self.after_uninstall()

    def after_uninstall(self):
        pass

    def before_run(self):
        pass

    def run(self):
        self.before_run()
        ran = self.execute(self.RUN_COMMANDS)
        if ran:
            self.after_run()

    def after_run(self):
        pass

    def is_installed(self, dir_to_check=None):
        print("Unimplemented: DO NOT USE")
        return "?"

    def show_project_page(self):
        webbrowser.open_new_tab(self.PROJECT_URL)


class HackingToolsCollection(object):
    TITLE: str = ""  # used to show info in the menu
    DESCRIPTION: str = ""
    TOOLS = []  # type: List[Any[HackingTool, HackingToolsCollection]]

    def __init__(self):
        pass

    def show_info(self):
        run_command("figlet -f standard -c {} | lolcat".format(self.TITLE))
        # os.system(f'echo "{self.DESCRIPTION}"|boxes -d boy | lolcat')
        # print(self.DESCRIPTION)

    def show_options(self, parent=None):
        clear_screen()
        self.show_info()
        for index, tool in enumerate(self.TOOLS):
            print("[{:2}] {}".format(index, tool.TITLE))
        print("[{:2}] {}".format(
            99, ("Back to " + parent.TITLE) if parent is not None else "Exit"))
        tool_index = input("Choose a tool to proceed: ")
        try:
            tool_index = int(tool_index)
            if tool_index in range(len(self.TOOLS)):
                ret_code = self.TOOLS[tool_index].show_options(parent=self)
                if ret_code != 99:
                    input("\n\nPress ENTER to continue:")
            elif tool_index == 99:
                if parent is None:
                    sys.exit()
                return 99
        except (TypeError, ValueError):
            # raise
            print("Please enter a valid option")
            input("\n\nPress ENTER to continue:")
        except Exception as e:
            print_exc()
            input("\n\nPress ENTER to continue:")
        return self.show_options(parent=parent)
