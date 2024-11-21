# coding=utf-8
from core import HackingTool
from core import HackingToolsCollection


class TerminalMultiplexer(HackingTool):
    TITLE = "Terminal Multiplexer"
    DESCRIPTION = "Terminal Multiplexer is a tiling terminal emulator that " \
                  "allows us to open \n several terminal sessions inside one " \
                  "single window."
    INSTALL_COMMANDS = ["sudo apt-get install tilix"]

    def __init__(self):
        super(TerminalMultiplexer, self).__init__(runnable = False)


class Crivo(HackingTool):
    TITLE = "Crivo"
    DESCRIPTION = "A tool for extracting and filtering URLs, IPs, domains, " \
                  "\n and subdomains from web pages or text, " \
                  "with built-in web scraping capabilities.\n" \
                  "See: python3 crivo_cli.py -h"
    INSTALL_COMMANDS = [
        "git clone https://github.com/GMDSantana/crivo.git",
        "cd crivo;pip install -r requirements.txt"
    ]
    PROJECT_URL = "https://github.com/GMDSantana/crivo"

    def __init__(self):
        super(Crivo, self).__init__(runnable = False)


class MixTools(HackingToolsCollection):
    TITLE = "Mix tools"
    TOOLS = [
        TerminalMultiplexer(),
        Crivo()
    ]

