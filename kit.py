#! /usr/bin/python3

import os,re,time
from simple_term_menu import TerminalMenu
from termcolor import colored
from funcs import *

user = os.getlogin()

# Prints the description of the script
parser = argparse.ArgumentParser(description='Pentest environment kit script.\n use -h or --help for help',
								 epilog= "Please, the flags were annoying enough to implement; Don't hurt me for this.")
#Possible providable arguments
#EXAMPLE: parser.add_argument("--foo", help="foo", default="FOO")

parser.add_argument("-all", help="Updates & Upgrades the OS, then installs tools and software once completed.")
parser.add_argument("-scrub", help="Scrub the /etc/hosts file to the default configuration")
parser.add_argument("-shells", help="BROKEN, CURRENTLY DOES NOTHING")
parser.add_argument("-tools", help="Installs only the tools & software")
parser.add_argument("-jon", help="Prints a compliment to Jon")
#parser.add_argument("--four", help="Four")
parser.add_argument("-test", help="Testing for test purposes, obviously")
#Parse the supplied arguments
args = parser.parse_args()

####
if args.all:
	print(f"You chose {args.all}")
elif args.shells:
	print(f"You chose {args.shells}")
elif args.tools:
	print(f"You chose {args.tools}")
elif args.scrub:
	print("scrubbing /etc/hosts")
elif args.jon:
	jon()
elif args.test:
	test()
else:
	print(parser.description)


def main():
    os.chdir("/home/kali/Downloads")
    #terminal_selection()

if __name__ == "__main__":
    main()
