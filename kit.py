#! /usr/bin/python3

import os,re,time
from simple_term_menu import TerminalMenu
from termcolor import colored
from funcs import *

#### !!! Consider creating an empty array that we append the finished software to once it has been installed
#TODO: Grab the neo4j database info, make sure its running and provide to user
#TODO: Grab the neo4j webserver & the associated port ---> netstat -tano | grep -i "7474"
#TODO: Adjust the dir/file checks to local, rather than abspath
#TODO: After install, rename the privilege-escalation-suite dir to PEAS
#TODO: Ensure that the Metasploit database service is up & running, provide info to the user
#TODO: Maybe do a search to check if any errors or packages werent able to be added during the script
#TODO: Potentially rename the functions so they make more sense, and condense
#TODO: Scrub /etc/hosts file so that it only has the typical localhost/kali entries
#TODO: Add command-line argument options
#TODO: Check to make sure the kali installation is a proper VMX, because the others kinda break
#TODO: x11 keyboard injection script
#TODO: Include ansible malicious playbook
#TODO: Include windows persistence snippet(s)

# sudo systemctl start postgresql
# <check to ensure the service is running now>
# msfdb init

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

# This grabs the IP address of tun0 and uses it to start generating malicious binaries
## TODO: Create a method to select what interface you want to use
# ip_addr = os.popen('ip addr show tun0 | grep "\\<inet\\>" | awk \'{ print $2 }\' | awk -F "/" \'{ print $1 }\'').read().strip()
# ip_addr = os.popen('ip addr show eth0 | grep "\\<inet\\>" | awk \'{ print $2 }\' | awk -F "/" \'{ print $1 }\'').read().strip()
# This port is used for malicious binary generation
# listen_port = 6969

# I moved this back into the main python executable, because I didn't like the idea of main() being in a function warehouse
def main():
    os.chdir("/home/kali/Downloads")
    print(os.system("pwd"))
    #terminal_selection()

if __name__ == "__main__":
    main()
