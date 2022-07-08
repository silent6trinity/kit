#! /usr/bin/python3

import os, re
from simple_term_menu import TerminalMenu
from termcolor import colored
from funcs import *

# Maybe sometime later we'll take this and make a separate file, but for now, I want everything in
## one single executable file


#### !!! Consider creating an empty array that we append the finished software to once it has been installed
#TODO: Make this less error prone - some linux flavors don't have /home at the root
#TODO: Check to make sure we're in the Downloads directory before installs & downloads - otherwise bail
#TODO: Grab the neo4j database info, make sure its running and provide to user
#TODO: Grab the neo4j webserver & the associated port ---> netstat -tano | grep -i "7474"
#TODO: Adjust the dir/file checks to local, rather than abspath
#TODO: Use a list of github repos and iterate through them, rather than this mess
#TODO: Install assetfinder
#TODO: After install, rename the privilege-escalation-suite dir to PEAS
#TODO: Ensure that the Metasploit database service is up & running, provide info to the user
#TODO: Maybe do a search to check if any errors or packages werent able to be added during the script
#TODO: Separate the function creations into its own python file and import them
# sudo systemctl start postgresql
# <check to ensure the service is running now>
# msfdb init

#ADD PyPi PACLAGES TO ME
#pypi_packages = ['one-lin3r','ptftpd','bloodhound','colorama','pysnmp']

sublime = 'deb https://download.sublimetext.com/ apt/stable/'
user = os.getlogin()

# This grabs the IP address of tun0 and uses it to start generating malicious binaries
## TODO: Create a method to select what interface you want to use
# ip_addr = os.popen('ip addr show tun0 | grep "\\<inet\\>" | awk \'{ print $2 }\' | awk -F "/" \'{ print $1 }\'').read().strip()
# This port is used for malicious binary generation
# listen_port = 6969

# I moved this back into the main python executable, because I didn't like the idea of main() being in a function warehouse
def main():
    os.chdir("/opt")
    terminal_selection()

if __name__ == "__main__":
    main()
