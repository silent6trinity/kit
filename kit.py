#! /usr/bin/python3
# Attempt to recreate kit.sh with python - This is meant for linux
# For the time being, a lot of the calls are going to be invoked by os.system()
## This isn't safe/smart, but time...burnout....etc

# TODO: Instead of individual lines for package installs, why not iterate through
##       a list of them instead? Or better yet, maybe pull them from a text file
import os
from termcolor import colored

user = os.getlogin()
sublime = 'deb https://download.sublimetext.com/ apt/stable/'


#TODO: Make this less error prone - some linux flavors don't have /home at the root
#TODO: Check to make sure we're in the Downloads directory before installs & downloads - otherwise bail
#TODO: Grab the neo4j database info, make sure its running and provide to user
#TODO: Grab the neo4j webserver & the associated port

#TODO: Ensure that the Metasploit database service is up & running, provide info to the user
# cd_dl = f"/home/{user}/Downloads/"


def system_update():
    os.system('sudo apt install python3-pip -y')
    os.system('sudo apt update -y')
    os.system('sudo apt upgrade -y')
    os.system('sudo apt upgrade -y')
    os.system('sudo apt autoremove -y')
    print("")
    print(colored("Finished SYSTEM setup", 'green'))
    print("")
    return()

def software_update():
    print("")
    print(colored("Beginning Software install(s) & updates, please wait...", 'blue'))
    print("")

    os.system('wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg\
                | sudo apt-key add -')
    os.system('sudo apt-get install apt-transport-https')
    os.system(f'echo {sublime} | sudo tee /etc/apt/sources.list.d/sublime-text.list')
    os.system('sudo apt-get install sublime-text -y')
    os.system('sudo apt install seclists -y')
    os.system('sudo apt install gobuster -y')
    os.system('sudo apt install metasploit-framework -y')
    os.system('sudo apt install crackmapexec -y')
    os.system('sudo apt install snmpcheck -y')
    os.system('sudo apt install enum4linux -y')
    os.system('sudo apt install smbmap -y')
    os.system('sudo apt install wfuzz -y')
    os.system('sudo apt install yersinia -y')
    os.system('sudo apt install bloodhound -y')
    os.system('sudo apt install subfinder')
    os.system('sudo apt install tilix')
    os.system('sudo apt install -y')
    os.system('pip3 install one-lin3r')
    os.system('pip3 install ptftpd')
    os.system('pip3 install bloodhound')
    os.system('sudo mkdir -p /usr/share/neo4j/logs')
    os.system('sudo touch /usr/share/neo4j/logs/neo4j.log')
    os.system('sudo neo4j start')
    # now to check if the software already exists...
    # Change 'path' so that it's either dynamic or ... will actually work
    # maybe even make the check a function later on...

# TODO: Adjust the dir/file checks to local, rather than abspath
    ### BEGIN IF/ELSE CHECKS FOR SOFTWARE ####
    if os.path.exists("/usr/local/bin/one-lin3r"):
        print(colored("one-lin3r already exists in /usr/local/bin already exists in /usr/local/bin, continuing...\n", 'green'))
    else:
        os.system(f"sudo ln -s /home/{user}/.local/bin/one-lin3r /usr/local/bin")

    if os.path.exists("/home/$user/Downloads/nmap-vulners"):
        os.system(f'sudo cp /home/{user}/Downloads/nmap-vulners/vulners.nse /usr/share/nmap/scripts/vulners.nse')
        print(colored("nmap-vulners already installed, continuing...\n", 'green'))
    else:
        os.system('git clone https://github.com/vulnersCom/nmap-vulners')
        os.system(f'sudo cp /home/{user}/Downloads/nmap-vulners/vulners.nse /usr/share/nmap/scripts/vulners.nse')

    if os.path.exists(f'/home/{user}/Downloads/nmapAutomator'):
        print(colored("nmapAutomator already installed, continuing...", 'green'))
        if not os.path.exists('/usr/local/bin/nmapAutomator.sh'):
            os.system(f'sudo ln -s /home/{user}/Downloads/nmapAutomator/nmapAutomator.sh /usr/local/bin/')
        else:
            print(colored("Already have nmapAutomator in local binaries, continuing...\n", 'green'))
    else:
        os.system('git clone https://github.com/21y4d/nmapAutomator')
        os.system(f'chmod +x /home/{user}/Downloads/nmapAutomator/nmapAutomator.sh')
        print('nmapAutomator is now dynamically executable')


    if os.path.exists(f'/home/{user}/Downloads/Impacket'):
        print(colored("Impacket is already installed, continuing...\n", 'green'))
    else:
        os.system('git clone https://github.com/SecureAuthCorp/Impacket')

        #TODO: After install, rename the directory, because... do I need to justify?
    if os.path.exists(f'/home/{user}/Downloads/privilege-escalation-awesome-scripts-suite'):
        print(colored("LinPEAS & WinPEAS already installed, continuing...\n", 'green'))
    else:
        os.system('git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite')


    if os.path.exists('/usr/local/bin/LinEnum.sh'):
        print(colored("LinEnum already installed, continuing...\n", 'green'))
    else:
        os.system(f'wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh\
                    -O /home/{user}/Downloads/LinEnum.sh')
        os.system(f'sudo ln -s /home/{user}/Downloads/LinEnum.sh /usr/local/bin/')


    if os.path.exists(f'/home/{user}/Downloads/evil-winrm'):
        print(colored("evil-winRM already installed, continuing...\n", 'green'))
    else:
        os.system('git clone https://github.com/HackPlayers/evil-winrm')


    if os.path.exists(f'/home/{user}/Downloads/Enum4LinuxPy'):
        print(colored("Enum4LinuxPy already installed, continuing...\n", 'green'))
    else:
        os.system('git clone https://github.com/0v3rride/Enum4LinuxPy')


    if os.path.exists(f'/home/{user}/Downloads/vlan-hopping'):
        print(colored("VLAN-Hopping already installed, continuing...", 'green'))
    else:
        os.system('git clone https://github.com/nccgroup/vlan-hopping.git')
        #### END IF ELSE CHECKS #####

    ### TOOL UPDATES & SETUPS ###
    print("Updating searchsploit DB....\n")
    os.system('sudo searchsploit -u')
    print(colored("Finished searchsploit update", 'green'))
    print("Updating locate DB...\n")
    os.system('sudo updatedb')
    print(colored("Finished locate DB update \n", 'green'))
    print("Updating nmap script database\n")
    os.system('sudo nmap --script-updatedb')
    print(colored("nmap script database updated \n", 'green'))

    print("Checking if rockyou has been unzipped...")
    if os.path.isfile('/usr/share/wordlists/rockyou.txt.gz'):
        print("It hasn't been decompressed - decompressing now...\n")
        os.system('sudo gunzip /usr/share/wordlists/rockyou.txt.gz')
    else:
        print(colored("rockyou has already been unzipped \n", 'green'))

    print(colored("Software & Tool updates have been completed!", 'green'))
    return()
    #### END TOOL UPDATES & SETUPS ####


#Wrap the functions with the user choices now
def all():
    os.system(f"cd /home/{user}/Downloads/")
    system_update()
    software_update()
    return()

def tools():
    os.system(f"cd /home/{user}/Downloads/")
    software_update()
    return()

def main():
    print(colored("Automated Kit buildout script\n", 'blue'))
    print("Would you like to install ALL or just the TOOLS?\n")
    print("Please type TOOLS or ALL \n")
    choice = input()
    choice = str(choice)
    if choice == "ALL":
        all()
    elif choice == "TOOLS":
        tools()
    else:
        print("You had one simple choice and you already screwed that up")

if __name__ == "__main__":
    main()    
