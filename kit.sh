#!/bin/zsh


#### COLORS ####
C=$(printf '\033')
RED="${C}[1;31m"
G="${C}[1;32m"
Y="${C}[1;33m"
NC="${C}[0m"
################

echo "$Y Automated kit buildout script"
echo "$NC"

set -eu -o pipefail # If we fail due to some error, debug all lines
sudo -n true
test $? -eq 0 || exit 1 "$RED ERROR: This script must be run as root"
echo "$NC"

###################
#### FUNCTIONS ####
# SYSTEM LEVEL UPDATES & INSTALLS
function systemupdate() {
	cd /home/kali/Downloads
	wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg | sudo apt-key add -
	sudo apt-get install apt-transport-https
	echo "deb https://download.sublimetext.com/ apt/stable/" | sudo tee /etc/apt/sources.list.d/sublime-text.list
	sudo apt install python3-pip -y
	sudo apt update -y
	sudo apt upgrade -y
	sudo apt upgrade -y
	sudo apt autoremove -y
	echo "$G Finished SYSTEM setup, continuing to software and tools.. $NC"
	echo ""
}

# SOFTWARE TOOL PACKAGE INSTALLS
function softwareupdate() {
	cd /home/kali/Downloads
	echo "$Y Beginning software installs & updates.. $NC"
	echo ""
	sudo apt-get install python-pip -y
	sudo apt-get install sublime-text -y
	sudo apt install seclists -y
	sudo apt install gobuster -y
	sudo apt install crackmapexec -y
	sudo apt install snmpcheck -y
	sudo apt install enum4linux -y
	sudo apt install smbmap -y
	sudo apt install wfuzz -y
	sudo apt install yersinia -y
	sudo apt install bloodhound -y
	sudo apt install subfinder
	sudo apt install tilix
	sudo apt install -y
	pip3 install one-lin3r
	pip3 install ptftpd
	pip3 install bloodhound
	sudo mkdir -p /usr/share/neo4j/logs
	sudo touch /usr/share/neo4j/logs/neo4j.log
	sudo neo4j start

	if [[ ! -f "/usr/local/bin/one-lin3r" ]]; then
		sudo ln -s /home/kali/.local/bin/one-lin3r /usr/local/bin/
	else
		echo "$Y one-lin3r already exists in /usr/local/bin"
		echo "$NC"
		echo "Continuing..."
	fi

	# GIT CLONES
	if [[ ! -d "/home/kali/Downloads/nmap-vulners" ]]; then
		git clone https://github.com/vulnersCom/nmap-vulners
	elif [[ -d "/home/kali/Downloads/nmap-vulners" ]]; then
		cp /home/kali/Downloads/nmap-vulners/vulners.nse /usr/share/nmap/scripts/vulners.nse
	fi
	
	if [[ ! -d "/home/kali/Downloads/nmapAutomator" ]]; then
		git clone https://github.com/21y4d/nmapAutomator
		chmod +x /home/kali/Downloads/nmapAutomator/nmapAutomator.sh
		echo "nmapAutomator is now executable"
		if [[ ! -f /usr/local/bin/nmapAutomator.sh ]]; then
			sudo ln -s /home/kali/Downloads/nmapAutomator/nmapAutomator.sh /usr/local/bin/
		fi
	else
		echo "$Y Already have nmapAutomator.... continuing $NC"
	fi

	if [[ ! -d "/home/kali/Downloads/Impacket" ]]; then
		git clone https://github.com/SecureAuthCorp/Impacket
	else
		echo "$Y Already have Impacket, continuing $NC"
	fi
	if [[ ! -d "/home/kali/Downloads/privilege-escalation-awesome-scripts-suite" ]]; then
		git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite
		mv "/home/kali/Downloads/privilege-escalation-awesome-scripts-suite" "/home/kali/Downloads/PEAS"
	else
		echo "$Y Already have LinPEAS & WinPEAS... continuing $NC"
	fi

	if [[ ! -d "/home/kali/Downloads/mitm6" ]]; then
		git clone https://github.com/fox-it/mitm6
		pip3 install -r ~/home/kali/Downloads/mitm6/requirements.txt
		python3 /home/kali/Downloads/mitm6/setup.py install
	else
		echo "$Y Already have LinPEAS & WinPEAS... continuing $NC"
	fi

	if [[ ! -e "/usr/local/bin/LinEnum.sh" ]]; then
		wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /home/kali/Downloads/LinEnum.sh
		sudo ln -s /home/kali/Downloads/LinEnum.sh /usr/local/bin/
	else
		echo "$Y Already have LinEnum.sh... continuing $NC"
	fi
	if [[ ! -d "/home/kali/Downloads/evil-winrm" ]]; then
		git clone https://github.com/HackPlayers/evil-winrm
	else
		echo "$Y Already have evil-winrm... continuing"
	fi
	if [[ -d "/home/kali/Downloads/Enum4LinuxPy" ]]; then
		git clone https://github.com/0v3rride/Enum4LinuxPy
	else
		echo "$Y Already have Enum4LinuxPy... contuing"
	fi
	if [[ -d "/home/kali/Downloads/vlan-hopping" ]]; then
		git clone https://github.com/nccgroup/vlan-hopping.git
	else:
		echo "$Y Already have vlan-hopping.... continuing"
	fi


	# TOOL UPDATES & SETUPS
	echo "$Y Updating searchsploit database...$NC"
	sudo searchsploit -u
	echo "$G Searchsploit database updated. $NC"
	echo ""
	echo "$Y Updating locate database...$NC"
	sudo updatedb
	echo "$G locate database updated. $NC"
	echo "$Y Updating metasploit $NC"
	sudo apt install metasploit-framework
	echo "$G metasploit updated"
	echo "$Y Updating nmap script database... $NC"
	nmap --script-updatedb
	echo ""
	echo ""
	echo "$G nmap database updated $NC"

	if [[ -d "/usr/share/wordlists/rockyou.txt.gz" ]]; then
		sudo gunzip /usr/share/wordlists/rockyou.txt.gz
	else
		echo "$G rockyou has already been decompressed."
	fi
}

function main() {
	softwareupdate
	systemupdate
}

###### END FUNCTIONS ######


##### MAIN ####
echo "$Y Would you like to install$NC$RED ALL$NC?"
echo "$Y Or just all $NC$RED TOOLS?$NC$Y If TOOLS is selected, apt update, install, upgrade, etc. Will not be performed. $NC"

read input

if [[ $input == "ALL" ]]; then
	systemupdate
	softwareupdate
elif
	[[ $input == "TOOLS" ]]; then
	softwareupdate
else
		echo "Improper input"
		echo "Exiting"
		exit 1
fi

echo ""
echo ""
echo "$G Script Complete! $NC"
exit 2
