#! /usr/bin/python3
import os,re,time
from termcolor import colored
from funcs import *



# Prints the description of the script
parser = argparse.ArgumentParser(description='Pentest environment kit script.\n use -h or --help for help',
								 epilog= "Please, the flags were annoying enough to implement; Don't hurt me for this.")
#EXAMPLE: parser.add_argument("--foo", help="foo", default="FOO")
parser.add_argument("-all", help="Updates & Upgrades the OS, then installs tools and software once completed.")
parser.add_argument("-scrub", help="Scrub the /etc/hosts file to the default configuration")
parser.add_argument("-shells", help="BROKEN, CURRENTLY DOES NOTHING")
parser.add_argument("-tools", help="Installs only the tools & software")
parser.add_argument("-jon", help="Prints a compliment to Jon")
parser.add_argument("-c2", help="Installs malware C2 frameworks (currently sliver only)")
parser.add_argument("-test", help="Testing for test purposes, obviously")
#Parse the supplied arguments
args = parser.parse_args()

####
if args.all:
	print(f"You chose {args.all}")
	nginx_config()
	system_update()
	msfdb_init()
	neo4j_init()
	#software_update()
	c2_sliver_install()
elif args.shells:
	print(f"You chose {args.shells}")
	#shell_creation()
elif args.tools:
	print(f"You chose {args.tools}")
	#software_update()
	tool_install()
	tool_update()
	msfdb_init()
	neo4j_init()
	nginx_config()
	c2_sliver_install()
elif args.scrub:
	# This isn't doing anything just yet.
	print("scrubbing /etc/hosts")
elif args.jon:
	jon()
elif args.c2:
	c2_sliver_install()
elif args.test:
	test()
else:
	print(parser.description)

def main():
	os.chdir(f"{dldir}")

if __name__ == "__main__":
    main()
