#!/usr/bin/python

#Special thanks to:
#Nick Sanzotta, for helping with general coding expertise
#unum alces!

# poll various OSINT sources for data, write to .doc
# dns
# shodan
# scrape pastebin, etc
# google dorks via googlesearch 

import sys
import argparse
import subprocess
import dns.resolver
#import urllib2
import shodan
import docx
from google import search

#python-docx: https://pypi.python.org/pypi/python-docx
#shodan: https://github.com/achillean/shodan-python
#google: https://pypi.python.org/pypi/google, also installs beautifulsoup

class colors:
   white = "\033[1;37m"
   normal = "\033[0;00m"
   red = "\033[1;31m"
   blue = "\033[1;34m"
   green = "\033[1;32m"

banner = '\n ' + "-" * 85 + colors.green + '\n  AutOSINT.py v0.1, a way to do some automated OSINT tasks\n ' + colors.normal + "-" * 85 + "\n"

print banner

#check module dependencies
modulename = 'shodan'
if modulename not in sys.modules:
    print colors.red+'\n !!!You have not imported the {} module!!!'.format(modulename) +'\n'+colors.normal
else:
	print colors.green+'\n all module dependencies found \n'+colors.normal

#parse input, nargs allows one or more to be entered
parser = argparse.ArgumentParser()
parser.add_argument("-d","--domain", nargs='+', help="the domain(s) you want to search")
parser.add_argument("-i", "--ipaddress", nargs='+', help="the IP address(es) you want to search")
parser.add_argument("-a", "--all", help="run all queries", action='store_true')
parser.add_argument("-w", "--whois", help="query whois", action='store_true')
parser.add_argument("-n", "--nslookup",help="query DNS", action='store_true')
parser.add_argument("-g", "--google",help="query Google", action='store_true')
args = parser.parse_args()

#set all if all is set, lol
if args.all is True:
	args.whois = True
	args.nslookup = True
	args.google = True
print args

#require at least one argument
if not (args.domain or args.ipaddress):
    parser.error('No action requested, add domain or IP address')

#only allow one of ip or domain
if (args.domain and args.ipaddress):
	parser.error(colors.red+'Only one argument at a time'+colors.normal)

#if no queries defined, exit
if (args.whois is False and args.nslookup is False and args.google is False):
	print colors.red+"No options specified, use -h or --help for a list"+colors.normal
	exit()

#check to see if an ip or domain name was entered
if (args.domain):
	lookup=args.domain
else:
	lookup=args.ipaddress

# only grabs first entry for now
print colors.green+"\nSearching Sources for: "  + lookup[0]+colors.normal
lookup = str(lookup[0])



#probably just need a function to pass in arguments and conditionally run queries instead of 1000 if statements
#
#whois query, dumps out a list
if args.whois is True:
	whoisProcess = subprocess.Popen(["whois",lookup], stdout=subprocess.PIPE)
	whoisOutput = whoisProcess.communicate()[0].split('\n')
	print colors.green+"\nQuerying whois\n"+colors.normal
	print (whoisOutput)
else:
	whoisOutput="no whois performed"


#DNS query, dumps out a list
if args.nslookup is True:
	dnsProcess = subprocess.Popen(['host','-a',lookup], stdout=subprocess.PIPE)
	dnsOutput = dnsProcess.communicate()[0].split('\n')
	print colors.green+"\nQuerying DNS via host -a\n"+colors.normal
	print (dnsOutput)
else:
	dnsOutput="no dns lookup performed"


googleOutput=[]
if args.google is True:
	print colors.green+"\nQuerying google\n"+colors.normal
	for url in search('password site:' +lookup, stop=20):
		print(url)
		googleOutput.append(url)
		

#dump to a word doc
doc = docx.Document()
doc.add_paragraph('Sample Output')
doc.add_paragraph('Google search for the word password')
#doc.add_paragraph(googleOutput)
doc.add_paragraph(whoisOutput)
doc.add_paragraph(dnsOutput)
doc.save('OSINT.docx')

exit()