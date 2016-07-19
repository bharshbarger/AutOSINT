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
import urllib2
import shodan
import docx

#python-docx: https://pypi.python.org/pypi/python-docx
#shodan: https://github.com/achillean/shodan-python
#google: https://pypi.python.org/pypi/google


class colors:
   white = "\033[1;37m"
   normal = "\033[0;00m"
   red = "\033[1;31m"
   blue = "\033[1;34m"
   green = "\033[1;32m"

banner = '\n ' + "-" * 85 + colors.white + '\n  AutOSINT.py v0.1, a way to do some automated OSINT tasks\n ' + colors.normal + "-" * 85 + "\n"

print banner

#parse input, nargs allows one or more to be entered
parser = argparse.ArgumentParser()
parser.add_argument("-d","--domain", nargs='+', help="the domain(s) you want to search")
parser.add_argument("-i", "--ipaddress", nargs='+', help="the IP address(es) you want to search")
args = parser.parse_args()


#require at least one argument
if not (args.domain or args.ipaddress):
    parser.error('No action requested, add domain or IP address')

#only allow one argument at a time
if (args.domain and args.ipaddress):
	parser.error('Only one argument at a time')

#check to see if an ip or domain name was entered
if (args.domain):
	lookup=args.domain
else:
	lookup=args.ipaddress

#check module dependencies
modulename = 'shodan'
if modulename not in sys.modules:
    print colors.red+'\n !!!You have not imported the {} module!!!'.format(modulename) +'\n'+colors.normal
else:
	print colors.green+'\n all module dependencies found \n'+colors.normal
    
# only grabs first entry for now
print "Searching Sources for: "  + lookup[0]
lookup = str(lookup[0])


#whois query, dumps out a list
whoisProcess = subprocess.Popen(["whois",lookup], stdout=subprocess.PIPE)
whoisOutput = whoisProcess.communicate()[0].split('\n')
print (whoisOutput)

#DNS query, dumps out a list
dnsProcess = subprocess.Popen(["host",lookup], stdout=subprocess.PIPE)
dnsOutput = dnsProcess.communicate()[0].split('\n')
print (dnsOutput)



#dump to a word doc
doc = docx.Document()
doc.add_paragraph('Sample Output')
doc.add_paragraph(whoisOutput)
doc.add_paragraph(dnsOutput)
doc.save('OSINT.docx')