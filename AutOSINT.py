#!/usr/bin/env python

#By @arbitrary_code

#Special thanks to:
#Nick Sanzotta, for helping with general coding expertise
#unum alces!

# poll various OSINT sources for data, write to .doc
# whois - added
# dns - added
# shodan - added
# scrape pastebin, etc.
# google dorks via googlesearch. only does "password site:domain now"
# BGP info - todo
# AS info - todo
# linkedin (from Nick)
# read pw/keys from github


import sys
import argparse
import subprocess
import dns.resolver
import shodan
import docx
from google import search
from termcolor import colored
import socket

#python-docx: https://pypi.python.org/pypi/python-docx
#shodan: https://github.com/achillean/shodan-python
#google: https://pypi.python.org/pypi/google, also installs beautifulsoup

#*******************************************************************************

def main():

	print colored('''
    _         _    ___  ____ ___ _   _ _____ 
   / \  _   _| |_ / _ \/ ___|_ _| \ | |_   _|
  / _ \| | | | __| | | \___ \| ||  \| | | |  
 / ___ \ |_| | |_| |_| |___) | || |\  | | |  
/_/   \_\__,_|\__|\___/|____/___|_| \_| |_|\n''')

	print colored('AutOSINT.py v0.1, a way to do some automated OSINT tasks\n', 'green')

	#check module dependencies
	moduleDependencies = ('shodan','termcolor','google','docx','shodan')
	for m in moduleDependencies:
		if m not in sys.modules:
		    print colored('!!!You have not imported the' + m + 'module!!!', 'red')
		else:
			print colored('[+] ' + m + 'module dependency found', 'green')

	#parse input, nargs allows one or more to be entered
	parser = argparse.ArgumentParser()
	parser.add_argument('-d','--domain', nargs = '+', help = 'the Domain(s) you want to search')
	parser.add_argument('-i', '--ipaddress', nargs = '+', help = 'the IP address(es) you want to search')
	parser.add_argument('-a', '--all', help = 'run All queries', action = 'store_true')
	parser.add_argument('-w', '--whois', help = 'query Whois', action = 'store_true')
	parser.add_argument('-n', '--nslookup',help = 'Name query DNS', action = 'store_true')
	parser.add_argument('-g', '--google',help = 'query Google', action = 'store_true')
	parser.add_argument('-s', '--shodan', nargs = '?', help = 'query Shodan, optionally provide -s <apikey>')
	parser.add_argument('-v', '--verbose', help = 'Verbosely everything to stdout, equivalent to -wngs', action = 'store_true')
	args = parser.parse_args()
	print args

	#set all
	
	if args.all is True:
		args.whois = True
		args.nslookup = True
		args.google = True



	#validate entered IP address? do we even care? i and d do the same shit
	if args.ipaddress is not None:
		for a in args.ipaddress:
			try:
				socket.inet_aton(a)
			except socket.error:
				print colored("[-] Invalid IP entered! ", 'red') + a

	#require at least one argument
	if not (args.domain or args.ipaddress):
	    parser.error('No action requested, add domain(s) or IP address(es)\n')

	#if no queries defined, exit
	if (args.whois is False and args.nslookup is False and args.google is False and args.shodan is False):
		print colored('No options specified, use -h or --help for a list', 'red')
		exit()


	#check to see if an ip or domain name was entered
	if args.domain is not None:
		for d in args.domain:
			lookup = args.domain
	else:
		for i in args.ipaddress:
			lookup = args.ipaddress

	print "lookup value is "+ str(lookup)



	# only grabs first entry for now
	#print colored('Searching Sources for: '  + lookup[0] + '\n')
	#lookup = str(lookup[0])

	#call functions



	if args.whois is True:
		whoisResultWrite = whois_search(args, lookup)
	
	if args.nslookup is True:
		dnsResultWrite = dns_search(args, lookup)
	
	if args.google is True:
		googleResultWrite = google_serach(args, lookup)
	
	if args.shodan is not None:
		shodanResultWrite = shodan_search(args, lookup)
	
	
	#write_report(args, googleResultWrite, whoisResultWrite, dnsResultWrite, shodanResultWrite)

#*******************************************************************************
#queries whois of ip or domain set in lookup, dumps to stdout if -v is set, writes to file either way
def whois_search(args, lookup):



	whoisResult = []

	#iterate the index and values of the lookup list
	for i, l in enumerate(lookup):
		print colored ('Performing whois query ' + str(i + 1) + ' for ' + l, 'blue')
		
		#subprocess open the whois command for current value of "l" in lookup list. 
		#split into newlines instead of commas
		whoisResult = subprocess.Popen(['whois',l], stdout = subprocess.PIPE).communicate()[0].split('\n')

		#append lists together
		whoisResult.append(str(whoisResult))

		#verbose logic
		if args.verbose is True:
			print whoisResult

	return whoisResult
#*******************************************************************************
def dns_search(args, lookup):
	
	#DNS query, dumps out a list
	
	dnsResult = []
	#iterate the index and values of the lookup list
	for i, l in enumerate(lookup):
		print colored('Performing DNS query ' + str(i + 1) + ' for ' + l, 'blue')
		
		#subprocess to run host -a on the current value of l in the loop, split into newlines
		dnsResult = subprocess.Popen(['host','-a', str(l)], stdout = subprocess.PIPE).communicate()[0].split('\n')

		#append lists together
		dnsResult.append(str(dnsResult))


		#print dnsResult
		if args.verbose is True:
			print dnsResult
		#verbose logic


	#return list object
	return dnsResult



#*******************************************************************************
#this could be GREATLY improved
def google_serach(args, lookup):

	googleResult = []

	for i, l in enumerate(lookup):
		print colored('Google query ' + str(i + 1) + ' for "password site:' + l, 'blue')
		for url in search('password site:' + l, stop = 20):
			if args.verbose is True:
				print(url)
			googleResult.append(str(url))

	return googleResult

#*******************************************************************************
def shodan_search(args, lookup):
	#probably need to customize search type based on -i or -d		
	#ref this https://shodan.readthedocs.io/en/latest/tutorial.html#connect-to-the-api
	#returns json

	shodanResult = []
	#list that we'll return

	shodanApiKey = args.shodan
	shodanApi = shodan.Shodan(shodanApiKey)
	print shodanApiKey

	# Search Shodan
	if shodanApiKey is not None:
		
		for i, l in enumerate(lookup):
			print colored('Querying Shodan via API search for ' + l, 'blue')
			results = shodanApi.search(lookup)
			if args.verbose is True:
				print 'Results found: %s' % results['total']
				for result in results['matches']:
					print 'IP: %s' % result['ip_str']
					print result['data']
					shodanResult.append(str(results))
	
	return shodanResult
			
#*******************************************************************************
def write_report(args, googleResult, whoisResult, dnsResult, shodanResult):


	print colored('Writing results of your query options for to a .docx into the current directory', 'yellow')
	#dump to a word doc
	doc = docx.Document()
	doc.add_paragraph('Sample Output')
	doc.add_paragraph('Google search for the word password')
	doc.add_paragraph(googleResult)
	doc.add_paragraph(whoisResult)
	doc.add_paragraph(dnsResult)
	doc.add_paragraph(shodanResult)
	doc.save('OSINT.docx')

if __name__ == '__main__':
    main()
