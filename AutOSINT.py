#!/usr/bin/env python

#By @arbitrary_code

#Special thanks to:
#@Beamr
#@tatanus
#unum alces!

try:

	import argparse, time, os


	'''import sys

	
	import subprocess
	import socket
	

	import urllib
	import urllib2



	import re
	
	import json
	import pprint
	from lxml import html

	from collections import Counter'''

	#AutOSINT module imports
	from webscrape import Scraper
	from whois import Whois
	from dnsquery import Dnsquery
	from hibp import Haveibeenpwned
	from googledork import Googledork
	from shodansearch import Shodansearch
	from pastebinscrape import Pastebinscrape
	from theharvester import Theharvester
	from credleaks import Credleaks
	from pyfoca import Pyfoca
	from reportgen import Reportgen

except ImportError as e:
	raise ImportError('Error importing %s' % e)
	sys.exit(1)

#*******************************************************************************

def main():
	startTime=time.time()

	#parse input, nargs allows one or more to be entered
	#https://docs.python.org/3/library/argparse.html
	#set nargs back to + for multi search of domain or ip (still really buggy)
	parser = argparse.ArgumentParser()
	parser.add_argument('-a', '--all', help = 'run All queries', action = 'store_true')
	parser.add_argument('-b', '--hibp', help='Search haveibeenpwned.com for breaches related to a domain', action='store_true')
	parser.add_argument('-c', '--creds', help = 'Search local copies of credential dumps', action = 'store_true')
	parser.add_argument('-d', '--domain', nargs = 1, help = 'the Domain you want to search.')
	parser.add_argument('-f', '--foca', help = 'invoke pyfoca', action = 'store_true')
	parser.add_argument('-g', '--googledork', nargs = '+',help = 'query Google for supplied args that are treated as a dork. i.e. -g password becomes a search for "password site:<domain>". Combine terms inside of quotes like "site:rapid7.com inurl:aspx" ')
	parser.add_argument('-i', '--ipaddress', nargs = 1, help = 'the IP address you want to search. Must be a valid IP. ')
	parser.add_argument('-n', '--nslookup',help = 'Name query DNS for supplied -d or -i values. Requires a -d or -i value', action = 'store_true')
	parser.add_argument('-p', '--pastebinsearch', nargs = '+', help = 'Search google for <arg> site:pastebin.com. Requires a pro account if you dont want to get blacklisted.')
	parser.add_argument('-s', '--shodan', help = 'query Shodan, API keys stored in ./api_keys/', action='store_true')
	parser.add_argument('-S', '--scraper', help = 'Scrape pastebin, github, indeed, more to be added. API keys stored in ./api_keys/', action = 'store_true')
	parser.add_argument('-t', '--theharvester', help = 'Invoke theHarvester', action = 'store_true')
	parser.add_argument('-v', '--verbose', help = 'Verbose', action = 'store_true')	
	parser.add_argument('-w', '--whois', help = 'query Whois for supplied -d or -i values. Requires a -d or -i value', action = 'store_true')
	
	args = parser.parse_args()

	#verbosity flag to print logo and args
	if args.verbose is True:print '''
    _         _    ___  ____ ___ _   _ _____ 
   / \  _   _| |_ / _ \/ ___|_ _| \ | |_   _|
  / _ \| | | | __| | | \___ \| ||  \| | | |  
 / ___ \ |_| | |_| |_| |___) | || |\  | | |  
/_/   \_\__,_|\__|\___/|____/___|_| \_| |_|\n'''

	if args.verbose is True:print 'AutOSINT.py v0.2, a way to do some automated OSINT tasks\n'
	if args.verbose is True:print args

	#set True on action store_true args if -a
	if args.all is True:
		args.creds = True
		args.hibp = True
		args.foca = True
		args.nslookup = True
		args.theharvester = True
		args.whois = True
		args.scraper = True
		args.shodan = True
		if args.googledork is None:
			print '[-] You need to provide arguments for google dorking. e.g -g inurl:apsx'
			sys.exit()
		if args.pastebinsearch is None:
			print '[-] You need to provide arguments for pastebin keywords. e.g -p password id_rsa'
			sys.exit()

	#check directories
	reportDir='./reports/'
	apiKeyDir='./api_keys/'
	if not os.path.exists(reportDir):
		os.makedirs(reportDir)

	if not os.path.exists(apiKeyDir):
		os.makedirs(apiKeyDir)

	#validate entered IP address? do we even care about IP address? i and d do the same shit
	if args.ipaddress is not None:
		for a in args.ipaddress:
			try:
				socket.inet_aton(a)
			except socket.error:
				print '[-] Invalid IP address entered!' + a
				sys.exit()

	#require at least one argument
	if not (args.domain or args.ipaddress):
	    parser.error('[-] No OSINT reference provided, add domain(s) with -d or IP address(es) with -i\n')
	    sys.exit()

	#if no queries defined, exit. -a sets all so we're good there
	if (args.whois is False and \
		args.hibp is False and \
		args.nslookup is False and \
		args.googledork is None and \
		args.shodan is False and \
		args.creds is False and \
		args.theharvester is False and \
		args.scraper is False and \
		args.pastebinsearch is None and \
		args.foca is False):
		print '[-] No options specified, use -h or --help for a list'
		sys.exit()

	#check to see if an ip or domain name was entered
	if args.domain is not None:
		for d in args.domain:
			lookup = args.domain
			for l in lookup:
				if not os.path.exists(reportDir+'/'+l):
					os.makedirs(reportDir+'/'+l)
				
	else:
		for i in args.ipaddress:
			lookup = args.ipaddress
			for l in lookup:
				if not os.path.exists(reportDir+'/'+l):
					os.makedirs(reportDir+'/'+l)

	if args.verbose is True:
		print '[+] Lookup Values: '+', '.join(lookup)


	#init results lists, this can probably be done a better way
	whoisResult=[]
	dnsResult = []
	googleResult =[]
	shodanResult=[]
	pasteScrapeResult = []
	pasteScrapeContent = []
	harvesterResult =[]
	scrapeResult=[]
	credResult=[]
	pyfocaResult=[]
	hibpResult=[]

	#call function if -w arg
	if args.whois is True:
		
		whoisSearch = Whois()
		whoisResult = whoisSearch.run(args, lookup, reportDir)

	#call function if -n arg
	if args.nslookup is True:
		
		dnsQuery = Dnsquery()
		dnsResult = dnsQuery.run(args, lookup, reportDir)

	#call function if -b arg
	if args.hibp is True:

		hibpSearch = Haveibeenpwned()
		hibpResult = hibpSearch.run(args, lookup, reportDir)

	#call function if -g arg
	if args.googledork is not None:
		
		googleDork = Googledork()
		googleResult = googleDork.run(args, lookup, reportDir)

	#call function if -s arg
	if args.shodan is True:
		
		shodanSearch = Shodansearch()
		shodanResult = shodanSearch.run(args, lookup, reportDir, apiKeyDir)

	#call function if -p arg
	if args.pastebinsearch is not None:
		
		pastebinScrape = Pastebinscrape()
		pasteScrapeResult = pastebinScrape.run(args, lookup, reportDir, apiKeyDir)

	# call function if -t arg
	if args.theharvester is True:
		
		theHarvester = Theharvester()
		harvesterResult = theHarvester.run(args, lookup, reportDir)

	#call function if -c arg 
	if args.creds is True:
		
		credLeaks = Credleaks()
		credResult = credLeaks.run(args, lookup, startTime, reportDir)


	#call function if -S arg
	if args.scraper is True:
		
		web_scraper = Scraper()
		scrapeResult = scrapeResults = web_scraper.run(args, lookup, reportDir, apiKeyDir)

	#call function if -f arg
	if args.foca is True:
		
		pyFoca = Pyfoca()
		pyfocaResult = pyFoca.run(args, lookup, reportDir)

	#run the docx report. text files happen in the respective functions
	
	reportGen = Reportgen()
	reportGen.run(args, reportDir, lookup, whoisResult, dnsResult, googleResult, shodanResult, pasteScrapeResult, harvesterResult, scrapeResult, credResult, pyfocaResult)


	
if __name__ == '__main__':
    main()
