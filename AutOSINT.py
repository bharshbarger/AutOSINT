#!/usr/bin/env python

#By @arbitrary_code
#https://github.com/bharshbarger/AutOSINT

#Special thanks to:
#@Beamr
#@tatanus
#unum alces!

try:

	import argparse, time, os

	'''import sys
	import urllib
	import urllib2
	import re
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

class Autosint:

	def __init__(self, args):

		#version
		self.version = '0.2'

		#container for lookup values (domain or ip(ip not working rn))
		self.lookup = []

		#module results lists
		self.whoisResult = []
		self.dnsResult = []
		self.googleResult = []
		self.shodanResult = []
		self.pasteScrapeResult = []
		self.pasteScrapeContent = []
		self.harvesterResult = []
		self.scrapeResult = []
		self.credResult = []
		self.pyfocaResult = []
		self.hibpResult = []

		#start timer
		self.startTime=time.time()

		#local dirs
		self.reportDir='./reports/'
		self.apiKeyDir='./api_keys/'


		
		#check local dirs
		if not os.path.exists(self.reportDir):
			os.makedirs(self.reportDir)

		if not os.path.exists(self.apiKeyDir):
			os.makedirs(self.apiKeyDir)
	
	def clear(self):

		#clean up screen
	    os.system('cls' if os.name == 'nt' else 'clear')


	def banner(self, args):
			
		#verbosity flag to print logo and args
		if args.verbose is True:print '''
	    _         _    ___  ____ ___ _   _ _____ 
	   / \  _   _| |_ / _ \/ ___|_ _| \ | |_   _|
	  / _ \| | | | __| | | \___ \| ||  \| | | |  
	 / ___ \ |_| | |_| |_| |___) | || |\  | | |  
	/_/   \_\__,_|\__|\___/|____/___|_| \_| |_|\n'''

		if args.verbose is True:print 'AutOSINT.py %s, a way to do some automated OSINT tasks\n' % self.version
		if args.verbose is True:print args

	
	def checkargs(self, args):
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
				self.lookup = args.domain
				for l in self.lookup:
					if not os.path.exists(self.reportDir+'/'+l):
						os.makedirs(self.reportDir+'/'+l)
					
		else:
			for i in args.ipaddress:
				self.lookup = args.ipaddress
				for l in self.lookup:
					if not os.path.exists(self.reportDir+'/'+l):
						os.makedirs(self.reportDir+'/'+l)

		if args.verbose is True:
			print '[+] Lookup Values: '+', '.join(self.lookup)


		#call function if -w arg
		if args.whois is True:
			whoisSearch = Whois()
			self.whoisResult = whoisSearch.run(args, self.lookup, self.reportDir)

		#call function if -n arg
		if args.nslookup is True:
			dnsQuery = Dnsquery()
			self.dnsResult = dnsQuery.run(args, self.lookup, self.reportDir)

		#call function if -b arg
		if args.hibp is True:
			hibpSearch = Haveibeenpwned()
			self.hibpResult = hibpSearch.run(args, self.lookup, self.reportDir)

		#call function if -g arg
		if args.googledork is not None:
			
			googleDork = Googledork()

			self.googleResult = googleDork.run(args, self.lookup, self.reportDir)

		#call function if -s arg
		if args.shodan is True:
			
			shodanSearch = Shodansearch()

			self.shodanResult = shodanSearch.run(args, self.lookup, self.reportDir, self.apiKeyDir)

		#call function if -p arg
		if args.pastebinsearch is not None:
			pastebinScrape = Pastebinscrape()
			self.pasteScrapeResult = pastebinScrape.run(args, self.lookup, self.reportDir, self.apiKeyDir)

		# call function if -t arg
		if args.theharvester is True:
			theHarvester = Theharvester()
			self.harvesterResult = theHarvester.run(args, self.lookup, self.reportDir)

		#call function if -c arg 
		if args.creds is True:
			credLeaks = Credleaks()
			self.credResult = credLeaks.run(args, self.lookup, self.startTime, self.reportDir)


			#call function if -S arg
		if args.scraper is True:
			web_scraper = Scraper()
			self.scrapeResult = self.scrapeResults = web_scraper.run(args, self.lookup, self.reportDir, self.apiKeyDir)

		#call function if -f arg
		if args.foca is True:
			pyFoca = Pyfoca()
			self.pyfocaResult = pyFoca.run(args, self.lookup, self.reportDir)

	#run the docx report. text files happen in the respective functions
	def report(self, args):
		
		reportGen = Reportgen()
		reportGen.run(args, self.reportDir, self.lookup, self.whoisResult, self.dnsResult, self.googleResult, self.shodanResult, self.pasteScrapeResult, self.harvesterResult, self.scrapeResult, self.credResult, self.pyfocaResult)

def main():

	#https://docs.python.org/3/library/argparse.html
	#set nargs back to + for multi search of domain or ip (still really buggy)
	
	parser = argparse.ArgumentParser()
	parser.add_argument('-a', '--all', help = 'run All queries', action = 'store_true')
	parser.add_argument('-b', '--hibp', help='Search haveibeenpwned.com for breaches related to a domain', action='store_true')
	parser.add_argument('-c', '--creds', help = 'Search local copies of credential dumps', action = 'store_true')
	parser.add_argument('-d', '--domain', metavar='foo.com', nargs = 1, help = 'the Domain you want to search.')
	parser.add_argument('-f', '--foca', help = 'invoke pyfoca', action = 'store_true')
	parser.add_argument('-g', '--googledork', metavar='password id_rsa', nargs = '+',help = 'query Google for supplied args that are treated as a dork. i.e. -g password becomes a search for "password site:<domain>". Combine terms inside of quotes like "site:rapid7.com inurl:aspx" ')
	parser.add_argument('-i', '--ipaddress', nargs = 1, help = 'the IP address you want to search. Must be a valid IP. ')
	parser.add_argument('-n', '--nslookup',help = 'Name query DNS for supplied -d or -i values. Requires a -d or -i value', action = 'store_true')
	parser.add_argument('-p', '--pastebinsearch', metavar='password id_rsa' ,nargs = '+', help = 'Search google for <arg> site:pastebin.com. Requires a pro account if you dont want to get blacklisted.')
	parser.add_argument('-s', '--shodan', help = 'query Shodan, API keys stored in ./api_keys/', action='store_true')
	parser.add_argument('-S', '--scraper', help = 'Scrape pastebin, github, indeed, more to be added. API keys stored in ./api_keys/', action = 'store_true')
	parser.add_argument('-t', '--theharvester', help = 'Invoke theHarvester', action = 'store_true')
	parser.add_argument('-v', '--verbose', help = 'Verbose', action = 'store_true')	
	parser.add_argument('-w', '--whois', help = 'query Whois for supplied -d or -i values. Requires a -d or -i value', action = 'store_true')
		
	args = parser.parse_args()

	#run functions with arguments passed
	runAutosint = Autosint(args)
	runAutosint.clear()
	runAutosint.banner(args)
	runAutosint.checkargs(args)
	runAutosint.report(args)
	
if __name__ == '__main__':

    main()
