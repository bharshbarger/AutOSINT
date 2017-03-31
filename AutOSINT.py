#!/usr/bin/env python

#By @arbitrary_code
#https://github.com/bharshbarger/AutOSINT

#Special thanks to:
#@Beamr
#@tatanus
#unum alces!

#try:

#builtins
import argparse, time, os, sys

#AutOSINT module imports
from modules.whois import Whois
from modules.dnsquery import Dnsquery
from modules.hibp import Haveibeenpwned
from modules.googledork import Googledork
from modules.shodansearch import Shodansearch
from modules.pastebinscrape import Pastebinscrape
from modules.theharvester import Theharvester
from modules.credleaks import Credleaks
from modules.pyfoca import Pyfoca
from modules.webscrape import Scraper

from resources.reportgen import Reportgen
from resources.database import Database

#except ImportError as e:
	#print('Error importing module(s) %s' % e)


class Autosint:

	def __init__(self, args, parser):

		#version
		self.version = 'v2.03.31.17'

		#container for lookup values (domain or ip(ip not working rn))
		self.lookup = []

		#import args and parser objects from argparse
		self.args = args
		self.parser = parser

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
		self.dbDir='./resources/'


	
	def clear(self):

		#clean up screen
	    os.system('cls' if os.name == 'nt' else 'clear')


	def banner(self):
			
		#verbosity flag to print logo and args
		if self.args.verbose is True:print( '''
			    _         _    ___  ____ ___ _   _ _____ 
			   / \  _   _| |_ / _ \/ ___|_ _| \ | |_   _|
			  / _ \| | | | __| | | \___ \| ||  \| | | |  
			 / ___ \ |_| | |_| |_| |___) | || |\  | | |  
			/_/   \_\__,_|\__|\___/|____/___|_| \_| |_|\n''')

		if self.args.verbose is True:print('AutOSINT.py %s, a way to do some automated OSINT tasks\n' % self.version)
		if self.args.verbose is True:print(self.args)

	
	def checkargs(self):

		#check local dirs for reports, apikey and database
		if not os.path.exists(self.reportDir):
			os.makedirs(self.reportDir)

		if not os.path.exists(self.apiKeyDir):
			os.makedirs(self.apiKeyDir)

		if not os.path.exists(self.dbDir):
			os.makedirs(self.dbDir)

		#set True on action store_true args if -a
		if self.args.all is True:
			self.args.creds = True
			self.args.hibp = True
			self.args.foca = True
			self.args.nslookup = True
			self.args.theharvester = True
			self.args.whois = True
			self.args.scraper = True
			self.args.shodan = True
			if self.args.googledork is None:
				print ('[-] You need to provide arguments for google dorking. e.g -g inurl:apsx')
				sys.exit(0)
			if self.args.pastebinsearch is None:
				print ('[-] You need to provide arguments for pastebin keywords. e.g -p password id_rsa')
				sys.exit(0)

			

		#validate entered IP address? do we even care about IP address? i and d do the same shit
		if self.args.ipaddress is not None:
			for a in self.args.ipaddress:
				try:
					socket.inet_aton(a)
				except socket.error:
					print '[-] Invalid IP address entered!' + a
					sys.exit()

		#require at least one argument
		if not (self.args.domain or self.args.ipaddress):
		    print('[-] No OSINT reference provided, add domain(s) with -d or IP address(es) with -i\n')
		    sys.exit()

		#if no queries defined, exit. -a sets all so we're good there
		if (self.args.whois is False and \
			self.args.hibp is False and \
			self.args.nslookup is False and \
			self.args.googledork is None and \
			self.args.shodan is False and \
			self.args.creds is False and \
			self.args.theharvester is False and \
			self.args.scraper is False and \
			self.args.pastebinsearch is None and \
			self.args.foca is False):
			print '[-] No options specified, use -h or --help for a list'
			sys.exit()

		#check to see if an ip or domain name was entered
		if self.args.domain is not None:
			for d in self.args.domain:
				self.lookup = self.args.domain
				for l in self.lookup:
					if not os.path.exists(self.reportDir+'/'+l):
						os.makedirs(self.reportDir+'/'+l)
					
		else:
			for i in self.args.ipaddress:
				self.lookup = self.args.ipaddress
				for l in self.lookup:
					if not os.path.exists(self.reportDir+'/'+l):
						os.makedirs(self.reportDir+'/'+l)

		if self.args.verbose is True:
			print '[+] Lookup Values: '+', '.join(self.lookup)

	def runQueries(self):
		#call function if -w arg
		if self.args.whois is True:

			whoisQuery = Whois()
		
			
			self.whoisResult = whoisQuery.run(self.args, self.lookup, self.reportDir)

		#call function if -n arg
		if self.args.nslookup is True:
			dnsQuery = Dnsquery()
			self.dnsResult = dnsQuery.run(self.args, self.lookup, self.reportDir)

		#call function if -b arg
		if self.args.hibp is True:
			hibpSearch = Haveibeenpwned()
			self.hibpResult = hibpSearch.run(self.args, self.lookup, self.reportDir)

		#call function if -g arg
		if self.args.googledork is not None:
			
			googleDork = Googledork()

			self.googleResult = googleDork.run(self.args, self.lookup, self.reportDir)

		#call function if -s arg
		if self.args.shodan is True:
			
			shodanSearch = Shodansearch()

			self.shodanResult = shodanSearch.run(self.args, self.lookup, self.reportDir, self.apiKeyDir)

		#call function if -p arg
		if self.args.pastebinsearch is not None:
			pastebinScrape = Pastebinscrape()
			self.pasteScrapeResult = pastebinScrape.run(self.args, self.lookup, self.reportDir, self.apiKeyDir)

		# call function if -t arg
		if self.args.theharvester is True:
			theHarvester = Theharvester()
			self.harvesterResult = theHarvester.run(self.args, self.lookup, self.reportDir)

		#call function if -c arg 
		if self.args.creds is True:
			credLeaks = Credleaks()
			self.credResult = credLeaks.run(self.args, self.lookup, self.startTime, self.reportDir)


			#call function if -S arg
		if self.args.scraper is True:
			web_scraper = Scraper()
			self.scrapeResult = self.scrapeResults = web_scraper.run(self.args, self.lookup, self.reportDir, self.apiKeyDir)

		#call function if -f arg
		if self.args.foca is True:
			pyFoca = Pyfoca()
			self.pyfocaResult = pyFoca.run(self.args, self.lookup, self.reportDir)
			

	#run the docx report. text files happen in the respective functions
	def report(self):
		
		self.reportGen = reportGen()
		self.reportGen.run(self.args, self.reportDir, self.lookup, self.whoisResult, self.dnsResult, self.googleResult, self.shodanResult, self.pasteScrapeResult, self.harvesterResult, self.scrapeResult, self.credResult, self.pyfocaResult)

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
	runAutosint = Autosint(args, parser)
	runAutosint.clear()
	runAutosint.banner()
	runAutosint.checkargs()
	runAutosint.runQueries()
	runAutosint.report()
	
if __name__ == '__main__':
    main()
