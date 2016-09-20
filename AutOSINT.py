#!/usr/bin/env python

#By @arbitrary_code

#Special thanks to:
#@Beamr, for helping with general coding expertise
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
# accept cidr input - todo

import sys
import time
import argparse
import subprocess
import dns.resolver
import socket
import urllib2
import shodan
import docx
import re
import os
from google import search

#python-docx: https://pypi.python.org/pypi/python-docx
#shodan: https://github.com/achillean/shodan-python
#google: https://pypi.python.org/pypi/google, also installs beautifulsoup

#*******************************************************************************

def main():
	startTime=time.time()

	print '''
    _         _    ___  ____ ___ _   _ _____ 
   / \  _   _| |_ / _ \/ ___|_ _| \ | |_   _|
  / _ \| | | | __| | | \___ \| ||  \| | | |  
 / ___ \ |_| | |_| |_| |___) | || |\  | | |  
/_/   \_\__,_|\__|\___/|____/___|_| \_| |_|\n'''

	print 'AutOSINT.py v0.1, a way to do some automated OSINT tasks\n'


	#parse input, nargs allows one or more to be entered
	#https://docs.python.org/3/library/argparse.html
	parser = argparse.ArgumentParser()
	parser.add_argument('-d', '--domain', nargs = '+', help = 'the Domain(s) you want to search.')
	parser.add_argument('-i', '--ipaddress', nargs = '+', help = 'the IP address(es) you want to search. Must be a valid IP. ')
	parser.add_argument('-a', '--all', help = 'run All queries', action = 'store_true')
	parser.add_argument('-w', '--whois', help = 'query Whois for supplied -d or -i values. Requires a -d or -i value', action = 'store_true')
	parser.add_argument('-n', '--nslookup',help = 'Name query DNS for supplied -d or -i values. Requires a -d or -i value', action = 'store_true')
	parser.add_argument('-g', '--googledork', nargs = '+', help = 'query Google for supplied args that are treated as a dork. i.e. -g password becomes a search for "password site:<domain>"')
	parser.add_argument('-s', '--shodan', nargs = 1, help = 'query Shodan, optionally provide -s <apikey>')
	parser.add_argument('-v', '--verbose', help = 'Verbose', action = 'store_true')
	parser.add_argument('-p', '--pastebinsearch', nargs = '+', help = 'Search google for <arg> site:pastebin.com. Requires a pro account if you dont want to get blacklisted')
	parser.add_argument('-t', '--theharvester', help = 'Invoke theHarvester', action = 'store_true')
	parser.add_argument('-c', '--creds', help = 'Search local copies of credential dumps', action = 'store_true')
	parser.add_argument('-f', '--foca', help = 'invoke pyfoca', action = 'store_true')
	args = parser.parse_args()
	
	if args.verbose is True:
		print args

	#set all if -a
	if args.all is True:
		args.whois = True
		args.nslookup = True
		args.shodan = True
		args.theharvester = True
		args.creds = True


	#validate entered IP address? do we even care? i and d do the same shit
	if args.ipaddress is not None:
		for a in args.ipaddress:
			try:
				socket.inet_aton(a)
			except socket.error:
				print '[-] Invalid IP entered!' + a
				sys.exit(1)

	#require at least one argument
	if not (args.domain or args.ipaddress):
	    parser.error('No action requested, add domain(s) or IP address(es)\n')

	#if no queries defined, exit
	if (args.whois is False and \
		args.nslookup is False and \
		args.googledork is None and \
		args.shodan is None and \
		args.creds is False and \
		args.pastebinsearch is None):
		print '[-] No options specified, use -h or --help for a list'
		sys.exit(1)

	#check to see if an ip or domain name was entered
	if args.domain is not None:
		for d in args.domain:
			lookup = args.domain
	else:
		for i in args.ipaddress:
			lookup = args.ipaddress

	if args.verbose is True:
		print "lookup value is "+ str(lookup)




	#call functions
	whois_search(args, lookup)
	dns_search(args, lookup)
	google_search(args, lookup)
	shodan_search(args, lookup)
	pastebin_search(args, lookup)
	the_harvester(args, lookup)
	credential_leaks(args, lookup, startTime)
	#write_report(args, googleResultWrite, whoisResultWrite, dnsResultWrite, shodanResultWrite)

#*******************************************************************************
#queries whois of ip or domain set in lookup, dumps to stdout if -v is set, writes to file either way
def whois_search(args, lookup):

	#invoke if option set
	if args.whois is True:

		#init results list
		whoisResult = []

		#iterate the index and values of the lookup list
		for i, l in enumerate(lookup):
			print '[+] Performing whois query ' + str(i + 1) + ' for ' + l
			
			whoisFile=open(''.join(l)+'_whois.txt','w')

			#subprocess open the whois command for current value of "l" in lookup list. 
			#split into newlines instead of commas
			whoisCmd = subprocess.Popen(['whois',l], stdout = subprocess.PIPE).communicate()[0].split('\n')

			#append lists together
			whoisResult.append(whoisCmd)

			#write the file
			for r in whoisResult:
				whoisFile.writelines('\n'.join(r))
			
			#verbosity logic
			if args.verbose is True:
				for w in whoisResult: print '\n'.join(w)

		return whoisResult
#*******************************************************************************
def dns_search(args, lookup):
	#DNS query, dumps out a list
	
		#invoke if option set
		if args.nslookup is True:
			
			#init results list
			dnsResult = []
			
			#iterate the index and values of the lookup list
			for i, l in enumerate(lookup):
				print '[+] Performing DNS query #'+ str(i + 1) + ' using "host -a " ' + l
				dnsFile=open(''.join(l)+'_dns.txt','a')
				#subprocess to run host -a on the current value of l in the loop, split into newlines
				dnsCmd = subprocess.Popen(['host', '-a', str(l)], stdout = subprocess.PIPE).communicate()[0].split('\n')

				#append lists together
				dnsResult.append(dnsCmd)

				for r in dnsResult:
					dnsFile.writelines('\n'.join(r))

				#print dnsResult if -v
				if args.verbose is True:
					for d in dnsResult: print '\n'.join(d)

			#return list object
			return dnsResult

#*******************************************************************************
# this could be GREATLY improved.
# pass google dorks as args for now
# GHDB password dorks https://www.exploit-db.com/google-hacking-database/9/
# GHDB sensitive dirs https://www.exploit-db.com/google-hacking-database/3/
# uses this awesome module https://pypi.python.org/pypi/google
# requires beautifulsoup

def google_search(args, lookup):

	# check for empty args
	if args.googledork is not None:

		#because i fail at logic
		if args.googledork is None:
			print '[-] No Google dork(s) defined! Set with -g <dork(s)> Skipping!!!'
			return

		for d in args.googledork:
			

			#init list
			googleResult = []

			#iterate the lookup list
			for i, l in enumerate(lookup):
				googleFile=open(''.join(l)+'_google_dork.txt','w')

				#show user whiat is being searched
				print '[+] Google query ' + str(i + 1) + ' for " '+str(d)+' ' + 'site:'+str(l) + ' "'
				
				try:
					#iterate url results from search of password(for now) and site:current list value
					for url in search(str(d)+ ' ' + 'site:'+str(l), stop = 20):
						
						#append results together
						googleResult.append(url)

						#rate limit to 1 per second
						time.sleep(1)
				#catch exceptions
				except Exception:
					pass

			for r in googleResult:
				googleFile.writelines(r + '\r\n')

			#verbosity flag
			if args.verbose is True:
				for r in googleResult: print ''.join(r)
					
			#return results list
			return googleResult
	
		

#*******************************************************************************
def shodan_search(args, lookup):
	#probably need to customize search type based on -i or -d		
	#first if  https://shodan.readthedocs.io/en/latest/tutorial.html#connect-to-the-api
	#else https://shodan.readthedocs.io/en/latest/tutorial.html#looking-up-a-host

	#variable for api key fed from args
	 

	# If theres an api key via -s
	if args.shodan is not None:

		shodanApiKey = args.shodan
		
		#list that we'll return
		shodanResult = []
	
		#invoke api with api key provided
		shodanApi = shodan.Shodan(shodanApiKey)

		#open output file
		shodanFile=open(''.join(lookup)+'_shodan.txt','w')
		
		#roll through the lookup list from -i or -d
		for i, l in enumerate(lookup):
			#user notification that something is happening
			print '[+] Querying Shodan via API search for ' + l
			try:
				#set results to api search of current lookup value
				results = shodanApi.search(l)
				#for each result
				for result in results['matches']:
					#append to shodanResult list
					shodanResult.append(str(results))
			#catch exceptions		
			except shodan.APIError, e:
				#print excepted error
				print '[-] Shodan Error: %s' % e + ' Skipping!!!'
				print '[!] You may need to specify an API key with -s <api key>'
				return
				
		#verbosity logic
		if args.verbose is True:
			print 'Results found: %s' % results['total']
			print 'IP: %s' % result['ip_str']
			print result['data']

		#write contents of shodanResult list. this needs formatted
		shodanFile.writelines('%s' % results['total'])
		for r in shodanResult:
			shodanFile.writelines('%s' % result['ip_str'])
			shodanFile.writelines('\n')
			shodanFile.writelines(result['data'])
			shodanFile.writelines('****************\n')

		return shodanResult
	
#*******************************************************************************
#right now this just google dorks a supplied arg for site:pastebin.com
#need to implement scraping api http://pastebin.com/api_scraping_faq
#scraping url is here http://pastebin.com/api_scraping.php
def pastebin_search(args, lookup):
	
	# check for empty args
	if args.pastebinsearch is not None:
		print '[!] requires a Pastebin Pro account for IP whitelisting'

		if args.pastebinsearch is None:
			print '[-] No pastebin search string provided. Skipping! Provide with -p <search items>'
			return

		for a in args.pastebinsearch:
			#init lists
			scrapeResult = []
			scrapeContent = []

			#iterate the lookup list
			for i, l in enumerate(lookup):

				scrapedFile=open(''.join(l)+'_pastebin_content.txt','w')
				pasteUrlFile=open(''.join(l)+'_pastebin_urls.txt','w')
				#show user whiat is being searched
				print 'Google query #' + str(i + 1) + ' for '+  str(a) +' '+ str(l) + ' site:pastebin.com'
				
				try:
					#iterate url results from search of dork arg and supplied lookup value against pastebin
					for url in search(str(a) +' '+ str(l) + ' site:pastebin.com', stop = 20):
						#time.sleep(1)

						#append results together
						scrapeResult.append(url)
						
						time.sleep(1)
						print url()
				except Exception:
					pass

				for r in scrapeResult:
					try:
						req = urllib2.Request(r)
						print 'Opening ' + r
						scrapeContent = urllib2.urlopen(req).read()
						time.sleep(1)
						#scrapeContent.append()
						print scrapeContent
						
					except Exception:
						pass
				
				
				for y in scrapeResult:
					scrapedFile.writelines(scrapeContent)

				for z in scrapeContent:
					pasteUrlFile.writelines(scrapeResult)
				

		#verbosity flag
		'''if args.verbose is True:
			for r in scrapeResult: print ''.join(r)
			for c in scrapeContent: print ' '.join(c)'''

		#return results list
		return scrapeResult
		return scrapeContent

	

		

#*******************************************************************************
def the_harvester(args, lookup):

	#https://github.com/laramies/theHarvester
	if args.theharvester is True:
		print '[+] Running theHarvester against google and linkedin'
		#init lists
		harvested = []
		harvesterGoogleResult = []
		harvesterLinkedinResult = []

		#based on domain or ip, enumerate with index and value
		for i, l in enumerate(lookup):

			#open file to write to
			harvesterFile=open(''.join(l)+'_theharvester.txt','w')

			#run harvester with -b google on lookup
			harvesterGoogleCmd = subprocess.Popen(['./theharvester', '-b', 'google', '-d', str(l)], stdout = subprocess.PIPE).communicate()[0].split('\r\n')

			#run harvester with -b linkedin on lookup
			harvesterLinkedinCmd = subprocess.Popen(['./theharvester', '-b', 'linkedin', '-d', str(l)], stdout = subprocess.PIPE).communicate()[0].split('\r\n')

			#append lists together
			harvesterGoogleResult.append(harvesterGoogleCmd)
			harvesterLinkedinResult.append(harvesterLinkedinCmd)

			#append resutls and write to lookup result file
			for r in harvesterGoogleResult:
				harvesterFile.writelines(r)

			for j in harvesterLinkedinResult:
				harvesterFile.writelines(j)
				
		#verbosity
		if args.verbose is True:
			for g in harvesterGoogleResult: print '\n'.join(g)
			for i in harvesterLinkedinResult: print '\n'.join(i)

			#return list object
			return harvesterGoogleResult
			return harvesterLinkedinResult



#*******************************************************************************
def credential_leaks(args, lookup, startTime):
	#grep through local copies of various password database dumps. 
	#compares to a hashcat potfile as well
	#you'll need a ./credleaks directory and a ./potfile directory populated
	#dumps need to be in uname:hash format
	#this could probably stand to be multi threaded

	potfileDir = './potfile'
	credLeakDir = './credleaks'

	if args.creds is True:

		if not os.path.exists(potfileDir):
			print '[-] The potfile directory is missing. Symlink your location to ./potfile and see if that works'
			return
		

		if not os.path.exists(credLeakDir):
			print '[-] The credleaks directory is missing. Symlink your location to ./credleaks and see if that works'
			return


	
		#for each domain/ip provided
		for l in lookup:
			credFile=open(''.join(l)+'_creds.txt','w')

			#init dictionary
			dumpDict={}

			#overall, take the lookup value (preferably a domain) and search the dumps for it
			#for each file in ./credleaks directory
			for credFileName in os.listdir('./credleaks/'):
				#open the file
				credFileOpen = open('./credleaks/'+credFileName, "r")
				j=0
				i=0
				#for each line in opened file
				for line in credFileOpen:
					i=i+1
					#regex search for our current lookup value l
					if re.search((str(l)), line):
						j=j+1
						#look for a colon delimiter
						if ':' in line:
							#split matches based on colons, like awk -F :. emails shouldnt have colons, right?
							#also the dat HAS to require colons otherwise it will return an index error
							matchedLine=line.split(":")
							#take the split parts, 0 and 1 that are uname and hash, respectively
							#place into a dict and strip the \r\n off of them
							dumpDict[str(matchedLine[1].rstrip("\r\n"))]=str(matchedLine[0].rstrip("\r\n"))
						else:
							dumpDict['xxx']=str(line.rstrip("\r\n"))
				if args.verbose is True: 
					print '[i] Searched ' + str(credFileName)+' and found '+ str(j)

			
			#if args.verbose is True:	
			#print dumpDict contents
			if args.verbose is True:
				for h, u in dumpDict.items():
					print(str(h), str(u)) 
			print '[+] Searching Local Credential Dumps in ./credleaks against potfile in ./potfile '+l
			credFile.writelines('********EMAILS FOUND BELOW********\n\n\n\n')
			for h, u in dumpDict.items():
				credFile.writelines(str(u)+'\n')
				
			credFile.writelines('********CREDENTIALS FOUND BELOW*********\n\n\n\n')
			
			#still in our lookup value iterate potfiles directory
			for potFileName in os.listdir('./potfile/'):
				#open a pot file
				with open('./potfile/'+potFileName, 'r') as potFile:
					#then look at every line
					print '[!] Any creds you have in your potfile will appear below as user:hash:plain : '
					for potLine in potFile:
						#then for every line look at every hash and user in the dict
						for h, u in dumpDict.items():
							#if the hash in the dict matches a line in the potfile
							#that is the same length as the original hash
							if str(h) == str(potLine[0:len(h)]):
								#print the hash
								print str(u)+':'+str(potLine.rstrip("\r\n"))
								#need to append the output to a variable to return or write to the file
								credFile.writelines(str(u)+':'+str(potLine[len(h):]))

#*******************************************************************************
def pyfoca():
	if args.whois is True:
		print "foca"
#*******************************************************************************
	

#*******************************************************************************

def write_report(args, googleResultWrite, whoisResultWrite, dnsResultWrite, shodanResultWrite):
	
	google = "No Google Results"


	if whoisResultWrite is not None:
		for w in whoisResultWrite: whois = (''.join(w))
	else:
		whois = "No Whois results"
		
	if googleResultWrite is not None:
		for r in googleResultWrite: google=(''.join(r))
	
			
	
	if dnsResultWrite is not None:
		for d in dnsResultWrite: dns = (''.join(d))
	else:
		dns = "no DNS results"



	print 'Writing results of your query options for to a .docx into the current directory'
	#dump to a word doc
	doc = docx.Document()
	doc.add_paragraph('Sample Output')
	doc.add_paragraph('Google search for the word password')
	doc.add_paragraph(str(google))

	doc.add_paragraph('Whois Results')
	doc.add_paragraph(str(whois))

	doc.add_paragraph('DNS Lookup Results')
	doc.add_paragraph(str(dns))

	doc.add_paragraph('Shodan query results')
	doc.add_paragraph(shodanResultWrite)
	doc.save('OSINT.docx')


if __name__ == '__main__':
    main()
