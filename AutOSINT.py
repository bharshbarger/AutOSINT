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


#todo
#reporting dorks, keys, training, get foca working

import sys
import time
import argparse
import subprocess
#import dns.resolver
import socket
import urllib2
import shodan
import docx
from docx.shared import Pt
import re
import os
from google import search

#python-docx: https://pypi.python.org/pypi/python-docx
#shodan: https://github.com/achillean/shodan-python
#google: https://pypi.python.org/pypi/google, also installs beautifulsoup

#*******************************************************************************

def main():
	startTime=time.time()

	#parse input, nargs allows one or more to be entered
	#https://docs.python.org/3/library/argparse.html
	parser = argparse.ArgumentParser()
	parser.add_argument('-a', '--all', help = 'run All queries', action = 'store_true')
	parser.add_argument('-c', '--creds', help = 'Search local copies of credential dumps', action = 'store_true')
	parser.add_argument('-d', '--domain', nargs = '+', help = 'the Domain(s) you want to search.')
	parser.add_argument('-f', '--foca', help = 'invoke pyfoca', action = 'store_true')
	parser.add_argument('-g', '--googledork', nargs = '+',help = 'query Google for supplied args that are treated as a dork. i.e. -g password becomes a search for "password site:<domain>" no option defaults to "password"')
	parser.add_argument('-i', '--ipaddress', nargs = '+', help = 'the IP address(es) you want to search. Must be a valid IP. ')
	parser.add_argument('-n', '--nslookup',help = 'Name query DNS for supplied -d or -i values. Requires a -d or -i value', action = 'store_true')
	parser.add_argument('-p', '--pastebinsearch', nargs = '+', help = 'Search google for <arg> site:pastebin.com. Requires a pro account if you dont want to get blacklisted.')
	parser.add_argument('-s', '--shodan', nargs = 1, help = 'query Shodan, optionally provide -s <apikey>')
	parser.add_argument('-S', '--scraper', nargs = '+', help = 'Scrape pastebin, github, indeed, more to be added. Args are scrape keywords if applicable')
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

	if args.verbose is True:print 'AutOSINT.py v0.1, a way to do some automated OSINT tasks\n'
	if args.verbose is True:print args



	#set True on action store_true args if -a
	if args.all is True:
		args.creds = True
		args.foca = True
		args.nslookup = True
		args.theharvester = True
		args.whois = True

	#validate entered IP address? do we even care about IP address? i and d do the same shit
	if args.ipaddress is not None:
		for a in args.ipaddress:
			try:
				socket.inet_aton(a)
			except socket.error:
				print '[-] Invalid IP entered!' + a
				sys.exit()

	#require at least one argument
	if not (args.domain or args.ipaddress):
	    parser.error('No OSINT reference provided, add domain(s) or IP address(es)\n')
	    sys.exit()

	#if no queries defined, exit
	if (args.whois is False and \
		args.nslookup is False and \
		args.googledork is None and \
		args.shodan is None and \
		args.creds is False and \
		args.scraper is None and \
		args.theharvester is False and \
		args.pastebinsearch is None):
		print '[-] No options specified, use -h or --help for a list'
		sys.exit()

	#check to see if an ip or domain name was entered
	if args.domain is not None:
		for d in args.domain:
			lookup = args.domain
			for l in lookup:
				reportDir='./reports/'+l+'/'
				#check directories
				if not os.path.exists(reportDir):
					os.makedirs(reportDir)
	else:
		for i in args.ipaddress:
			lookup = args.ipaddress
			for l in lookup:
					reportDir='./reports/'+l+'/'
					#check directories
					if not os.path.exists(reportDir):
						os.makedirs(reportDir)

	if args.verbose is True:
		print "lookup value is "+ str(lookup)

	#init results lists
	
	whoisResult =[]
	dnsResult = []
	googleResult =[]
	shodanResult = []
	pasteScrapeResult = []
	pasteScrapeContent = []
	harvesterResult =[]


	#call function if -w arg
	if args.whois is True:
		whoisResult = whois_search(args, lookup, reportDir)
	
	#call function if -n arg
	if args.nslookup is True:
		dnsResult = dns_search(args, lookup, reportDir)
	
	#call function if -g arg
	if args.googledork is not None:
		googleResult=google_search(args, lookup, reportDir)

	#call function if -s arg
	if args.shodan is not None:
		shodan_search(args, lookup, reportDir)
	
	#call function if -p arg
	if args.pastebinsearch is not None:
		pastebin_search(args, lookup, reportDir)
	
	# call function if -t arg
	if args.theharvester is True:
		harvesterResult=the_harvester(args, lookup, reportDir)
	
	#call function if -c arg 
	if args.creds is True:
		credential_leaks(args, lookup, startTime, reportDir)
	
	#call function if -S arg
	if args.scraper is not None:
		scrape_sites(args, lookup, reportDir)

	#always run the report
	write_report(args, reportDir, lookup, whoisResult, dnsResult, googleResult, shodanResult, pasteScrapeResult, pasteScrapeContent, harvesterResult)


#*******************************************************************************
#hibp api search to implement
#https://haveibeenpwned.com/API/v2
def hibp_search(args, lookup, reportDir):
	print 'coming soon'
#*******************************************************************************
def scrape_sites(args, lookup, reportDir):

	for i,l in enumerate(lookup):

		print '[+] Scraping sites using '+ l

		scrapeFile=open(reportDir+''.join(l)+'_scrape.html', 'w')

		for a in args.scraper:

			#init list and insert domain with tld stripped
			#insert lookup value into static urls
			scrapeUrls =['http://www.indeed.com/cmp/%s/jobs?q=%s' % (l.split('.')[0], a),\
			'https://github.com/search?q=%s&type=Code&ref=searchresults' % (l.split('.')[0]),\
			'https://www.glassdoor.com/Reviews/company-reviews.htm?suggestCount=0&suggestChosen=false&clickSource=searchBtn&typedKeyword=%s&sc.keyword=%s&locT=&locId=' % (l.split('.')[0],l.split('.')[0]), \
			'http://www.slideshare.net/%s' % (l.split('.')[0])]

			for url in scrapeUrls:
				if args.verbose is True:print '[+] Grabbing '+url
				try:
					req = urllib2.Request(url)
					print 'Opening ' + url
					scrapeContent = urllib2.urlopen(req).read()
					time.sleep(1)
					#scrapeContent.append()
					scrapeFile.writelines(scrapeContent)
					
				except Exception:
					pass
			return scrapeResult


#*******************************************************************************
#queries whois of ip or domain set in lookup, dumps to stdout if -v is set, writes to txt file either way.
#returns whoisResult for use in report
def whois_search(args, lookup, reportDir):

	whoisResult=[]

	#iterate the index and values of the lookup list
	for i, l in enumerate(lookup):
		print '[+] Performing whois query ' + str(i + 1) + ' for ' + l
		
		whoisFile=open(reportDir+''.join(l)+'_whois.txt','w')

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
#DNS query, dumps out a list
#retruns dnsResult for use in report

def dns_search(args, lookup, reportDir):
	
	dnsResult=[]

	#iterate the index and values of the lookup list
	for i, l in enumerate(lookup):
		print '[+] Performing DNS query '+ str(i + 1) + ' using "host -a  ' + l+'"'
		dnsFile=open(reportDir+''.join(l)+'_dns.txt','a')
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

def google_search(args, lookup, reportDir):
	#need a default dork list

	#C58EA28C-18C0-4a97-9AF2-036E93DDAFB3 is string for open OWA attachments
	# check for empty args
	#init lists
	googleResult = []

	for d in args.googledork:
		
		#iterate the lookup list
		for i, l in enumerate(lookup):
			googleFile=open(reportDir+''.join(l)+'_google_dork_'+d+'.txt','w')

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
		#iterate results
		for r in googleResult:
			#write results on newlines
			googleFile.writelines(r + '\r\n')

		#verbosity flag
		if args.verbose is True:
			for r in googleResult: print ''.join(r)
				
		#return results list
		return googleResult
	
		

#*******************************************************************************
def shodan_search(args, lookup, reportDir):
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
		shodanFile=open(reportDir+''.join(lookup)+'_shodan.txt','w')
		
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
		#add iterator to dump all results
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
def pastebin_search(args, lookup, reportDir):
	
	# check for empty args
	if args.pastebinsearch is not None:
		print '[!] requires a Pastebin Pro account for IP whitelisting'

		pasteScrapeResult = []
		pasteScrapeContent = []

		if args.pastebinsearch is None:
			print '[-] No pastebin search string provided. Skipping! Provide with -p <search items>'
			return

		for a in args.pastebinsearch:
			#init lists
			scrapeResult = []
			scrapeContent = []

			#iterate the lookup list
			for i, l in enumerate(lookup):

				scrapedFile=open(reportDir+''.join(l)+'_pastebin_content.txt','w')
				pasteUrlFile=open(reportDir+''.join(l)+'_pastebin_urls.txt','w')
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
		return pasteScrapeResult
		return pasteScrapeContent

	

		

#*******************************************************************************
def the_harvester(args, lookup, reportDir):

	#https://github.com/laramies/theHarvester
	if args.theharvester is True:
		
		#init lists
		harvested = []
		harvesterGoogleResult = []
		harvesterLinkedinResult = []
		harvesterResult=[]

		#based on domain or ip, enumerate with index and value
		for i, l in enumerate(lookup):

			#open file to write to
			harvesterFile=open(reportDir+''.join(l)+'_theharvester.txt','w')

			#run harvester with -b google on lookup
			print '[+] Running theHarvester -b google -d %s against google' % l
			harvesterGoogleCmd = subprocess.Popen(['theharvester', '-b', 'google', '-d', str(l)], stdout = subprocess.PIPE).communicate()[0].split('\r\n')

			#run harvester with -b linkedin on lookup
			print '[+] Running theHarvester -b linkedin -d %s against linkedin' % l
			harvesterLinkedinCmd = subprocess.Popen(['theharvester', '-b', 'linkedin', '-d', str(l)], stdout = subprocess.PIPE).communicate()[0].split('\r\n')

			#append lists together
			harvesterResult.append(harvesterGoogleCmd)
			harvesterResult.append(harvesterLinkedinCmd)

			#append resutls and write to lookup result file
			for r in harvesterResult:
				harvesterFile.writelines(r)

				
		#verbosity
		if args.verbose is True:
			for h in harvesterResult: print '\n'.join(h)


		#return list object
		return harvesterResult




#*******************************************************************************
def credential_leaks(args, lookup, startTime, reportDir):
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
			credFile=open(reportDir+''.join(l)+'_creds.txt','w')

			#init dictionary
			dumpDict={}
			credReportUsers=[]
			credReportPass=[]

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
				credReportUsers.append(str(u)+'\n')
				
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
								credReportPass.append(str(u)+':'+str(potLine[len(h):]))

			return credReportUsers
			return credReportPass

#*******************************************************************************
def pyfoca(args, lookup, reportDir):
	if args.whois is True:
		print "foca"
#*******************************************************************************
#viewdns.info
#http://viewdns.info/api/
#*******************************************************************************
#he bgp info
#http://bgp.he.net/dns/rapid7.com#_ipinfo
#*******************************************************************************
#active osint:
#zone transfer
#ike endpoints
#http screnshots
#*******************************************************************************
#*******************************************************************************

def write_report(args, reportDir, lookup, whoisResult, dnsResult, googleResult, shodanResult, pasteScrapeResult, pasteScrapeContent, harvesterResult):

	for l in lookup:

		whois=None
		dns=None
		shodan=None
		pasteUrl=None
		pasteContent=None
		harvestG=None
		harvestL=None


		if whoisResult is not None:
			for w in whoisResult: whois = ('\n'.join(w))
		else:
			whois = "No Whois results"

		if dnsResult is not None:
			for d in dnsResult: dns = ('\n'.join(d))
		else:
			dns = 'No DNS results'

		if shodanResult is not None:
			for s in shodanResult: shodan = (''.join(s))
		else:
			shodan = 'No shodan results'


		if pasteScrapeResult is not None:
			for psr in pasteScrapeResult: pasteUrl = (''.join(psr))
		else:
			pasteUrl = 'No pastebin urls found'

		if pasteScrapeContent is not None:
			for psc in pasteScrapeContent: pasteContent = (''.join(psc))
		else:
			pasteContent = 'No pastebin content found'

		



		#dump to a word doc
		#refs
		#https://python-docx.readthedocs.io/en/latest/user/text.html
		#https://python-docx.readthedocs.io/en/latest/user/quickstart.html
		
		#create a document 
		document = docx.Document()

		#need font stuff here?

		#add boilerplate header
		document.add_heading('Open Source Intelligence Report for %s' % l, level=2)
		
		#add boilerplate intro 
		document.add_paragraph('This document contains data obtained by programatically quering various free or low cost Internet data sources')
		document.add_paragraph('These data include information about the network, technology, and people associated with the targets')
		
		#break
		document.add_page_break()
		

		#add whois data with header and break after end
		document.add_heading('Whois Data for %s' % l , level=3)
		paragraph = document.add_paragraph()
		runParagraph = paragraph.add_run(whois)
		#set font stuff
		font=runParagraph.font
		font.name = 'Arial'
		font.size = Pt(10)
		document.add_page_break()
		
		#add dns data with header and break after end
		document.add_heading('Domain Name System Data for %s' % l, level=3)
		paragraph = document.add_paragraph()
		runParagraph = paragraph.add_run(dns)
		#set font stuff
		font=runParagraph.font
		font.name = 'Arial'
		font.size = Pt(10)
		document.add_page_break()

		#dork output
		document.add_heading('Google Dork Results for %s' % l, level=3)
		paragraph = document.add_paragraph()
		for r in googleResult:
			runParagraph = paragraph.add_run(''.join(r))
		#set font stuff
		font=runParagraph.font
		font.name = 'Arial'
		font.size = Pt(10)
		document.add_page_break()
		
		#harvester output
		document.add_heading('theHarvester Results for %s' % l, level=3)
		paragraph = document.add_paragraph()
		for h in harvesterResult: 
			runParagraph = paragraph.add_run(''.join(h))
		#set font stuff
		font=runParagraph.font
		font.name = 'Arial'
		font.size = Pt(10)


		document.add_paragraph(shodan)
		document.add_page_break()
		

		document.add_paragraph(pasteUrl)
		document.add_page_break()
		

		document.add_paragraph(pasteContent)
		document.add_page_break()


		print '[+] Writing file OSINT_%s_.docx in ./reports/%s'  % (l, l)
		document.save(reportDir+'OSINT_%s_.docx' % l)


if __name__ == '__main__':
    main()
