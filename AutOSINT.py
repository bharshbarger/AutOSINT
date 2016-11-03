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
# google dorks via googlesearch.
# BGP info - todo
# AS info - todo
# linkedin (from Nick)
# read pw/keys from github
# accept cidr input - todo

#bugs
#need newlines on google output in docx report
#setting default  of 'password in argparse not liking default=['password']'


#todo
#reporting dorks, keys, training, get foca working

import sys
import time
import argparse
import subprocess
import socket
import urllib2
import shodan
import docx
from docx.shared import Pt
from docx.shared import RGBColor
import re
import os
from google import search
import json
from lxml import html
import requests
from collections import Counter


#python-docx: https://pypi.python.org/pypi/python-docx
#shodan: https://github.com/achillean/shodan-python
#google: https://pypi.python.org/pypi/google, also installs beautifulsoup

#*******************************************************************************

def main():
	startTime=time.time()

	#parse input, nargs allows one or more to be entered
	#https://docs.python.org/3/library/argparse.html
	#set nargs back to + for multi search of domain or ip (still really buggy)
	parser = argparse.ArgumentParser()
	parser.add_argument('-a', '--all', help = 'run All queries', action = 'store_true')
	parser.add_argument('-c', '--creds', help = 'Search local copies of credential dumps', action = 'store_true')
	parser.add_argument('-d', '--domain', nargs = 1, help = 'the Domain you want to search.')
	parser.add_argument('-f', '--foca', help = 'invoke pyfoca', action = 'store_true')
	parser.add_argument('-g', '--googledork', nargs = '*',help = 'query Google for supplied args that are treated as a dork. i.e. -g password becomes a search for "password site:<domain>"')
	parser.add_argument('-i', '--ipaddress', nargs = 1, help = 'the IP address you want to search. Must be a valid IP. ')
	parser.add_argument('-n', '--nslookup',help = 'Name query DNS for supplied -d or -i values. Requires a -d or -i value', action = 'store_true')
	parser.add_argument('-p', '--pastebinsearch', nargs = '+', help = 'Search google for <arg> site:pastebin.com. Requires a pro account if you dont want to get blacklisted.')
	parser.add_argument('-s', '--shodan', nargs = 1, help = 'query Shodan, optionally provide -s <apikey>')
	parser.add_argument('-S', '--scraper', nargs = '+', help = 'Scrape pastebin, github, indeed, more to be added. Args are scrape keywords if applicable. Doesnt really work well right now')
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
				print '[-] Invalid IP address entered!' + a
				sys.exit()

	#require at least one argument
	if not (args.domain or args.ipaddress):
	    parser.error('[-] No OSINT reference provided, add domain(s) with -d or IP address(es) with -i\n')
	    sys.exit()

	#if no queries defined, exit. -a sets all so we're good there
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
		print "[+] Lookup value(s): "+ str(lookup)

	#init results lists
	
	whoisResult=[]
	dnsResult = []
	googleResult =[]
	shodanResult=[]
	pasteScrapeResult = []
	pasteScrapeContent = []
	harvesterResult =[]
	scrapeResult=[]
	credResult=[]

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
		shodanResult = shodan_search(args, lookup, reportDir)
	
	#call function if -p arg
	if args.pastebinsearch is not None:
		pasteScrapeResult=pastebin_search(args, lookup, reportDir)
	
	# call function if -t arg
	if args.theharvester is True:
		harvesterResult=the_harvester(args, lookup, reportDir)
	
	#call function if -c arg 
	if args.creds is True:
		credResult=credential_leaks(args, lookup, startTime, reportDir)
	
	#call function if -S arg
	if args.scraper is not None:
		scrapeResult=scrape_sites(args, lookup, reportDir)


	#run the docx report. text files happen in the respective functions
	write_report(args, reportDir, lookup, whoisResult, dnsResult, googleResult, shodanResult, pasteScrapeResult, harvesterResult, scrapeResult, credResult)


#*******************************************************************************
#hibp api search to implement
#https://haveibeenpwned.com/API/v2
def hibp_search(args, lookup, reportDir):
	print 'coming soon'
#*******************************************************************************
#ssl scan 
#*******************************************************************************
#censys
#https://www.censys.io/ipv4?q=rapid7.com
#*******************************************************************************
#virustotal passive dns api
#https://www.virustotal.com/en/documentation/public-api/#getting-domain-reports
#*******************************************************************************
#https://dnsdumpster.com/
#cool mapping of AS, etc
#*******************************************************************************
#passive dns

#*******************************************************************************
#viewdns.info
#http://viewdns.info/api/
#*******************************************************************************
#he bgp info
#http://bgp.he.net/dns/rapid7.com#_ipinfo
#*******************************************************************************
#active osint:
#zone transfer host -a does this?
#ike endpoints
#http screnshots

#*******************************************************************************
#generic site scraper (well, mainly an interface to available search APIs) 
#that uses fixed set of sites defined in scrapeUrls dictionary to look for 
#various things like job postings and user supplied keywords where applicable
def scrape_sites(args, lookup, reportDir):
	scrapeResult=[]
	userAgent = {'User-agent': 'Mozilla/5.0'}


	for i,l in enumerate(lookup):
		scrapeFile=open(reportDir+''.join(l)+'_scrape.txt','w')

		print '[+] Scraping sites using '+ l

		for a in args.scraper:

			#init list and insert domain with tld stripped
			#insert lookup value into static urls
			scrapeUrls = {\
			'indeed':'http://www.indeed.com/cmp/%s/jobs?q=%s' % (l.split('.')[0], a),\
			'github':'https://api.github.com/search/repositories?q=%s&sort=stars&order=desc' % (l.split('.')[0]),#pull off the tld\
			#'glassdoor':'https://www.glassdoor.com/Reviews/company-reviews.htm?suggestCount=0&suggestChosen=false&clickSource=searchBtn&typedKeyword=%s&sc.keyword=%s&locT=&locId=' % (l.split('.')[0],l.split('.')[0]),\
			#'slideshare':'http://www.slideshare.net/%s' % (l.split('.')[0]),\
			#'':'',\
			#'':''\
			}

			for name,url in scrapeUrls.items():
				if args.verbose is True:print '[+] Scraping '+ name
				#http://docs.python-guide.org/en/latest/scenarios/scrape/
				try:
					page = requests.get(url, headers = userAgent)
				except:
					print '[-] Scraping error on ' + url +':'
					pass

				#build html tree
				tree = html.fromstring(page.content)
				
				#indeed matches jobs. yeah yeah it doesnt use their api yet
				if name is 'indeed':
					jobCount = tree.xpath('//span[@class="cmp-jobs-count-number"]/text()')
					print '[+] '+str(''.join(jobCount)) + ' jobs posted on indeed'
					jobTitle = tree.xpath('//a[@class="cmp-job-url"]/text()')
					for t in jobTitle:
						scrapeResult.append(t+'\n')


				#github matches search for user supplied domain
				#https://developer.github.com/v3/search/
				#http://docs.python-guide.org/en/latest/scenarios/json/
				if name is 'github':
					gitJson = json.loads(page.text)
					#grab repo name
					for c,i in enumerate(gitJson['items']):
						scrapeResult.append(i['full_name']+'\n')
					print '[+] Found '+str(c+1)+' repositories matching '+ (l.split('.')[0])


					
			#write the file
			for s in scrapeResult:
				scrapeFile.writelines(''.join(str(s.encode('utf8'))))
				
			#verbosity logic
			if args.verbose is True:
				for r in scrapeResult: print ''.join(r.strip('\n'))
			

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
		try:
			whoisCmd = subprocess.Popen(['whois',l], stdout = subprocess.PIPE).communicate()[0].split('\n')
		except:
			print '[-] Error running whois command'
			whoisResult.append('Error running whois command')
			pass
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
		print '[+] Performing DNS query '+ str(i + 1) + ' using "host -a ' + l+'"'
		dnsFile=open(reportDir+''.join(l)+'_dns.txt','w')
		#subprocess to run host -a on the current value of l in the loop, split into newlines
		try:
			dnsCmd = subprocess.Popen(['host', '-a', str(l)], stdout = subprocess.PIPE).communicate()[0].split('\n')
		except:
			print '[-] Error running dns query'
			dnsResult.append('Error running DNS query')
			pass
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

	#if no args provided, default to 'password'
	if args.googledork is None:
		print '[i] No dork args, defaulting to "password"'
		args.googledork = ['password']

	else:

		for d in args.googledork:
			if args.verbose is True:print 'dorking for %s' % d
			
			#default to password if no arg

			#iterate the lookup list
			for i, l in enumerate(lookup):
				googleResult.append('Google query for: '+str(d)+ ' ' + 'site:'+str(l))
				googleFile=open(reportDir+''.join(l)+'_google_dork_'+str(d)+'.txt','w')

				#show user whiat is being searched
				print '[+] Google query ' + str(i + 1) + ' for "'+str(d)+' ' + 'site:'+str(l) + '"'
				
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

			'''#maybe just do the rest here instead of api?
			url='https://exploits.shodan.io/api/search?query='+str(l)+'&key='+str(shodanApiKey)
			try:
				req = urllib2.Request(url)
				scrapeContent = urllib2.urlopen(req).read()
				time.sleep(1)
				print scrapeContent
			except Exception:
					pass'''

			#user notification that something is happening
			print '[+] Querying Shodan via API search for ' + l
			try:
				#set results to api search of current lookup value
				#https://shodan.readthedocs.io/en/latest/examples/basic-search.html
				results = shodanApi.search(l)
				#for each result
				for result in results['matches']:
					#append to shodanResult list
					shodanResult.append(str(result))

				'''exploits=shodanApi.exploits.search(l)
				for ex in exploits:
					shodanResult.append(str(ex))'''
			#catch exceptions		
			except shodan.APIError, e:
				#print excepted error
				print '[-] Shodan Error: %s' % e + ' Skipping!!!'
				print '[!] You may need to specify an API key with -s <api key>'
				return
				
		#verbosity logic
		#add iterator to dump all results
		if args.verbose is True:
			print '[+] Results found: %s' % results['total']

		#write contents of shodanResult list. this needs formatted
		shodanFile.writelines('%s hosts found: \n\n' % results['total'])
		for r in shodanResult:
			shodanFile.writelines('%s \n' % result['ip_str'])
			shodanFile.writelines(result['data'])
			shodanFile.writelines('****************\n')

		print shodanResult
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
						pasteScrapeResult.append(url)
						
						time.sleep(1)
						print url()
				except Exception:
					print '[-] Error scraping pastebin, skipping...'
					pasteScrapeResult.append('Error scraping pastebin')
					pass

				for r in scrapeResult:
					try:
						req = urllib2.Request(r)
						print 'Opening ' + r
						pasteScrapeContent = urllib2.urlopen(req).read()
						time.sleep(1)
						pasteScrapeContent.append()

					except Exception:
						print '[-] Error scraping pastebin, skipping...'
						pasteScrapeContent.append('Error scraping pastebin')
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
			try:
				print '[+] Running theHarvester -b google -d %s ' % l
				harvesterGoogleCmd = subprocess.Popen(['theharvester', '-b', 'google', '-d', str(l), '-l', '500', '-h'], stdout = subprocess.PIPE).communicate()[0].split('\r\n')
			except:
				print '[-] Error running theharvester. Make sure it is in your PATH and you are connected to the Internet'
				harvesterResult.append('Error running theHarvester')
				pass

			#run harvester with -b linkedin on lookup
			try:
				print '[+] Running theHarvester -b linkedin -d %s ' % l
				harvesterLinkedinCmd = subprocess.Popen(['theharvester', '-b', 'linkedin', '-d', str(l), '-l', '500', '-h'], stdout = subprocess.PIPE).communicate()[0].split('\r\n')
			except:
				print '[-] Error running theharvester. Make sure it is in your PATH and you are connected to the Internet'
				harvesterResult.append('Error running theHarvester')
				pass

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
			credResult=[]


			print '[+] Searching credential dumps for entries that contain '+l
			#overall, take the lookup value (preferably a domain) and search the dumps for it
			#for each file in ./credleaks directory
			#really need to get this data out of text files an into an indexed form. it's slow af 
			for credFileName in os.listdir('./credleaks/'):
				#open the file
				credFileOpen = open('./credleaks/'+credFileName, "r")
				j=0
				#i=0
				#for each line in opened file
				for line in credFileOpen:
					#line counter index. i thought maybe i could also display how many lines were searched
					#i=i+1
					#regex search for our current lookup value l
					if re.search((str(l)), line):
						#counter index
						j=j+1
						#look for a colon delimiter. dump files should be like email:hash. this of course assumes the creds file has emails as usernames
						if ':' in line:
							#split matches based on colons, sorta like 'awk -F :'. emails shouldnt have colons, right?
							#also the dat HAS to require colons otherwise it will return an index error
							matchedLine=line.split(":")
							#take the split parts, 0 and 1 that are uname and hash, respectively
							#place into a dict and strip the \r\n off of them
							dumpDict[str(matchedLine[1].rstrip("\r\n"))]=str(matchedLine[0].rstrip("\r\n"))
						#otherwise print xxx if theres no hash for the entry. some dumps dont have hashes for everyone...
						else:
							dumpDict['xxx']=str(line.rstrip("\r\n"))
				#print each file searched and how many matches if verbose
				if args.verbose is True: 
					print '[i] Searched ' + str(credFileName)+' and found '+ str(j)

			
			#print hash and user of files if verbose	
			if args.verbose is True:
				for h, u in dumpDict.items():
					print(str(u)) 

			#start printing stuff and appending to credResult
			print '[+] Searching Local Credential Dumps in ./credleaks against potfile in ./potfile '
			credFile.writelines('********EMAILS FOUND BELOW********\n\n\n\n')
			credResult.append('********EMAILS FOUND BELOW********\n\n\n\n')
			
			#iterate the dictionary containing user and hashes
			for h, u in dumpDict.items():
				#write username to text file
				credFile.writelines(str(u)+'\n')
				#write username to credResult for the docx report
				credResult.append(str(u)+'\n')
				
			credFile.writelines('********CREDENTIALS FOUND BELOW*********\n\n\n\n')
			credResult.append('********CREDENTIALS FOUND BELOW*********\n\n\n\n')
			
			#this section 'cracks' the hashes provided a pre-populated pot file
			#still in our lookup value iterate potfiles directory. you can have multiple pots, just in case
			for potFileName in os.listdir('./potfile/'):
				#open a pot file
				with open('./potfile/'+potFileName, 'r') as potFile:
					#tell user you are looking
					print '[i] Any creds you have in your potfile will appear below as user:hash:plain : '
					#then look at every line
					for potLine in potFile:
						#then for every line look at every hash and user in the dict
						for h, u in dumpDict.items():
							#if the hash in the dict matches a line in the potfile
							#that is also the same length as the original hash (this is probably a crappy check tho...)
							if str(h) == str(potLine[0:len(h)]):
								#print the user: and the line from the potfile (hash:plain) to the user
								print str(u)+':'+str(potLine.rstrip("\r\n"))
								#need to append the output to a variable to return or write to the file
								#this is separate because not all found usernames/emails have hashes and not all hashes are cracked
								#write to text file
								credFile.writelines(str(u)+':'+str(potLine[len(h):]))
								#add to credResult for docx report
								credResult.append(str(u)+':'+str(potLine[len(h):]))


			return credResult	
			print credResult

#*******************************************************************************
def pyfoca(args, lookup, reportDir):
	if args.whois is True:
		print "foca"

#*******************************************************************************

def write_report(args, reportDir, lookup, whoisResult, dnsResult, googleResult, shodanResult, pasteScrapeResult, harvesterResult, scrapeResult, credResult):

	for l in lookup:
		print '[+] Starting OSINT report for '+l

		#dump to a word doc
		#refs
		#https://python-docx.readthedocs.io/en/latest/user/text.html
		#https://python-docx.readthedocs.io/en/latest/user/quickstart.html
		
		#create a document 
		document = docx.Document()

		#add header
		heading = document.add_heading()
		runHeading = heading.add_run('Open Source Intelligence Report for %s' % l)
		font=runHeading.font
		font.name = 'Arial'
		font.color.rgb = RGBColor(0xe9,0x58,0x23)
		
		#add intro text
		paragraph = document.add_paragraph() 
		runParagraph = paragraph.add_run('\nThis document contains information about network, technology, and people associated with the assessment targets. The information was obtained by programatically querying various free or low cost Internet data sources.\n')
		font=runParagraph.font
		font.name = 'Arial'
		font.size = Pt(10)
		runParagraph = paragraph.add_run('\nThese data include information about the network, technology, and people associated with the targets\n')
		font=runParagraph.font
		font.name = 'Arial'
		font.size = Pt(10)
		runParagraph = paragraph.add_run('\nSpecific data sources include: whois, domain name system (DNS) records, Google dork results, matches from recent compromises such as LinkedIn, Shodan, theHarvester, as well as queries to Pastebin, Github, job boards, etc. \n')
		font=runParagraph.font
		font.name = 'Arial'
		font.size = Pt(10)

		
		#page break for cover page
		document.add_page_break()

		if credResult is not None:
			#header
			heading = document.add_heading(level=3)
			runHeading = heading.add_run('Credentials found from recent compromises (LinkedIn, Adobe, etc.) %s' % l)
			font=runHeading.font
			font.name = 'Arial'
			font.color.rgb = RGBColor(0xe9,0x58,0x23)
			paragraph = document.add_paragraph()
			for c in credResult:
				runParagraph = paragraph.add_run(''.join(c))
				font=runParagraph.font
				font.name = 'Arial'
				font.size = Pt(10)
			document.add_page_break()
		
		#add whois data with header and break after end
		if whoisResult is not None:
			#header
			heading = document.add_heading(level=3)
			runHeading = heading.add_run('Whois Data for %s' % l)
			font=runHeading.font
			font.name = 'Arial'
			font.color.rgb = RGBColor(0xe9,0x58,0x23)
			#content
			paragraph = document.add_paragraph()
			for w in whoisResult:
				runParagraph = paragraph.add_run('\n'.join(w))
				font=runParagraph.font
				font.name = 'Arial'
				font.size = Pt(10)
			document.add_page_break()
		
		#add dns data with header and break after end
		if dnsResult is not None:
			#header
			heading = document.add_heading(level=3)
			runHeading = heading.add_run('Domain Name System Data for %s' % l)
			font=runHeading.font
			font.name = 'Arial'
			font.color.rgb = RGBColor(0xe9,0x58,0x23)
			#content
			paragraph = document.add_paragraph()
			for d in dnsResult:
				runParagraph = paragraph.add_run('\n'.join(d))
				font=runParagraph.font
				font.name = 'Arial'
				font.size = Pt(10)
			document.add_page_break()

		#google dork output
		if googleResult is not None:
			#header
			heading = document.add_heading(level=3)
			runHeading = heading.add_run('Google Dork Results for %s' % l)
			font=runHeading.font
			font.name = 'Arial'
			font.color.rgb = RGBColor(0xe9,0x58,0x23)
			#content
			paragraph = document.add_paragraph()
			for r in googleResult:
				runParagraph = paragraph.add_run(''.join(r+'\n'))
				font=runParagraph.font
				font.name = 'Arial'
				font.size = Pt(10)
			document.add_page_break()
		
		#harvester output
		if harvesterResult is not None:
			document.add_heading('theHarvester Results for %s' % l, level=3)
			paragraph = document.add_paragraph()
			for h in harvesterResult: 
				runParagraph = paragraph.add_run(''.join(h))
				#set font stuff
				font=runParagraph.font
				font.name = 'Arial'
				font.size = Pt(10)
			document.add_page_break()
		
		#shodan output
		if shodanResult is not None:
			#reading from file because im stupid and cant get the json formatted yet
			'''#print shodanResult
			parsed=json.loads(str(shodanResult))
			json.dumps(parsed, indent=4, sort_keys=True)

			
			paragraph = document.add_paragraph()
			runParagraph = paragraph.add_run(json.dumps(parsed, indent=4, sort_keys=True, separators=(',', ': '))) #and JSON spews forth'''

			document.add_heading('Shodan Results for %s' % l, level=3)
			paragraph = document.add_paragraph()
			try:
				with open(reportDir+''.join(lookup)+'_shodan.txt','r') as f:
					line = f.read().splitlines()
					for li in line:
						runParagraph = paragraph.add_run(li.rstrip('\n\r ')+'\n')
						#set font stuff
						font=runParagraph.font
						font.name = 'Arial'
						font.size = Pt(10)
			except:
				pass
		
		#pastebin scrape output
		if pasteScrapeResult is not None:
			document.add_heading('Pastebin URLs for %s' % l, level=3)
			document.add_paragraph(pasteScrapeResult)
			document.add_page_break()
			#document.add_paragraph(pasteScrapeContent)
			#document.add_page_break()



		#general scrape output
		if scrapeResult is not None:
			document.add_heading('Website Scraping Results for %s' % l, level=3)
			paragraph = document.add_paragraph()
			for sr in scrapeResult:
				runParagraph = paragraph.add_run(sr)
				#set font stuff
				font=runParagraph.font
				font.name = 'Arial'
				font.size = Pt(10)

			document.add_page_break()
		
		print '[+] Writing file: ./reports/%s/OSINT_%s_.docx'  % (l, l)
		document.save(reportDir+'OSINT_%s_.docx' % l)


if __name__ == '__main__':
    main()
