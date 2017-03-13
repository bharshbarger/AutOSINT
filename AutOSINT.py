#!/usr/bin/env python

#By @arbitrary_code

#Special thanks to:
#@Beamr
#@tatanus
#unum alces!

try:
	import sys
	import time
	import argparse
	import subprocess
	import socket
	

	import urllib
	import urllib2

	import docx
	from docx.shared import Pt
	from docx.shared import RGBColor
	from docx.shared import Inches
	from docx.enum.text import WD_ALIGN_PARAGRAPH
	from docx.oxml.shared import OxmlElement, qn

	import re
	import os
	import json
	import pprint
	from lxml import html

	from collections import Counter

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
		whoisSearch.run(args, lookup, reportDir)

	#call function if -n arg
	if args.nslookup is True:
		
		dnsQuery = Dnsquery()
		dnsQuery.run(args, lookup, reportDir)

	#call function if -b arg
	if args.hibp is True:

		hibpSearch = Haveibeenpwned()
		hibpSearch.run(args, lookup, reportDir)

	#call function if -g arg
	if args.googledork is not None:
		
		googleDork = Googledork()
		googleDork.run(args, lookup, reportDir)

	#call function if -s arg
	if args.shodan is True:
		
		shodanSearch = Shodansearch()
		shodanSearch.run(args, lookup, reportDir, apiKeyDir)

	#call function if -p arg
	if args.pastebinsearch is not None:
		
		pastebinScrape = Pastebinscrape()
		pastebinScrape.run(args, lookup, reportDir, apiKeyDir)

	# call function if -t arg
	if args.theharvester is True:
		
		theHarvester=Theharvester()
		theHarvester.run(args, lookup, reportDir)

		#harvesterResult=the_harvester(args, lookup, reportDir)
	
	#call function if -c arg 
	if args.creds is True:
		
		credLeaks=Credleaks()
		credLeaks.run(args, lookup, startTime, reportDir)


	#call function if -S arg
	if args.scraper is True:
		
		web_scraper=Scraper()
		scrapeResults = web_scraper.run(args, lookup, reportDir, apiKeyDir)

	#call function if -f arg
	if args.foca is True:
		
		pyFoca = Pyfoca()
		pyFoca.run(args, lookup, reportDir)

		#pyfocaResult=pyfoca(args, lookup, reportDir)

	#run the docx report. text files happen in the respective functions
	write_report(args, reportDir, lookup, whoisResult, dnsResult, googleResult, shodanResult, pasteScrapeResult, harvesterResult, scrapeResult, credResult, pyfocaResult)


		
#*******************************************************************************


	
#*******************************************************************************

				
#*******************************************************************************





#*******************************************************************************


#*******************************************************************************


#*******************************************************************************

def write_report(args, reportDir, lookup, whoisResult, dnsResult, googleResult, shodanResult, pasteScrapeResult, harvesterResult, scrapeResult, credResult, pyfocaResult):

	today = time.strftime("%m/%d/%Y")
	for l in lookup:
		print '[+] Starting OSINT report for '+l

		#dump to a word doc
		#refs
		#https://python-docx.readthedocs.io/en/latest/user/text.html
		#https://python-docx.readthedocs.io/en/latest/user/quickstart.html
		
		#create a document 
		document = docx.Document()


		#add logo
		document.add_picture('./resources/logo.png', height=Inches(1.25))

		#add domain cover info

		paragraph = document.add_paragraph() 
		runParagraph = paragraph.add_run('%s' % l)
		font=runParagraph.font
		font.name = 'Arial'
		font.size = Pt(28)
		font.color.rgb = RGBColor(0x00,0x00,0x00)
	
		#add cover info
		paragraph = document.add_paragraph() 
		runParagraph = paragraph.add_run('Open Source Intelligence Report\n\n\n\n\n\n\n\n\n\n\n')
		font=runParagraph.font
		font.name = 'Arial'
		font.size = Pt(26)
		font.color.rgb = RGBColor(0xe9,0x58,0x23)

		paragraph = document.add_paragraph() 
		runParagraph = paragraph.add_run('Generated on: %s' % today)
		font=runParagraph.font
		font.name = 'Arial'
		font.size = Pt(16)
		font.color.rgb = RGBColor(0x00,0x00,0x00)


		#page break for cover page
		document.add_page_break()
		
		#add intro text on intropage

		heading = document.add_heading()
		runHeading = heading.add_run('Executive Summary')
		font=runHeading.font
		font.name = 'Arial'
		font.size = Pt(20)
		font.color.rgb = RGBColor(0xe9,0x58,0x23)

		paragraph = document.add_paragraph() 
		runParagraph = paragraph.add_run('\nThis document contains information about network, technology, and people associated with the assessment targets. The information was obtained by programatically querying various free or low cost Internet data sources.\n')
		font=runParagraph.font
		font.name = 'Arial'
		font.size = Pt(11)
		runParagraph = paragraph.add_run('\nThese data include information about the network, technology, and people associated with the targets.\n')
		font=runParagraph.font
		font.name = 'Arial'
		font.size = Pt(11)
		runParagraph = paragraph.add_run('\nSpecific data sources include: whois, domain name system (DNS) records, Google dork results, and data from recent compromises such as LinkedIn. Other sources include results from Shodan, document metadata from theHarvester and pyFoca, as well as queries to Pastebin, Github, job boards, etc. \n')
		font=runParagraph.font
		font.name = 'Arial'
		font.size = Pt(11)

		
		#page break for cover page
		document.add_page_break()

		heading = document.add_heading()
		runHeading = heading.add_run('Table of Contents')
		font=runHeading.font
		font.bold = True
		font.name = 'Arial'
		font.size = Pt(20)
		font.color.rgb = RGBColor(0x0,0x0,0x0)

		#TOC https://github.com/python-openxml/python-docx/issues/36
		paragraph = document.add_paragraph()
		run = paragraph.add_run()
		font.name = 'Arial'
		font.size = Pt(11)
		fldChar = OxmlElement('w:fldChar')  # creates a new element
		fldChar.set(qn('w:fldCharType'), 'begin')  # sets attribute on element

		instrText = OxmlElement('w:instrText')
		instrText.set(qn('xml:space'), 'preserve')  # sets attribute on element
		instrText.text = 'TOC \o "1-3" \h \z \u'   # change 1-3 depending on heading levels you need

		fldChar2 = OxmlElement('w:fldChar')
		fldChar2.set(qn('w:fldCharType'), 'separate')
		fldChar3 = OxmlElement('w:t')
		fldChar3.text = "Right-click to update field."
		fldChar2.append(fldChar3)

		fldChar4 = OxmlElement('w:fldChar')
		fldChar4.set(qn('w:fldCharType'), 'end')

		r_element = run._r
		r_element.append(fldChar)
		r_element.append(instrText)
		r_element.append(fldChar2)
		r_element.append(fldChar4)
		p_element = paragraph._p



		#page break for toc
		document.add_page_break()


		if credResult:
			print '[+] Adding credential dump results to report'
			#header
			heading = document.add_heading(level=3)
			runHeading = heading.add_run('Credentials found from recent compromises (LinkedIn, Adobe, etc.) related to: %s' % l)
			font=runHeading.font
			font.name = 'Arial'
			font.color.rgb = RGBColor(0xe9,0x58,0x23)
			paragraph = document.add_paragraph()
			for c in credResult:
				runParagraph = paragraph.add_run(''.join(c))
				font=runParagraph.font
				font.name = 'Arial'
				font.size = Pt(11)
			document.add_page_break()
		
		#add whois data with header and break after end
		if whoisResult:
			print '[+] Adding whois results to report'
			#header
			heading = document.add_heading(level=3)
			runHeading = heading.add_run('Whois Data for: %s' % l)
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
		if dnsResult:
			print '[+] Adding DNS results to report'
			#header
			heading = document.add_heading(level=3)
			runHeading = heading.add_run('Domain Name System Data for: %s' % l)
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
		if googleResult:
			print '[+] Adding google dork results to report'
			#header
			heading = document.add_heading(level=3)
			runHeading = heading.add_run('Google Dork Results for: %s' % l)
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
		if harvesterResult:
			print '[+] Adding theHarvester results to report'
			#header
			heading = document.add_heading(level=3)
			runHeading = heading.add_run('theHarvester Results for: %s' % l)
			font=runHeading.font
			font.name = 'Arial'
			font.color.rgb = RGBColor(0xe9,0x58,0x23)
			#content
			paragraph = document.add_paragraph()
			for h in harvesterResult: 
				runParagraph = paragraph.add_run(''.join(h))
				#set font stuff
				font=runParagraph.font
				font.name = 'Arial'
				font.size = Pt(10)
			document.add_page_break()
		

		#pastebin scrape output
		if pasteScrapeResult:
			print '[+] Adding pastebin scrape results to report'
			document.add_heading('Pastebin URLs for %s' % l, level=3)
			document.add_paragraph(pasteScrapeResult)
			document.add_page_break()
			#document.add_paragraph(pasteScrapeContent)
			#document.add_page_break()



		#general scrape output
		if scrapeResult:
			print '[+] Adding website scraping results to report'
			#header
			heading = document.add_heading(level=3)
			runHeading = heading.add_run('Website Scraping Results for %s' % l)
			font=runHeading.font
			font.name = 'Arial'
			font.color.rgb = RGBColor(0xe9,0x58,0x23)
			#content
			paragraph = document.add_paragraph()
			for sr in scrapeResult:
				runParagraph = paragraph.add_run(sr)
				font=runParagraph.font
				font.name = 'Arial'
				font.size = Pt(10)

			document.add_page_break()


		#pyfoca results
		if pyfocaResult:
			print '[+] Adding pyfoca results to report'
			heading = document.add_heading(level=3)
			runHeading = heading.add_run('pyFoca Results for: %s' % l)
			font=runHeading.font
			font.name = 'Arial'
			font.color.rgb = RGBColor(0xe9,0x58,0x23)


			paragraph = document.add_paragraph()
			for fr in pyfocaResult:
				#lolwut
				runParagraph = paragraph.add_run(''.join(str(fr).strip(("\\ba\x00b\n\rc\fd\xc3"))))
				font=runParagraph.font
				font.name = 'Arial'
				font.size = Pt(10)

			document.add_page_break()
		
		#shodan output
		if shodanResult:
			heading = document.add_heading(level=3)
			runHeading = heading.add_run('Shodan Results for: %s' % l)
			font=runHeading.font
			font.name = 'Arial'
			font.color.rgb = RGBColor(0xe9,0x58,0x23)


			paragraph = document.add_paragraph()
			for shr in shodanResult:
				try:
					runParagraph = paragraph.add_run(str(shr).strip(("\\ba\x00b\n\rc\fd\xc3")))
					#set font stuff
					font=runParagraph.font
					font.name = 'Arial'
					font.size = Pt(10)
				except:
					print 'probably an encoding error...'
					continue
		
		print '[+] Writing file: ./reports/%s/OSINT_%s_.docx'  % (l, l)
		document.save(reportDir+l+'/'+l+'OSINT_%s_.docx' % l)


if __name__ == '__main__':
    main()
