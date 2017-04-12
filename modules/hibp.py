#!/usr/bin/env python

import json
import requests

class Haveibeenpwned():


	#https://haveibeenpwned.com/API/v2
	#https://haveibeenpwned.com/Pastes/Latest
	def run(self, args, lookup, reportDir):
		userAgent = {'user-agent': 'Pwnage Checker for AutOSINT'}
		if args.hibp is True:
			for i,l in enumerate(lookup):
				print '[+] Searching haveibeenpwned.com for %s' % l
				scrapeFile=open(reportDir+l+'/'+l+'_haveibeenpwned.txt','w')
                                #altered HIBP URL
				url = 'https://haveibeenpwned.com/api/v2/breaches?domain=%s' % l


				if args.verbose is True:print '[+] Searching haveibeenpwned.com for %s' % (l.split('.')[0])

				#http://docs.python-guide.org/en/latest/scenarios/scrape/
				try:
					page = requests.get(url, headers = userAgent, verify=False)
					#build html tree
					#save HIBP data to file
					json.dump((page.json()),scrapeFile)
					#add in error checking (placeholder) maybe more efficient than main try loop
					try:
					    if page.status_code == 503:
					        page.raise_for_status()
					except page.exceptions.HTTPError as e:
					    if e.page.status_code == 503:
					        print 'Service unavailable'
					        continue
					        
				except:
					print '[-] Connection error or no result on ' + url +':'
					print '[-] Status code %s' % page.status_code
					continue
