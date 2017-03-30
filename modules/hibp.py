#!/usr/bin/env python

import json
import requests

class Haveibeenpwned():


	#https://haveibeenpwned.com/API/v2
	#https://haveibeenpwned.com/Pastes/Latest
	def run(self, args, lookup, reportDir):
		userAgent = {'User-agent': 'Mozilla/5.0'}
		if args.hibp is True:
			for i,l in enumerate(lookup):
				print '[+] Searching haveibeenpwned.com for %s' % l
				scrapeFile=open(reportDir+l+'/'+l+'_haveibeenpwned.txt','w')
				url = 'https://haveibeenpwned.com/api/v2/breachedaccount/test@example.com?domain=%s' % l


				if args.verbose is True:print '[+] Searching haveibeenpwned.com for %s' % (l.split('.')[0])

				#http://docs.python-guide.org/en/latest/scenarios/scrape/
				try:
					page = requests.get(url, headers = userAgent, verify=False)
					#build html tree
					page.json()
					

				except:
					print '[-] Connection error or no result on ' + url +':'
					print '[-] Status code %s' % page.status_code
					continue