#!/usr/bin/env python
"""module to perform an API search against haveibeenpwned.com based on supplied domain"""
#https://haveibeenpwned.com/API/v2
#https://haveibeenpwned.com/Pastes/Latest
# needs work...
import json
import requests

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Haveibeenpwned():
    """haveibeenpwned module class"""
    def __init__(self):
        self.haveibeenpwned_json_result = []

    def run(self, args, lookup, reportDir):
        """main function"""
        userAgent = {'user-agent': 'Pwnage Checker for AutOSINT'}

        for i, l in enumerate(lookup):
            print('[+] Searching haveibeenpwned.com via API for {}'.format(l))
            scrapeFile=open(reportDir + l + '/' + l + '_haveibeenpwned.txt','w')
                            #altered HIBP URL
            url = 'https://haveibeenpwned.com/api/v2/breaches?domain={}'.format(l)

            if args.verbose is True:
                print('[+] Searching haveibeenpwned.com for {}'.format((l.split('.')[0])))

            #http://docs.python-guide.org/en/latest/scenarios/scrape/
            try:
                page = requests.get(url, headers=userAgent, verify=False)
                #build html tree
                #save HIBP data to file
                json.dump((page.json()),scrapeFile)
                #append to a result list
                self.haveibeenpwned_json_result.append(json.dump(page.json()))
                #add in error checking (placeholder) maybe more efficient than main try loop
                try:
                    if page.status_code == 503:
                        page.raise_for_status()
                except page.exceptions.HTTPError as e:
                    if e.page.status_code == 503:
                        print ('Service unavailable')
                        continue
            except:
                print ('[-] Connection error or no result on {} :'.format(url))
                print ('[-] Status code {}'.format(page.status_code))
                continue
