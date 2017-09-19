#!/usr/bin/env python

import os
import urllib
import json
import requests
from lxml import html
from pprint import pprint

class Scraper():

    def __init__(self):
        self.scrape_result=[]
        self.user_agent = {'User-agent': 'Mozilla/5.0'}
        self.a=''
        self.indeed_result=[]
        self.github_result=[]
        self.virustotal_result=[]
        self.virustotal_api_key_value=''
        self.virustotal_parameters ={}

    def run(self, args, lookup, reportDir, api_key_directory):
        scrape_result=[]
        user_agent_string = {'User-agent': 'Mozilla/5.0'}
        a=''
        indeed_result=[]
        github_result=[]
        virustotal_result=[]
        virustotal_api_key_value=''
        virustotal_parameters ={}
        virustotal_response_json = None


        for i,l in enumerate(lookup):
            scrapeFile=open(reportDir+l+'/'+l+'_scrape.txt','w')

            print('[+] Scraping sites using {}'.format(l))
            #http://www.indeed.com/jobs?as_and=ibm.com&as_phr=&as_any=&as_not=&as_ttl=&as_cmp=&jt=all&st=&salary=&radius=25&fromage=any&limit=500&sort=date&psf=advsrch
            #init list and insert domain with tld stripped
            #insert lookup value into static urls
            scrape_targets_dictionary = {\
            'indeed':'http://www.indeed.com/jobs?as_and={}&limit=500&sort=date'.format(l.split('.')[0]), \
            'github':'https://api.github.com/search/repositories?q={}&sort=stars&order=desc'.format(l.split('.')[0]),#pull off the tld\
            'glassdoor':'https://www.glassdoor.com/Reviews/company-reviews.htm?suggestCount=0&suggestChosen=false&clickSource=searchBtn&typedKeyword={}&sc.keyword={}&locT=&locId='.format(l.split('.')[0],l.split('.')[0]),\
            'slideshare':'http://www.slideshare.net/{}'.format(l.split('.')[0]), \
            'virustotal':'https://www.virustotal.com/vtapi/v2/{}/report'.format(l.split('.')[0]), \
            'censys':'https://www.censys.io/api/v1',
            'builtwith':'https://api.builtwith.com/free1/api.json'\
            #'':''\
            }

            for name,url in scrape_targets_dictionary.items():
                #indeed matches jobs. yeah yeah it doesnt use their api yet
                if name == 'indeed':
                    if args.verbose is True:
                        print('[+] Searching job postings on indeed.com for {}:'.format(l.split('.')[0]))
                    
                    #http://docs.python-guide.org/en/latest/scenarios/scrape/
                    try:
                        ipage = requests.get(url, headers = user_agent_string)
                    except Exception as e:
                        print('[-] Scraping error on {}: {}'.format(url, e))
                        continue

                    #build html tree
                    itree = html.fromstring(ipage.content)

                    #count jobs
                    jobCount = itree.xpath('//div[@id="searchCount"]/text()')
                    print('[+] {} Jobs posted on indeed.com that match {}:'.format(str(''.join(jobCount)), l.split('.')[0]))
                    indeed_job_title = itree.xpath('//a[@data-tn-element="indeed_job_title"]/text()')
                    indeed_result.append('\n[+] Job postings on indeed.com that match {} \n\n'.format(l).split('.')[0])
                    for t in indeed_job_title:
                        indeed_result.append('{}\n'.format(t))

                #github matches search for user supplied domain
                #https://developer.github.com/v3/search/
                #http://docs.python-guide.org/en/latest/scenarios/json/
                if name == 'github':
                    if args.verbose is True:print ('[+] Searching repository names on Github for {}'.format(l.split('.')[0]))

                    #http://docs.python-guide.org/en/latest/scenarios/scrape/
                    try:
                        gpage = requests.get(url, headers = user_agent_string)
                    except Exception as e:
                        print ('[-] Scraping error on {}: {}' %(url, e))
                        continue

                    #read json response
                    gitJson = gpage.json()
                    
                    #grab repo name from json items>index val>full_name
                    github_result.append('[+] Github repositories matching '+(l.split('.')[0])+'\n\n')
                    for i,r in enumerate(gitJson['items']):
                        self.github_result.append(gitJson['items'][i]['full_name']+'\n')

                if name == 'virustotal':
                    #look for api key
                    if not os.path.exists(api_key_directory + 'virus_total.key'):
                        print '[-] Missing {}virus_total.key' % api_key_directory
                        #prompt if missing
                        virustotal_api_key_value=raw_input("Please provide an API Key: ")
                        #prompt to save
                        response = raw_input('Would you like to save this key to a file? (y/n): ')
                        if 'y' in response.lower():
                            with open(api_key_directory + 'virus_total.key', 'w') as api_key_file:
                                api_key_file.writelines(virustotal_api_key_value)
                    else:
                        #read API key
                        try:
                            with open(api_key_directory + 'virus_total.key', 'r') as api_key_file:
                                for k in api_key_file:
                                    virustotal_api_key_value = k
                        except:
                            print ('[-] Error opening {}virus_total.key key file, skipping. '.format(api_key_directory))
                            continue

                    if args.verbose is True: 
                        print('[+] VirusTotal domain report for {}'.format(l))
                    

                    self.virustotal_result.append('[+] VirusTotal domain report for {}'.format(l))

                    virustotal_parameters = {'domain': l, 'apikey': virustotal_api_key_value}
                    virustotal_headers = {"Accept-Encoding": "gzip, deflate",\
                    "User-Agent" : "gzip,  My python example client"}

                    try:
                        response = requests.get('https://www.virustotal.com/vtapi/v2/domain/report',\
                        params=virustotal_parameters, headers=virustotal_headers)
                    except Exception as e:
                        print('Error: {}'.format(e))
                    
                    if args.verbose is True: 
                        print(response)

                    try:
                        virustotal_response_json = response.json()
                    except Exception as e:
                        print('[!] Error: {}'.format(e))

                    if args.verbose is True:
                        print(json.dumps(virustotal_response_json, indent=4, sort_keys=True))

                    self.virustotal_result.append(virustotal_response_json)



            #write the file
            for g in self.github_result:
                scrapeFile.writelines(''.join(str(g.encode('utf-8'))))
            for i in self.indeed_result:
                scrapeFile.writelines(''.join(str(i.encode('utf-8'))))
            for v in self.virustotal_result:
                scrapeFile.writelines(str(json.dumps(virustotal_response_json, indent=4, sort_keys=True)))
                    

            scrape_result.append(indeed_result)
            scrape_result.append(github_result) 

            #verbosity logic
            if args.verbose is True:
                for gr in github_result: 
                    print(''.join(gr.strip('\n')))
                for ir in indeed_result: 
                    print(''.join(ir.strip('\n')))

        return scrape_result