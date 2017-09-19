#!/usr/bin/env python

import requests, time
from google import search
from lxml import html

class Pastebinscrape():

    #right now this just google dorks a supplied arg for site:pastebin.com
    #need to implement scraping api http://pastebin.com/api_scraping_faq
    #that would necessitate a more ongoing program however, not one-off usage of autosint
    #scraping url is here http://pastebin.com/api_scraping.php
    def run(self, args, lookup, reportDir, apiKeyDir):
        
        #set a UA
        userAgent = {'User-agent': 'Mozilla/5.0'}
        
        #defaults and init
        pasteScrapeUrl = []
        pasteScrapeContent = []
        pasteScrapeResult =[]
        dorks=args.dorks
        scrapeURL = []
        scrapeContent = []

        #iterate the lookup list
        for i, l in enumerate(lookup):
            for d in dorks:

                #init textfiles
                scrapedFile=open(reportDir+l+'/'+l+'_pastebin_content.txt','w')
                pasteUrlFile=open(reportDir+l+'/'+l+'_pastebin_urls.txt','w')
                
                #show user whiat is being searched
                print('[+] Searching Pastebin for public pastes containing %s' % (l))
                print('[i] May require a Pastebin Pro account for IP whitelisting')


                #run google query code
                try:
                    #iterate url results from search of dork arg and supplied lookup value against pastebin. return top 20 hits
                    for url in search(str(d) +' '+ str(l) + ' site:pastebin.com', stop = 20):
                        #delay 1s to be polite
                        time.sleep(1)
                        #append results together
                        scrapeURL.append(url)
                        if args.verbose is True:
                            print ('[+] Paste containing "%s" and "%s" found at: %s' % (d,l,url))
                except Exception as e:
                    print('[-] Error dorking pastebin URLs: %s, skipping...' % e)
                    pasteScrapeResult.append('Error scraping Pastebin')
                    continue

                for u in scrapeURL:
                    #http://docs.python-guide.org/en/latest/scenarios/scrape/
                    try:
                        page = requests.get(u, headers = userAgent)
                        pasteUrlFile.writelines(u+'\n')
                        pasteScrapeResult.append(u+'\n')
                    except:
                        print ('[-] Error opening ' + u +':')
                        pasteScrapeResult.append('Error opening %s' % u)
                        continue


                    #build html tree
                    tree = html.fromstring(page.content)

                    #if verbose spit out url, search term and domain searched
                    if args.verbose is True:print ('[+] Looking for instances of %s and %s in %s' % (d,l,u))
                    #grab raw paste data from the textarea
                    rawPasteData = tree.xpath('//textarea[@class="paste_code"]/text()')

                    #search lines for lookup and keyword
                    for line in rawPasteData:
                        #regex for the lookup value (domain) in that line
                        #if re.search((str(l)), line):
                        if str(l) in line:
                            #if the argument search term is in the line
                            if d in line:
                                #print str(line)
                                scrapedFile.writelines(str(line.encode('utf8')))
                #print pasteScrapeResult
                return pasteScrapeResult
