#!/usr/bin/env python

import requests, time
from google import search
from lxml import html


# this could be GREATLY improved. need to implement the custom search api
# GHDB password dorks https://www.exploit-db.com/google-hacking-database/9/
# GHDB sensitive dirs https://www.exploit-db.com/google-hacking-database/3/
# uses this awesome module https://pypi.python.org/pypi/google
# https://stackoverflow.com/questions/4082966/what-are-the-alternatives-now-that-the-google-web-search-api-has-been-deprecated/11206266#11206266

class Googledork():
    def __init__(self):
        self.google_result = []



    def run(self, args, lookup, reportDir):

        self.args = args

        #C58EA28C-18C0-4a97-9AF2-036E93DDAFB3 is string for open OWA attachments, for example
        #init lists

        #iterate the lookup list
        for i, l in enumerate(lookup):
            for d in self.args.dorks:

                #add header to result
                self.google_result.append('[i] Google query for: "%s site:%s"' % (str(d),str(l)))

                #open a file for each domain searched
                googleFile=open(reportDir+l+'/'+l+'_google_dork.txt','w')

                #show user whiat is being searched
                print ('[+] Google query %s for %s site:%s' % (str(i + 1),str(d),str(l)))
                print('[+] Results:')
                
                try:
                    #iterate url results from search of password(for now) and site:current list value
                    for url in search(str(self.args.dorks)+' site:'+str(l), stop = 20):
                        #append results together
                        self.google_result.append(url)

                        #rate limit with 2 second delay
                        time.sleep(2)
                #catch exceptions
                except Exception as e:
                    print ('[!] Error encountered: %s' % e)
                    pass
        #iterate results
        for r in self.google_result:
            #write results on newlines
            googleFile.writelines(r + '\r\n')

        #verbosity flag
        if self.args.verbose is True:
            for r in self.google_result: print (''.join(r))
                
        #return results list
        return self.google_result
    