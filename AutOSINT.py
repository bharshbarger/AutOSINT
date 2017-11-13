#!/usr/bin/env python
"""A tool to automate some OSINT tasks and put results into a docx report
By @arbitrary_code
https://github.com/bharshbarger/AutOSINT
Special thanks to:
@Beamr
@tatanus
unum alces!"""

#builtins
import argparse
import os
import re
import socket
import sys
import time

#AutOSINT module imports
from modules.whois import Whois
from modules.dnsquery import Dnsquery
from modules.hibp import Haveibeenpwned
from modules.googledork import Googledork
from modules.shodansearch import Shodansearch
from modules.pastebinscrape import Pastebinscrape
from modules.theharvester import Theharvester
from modules.credleaks import Credleaks
from modules.pyfoca import Pyfoca
from modules.webscrape import Scraper
from modules.reportgen import Reportgen

class Autosint(object):
    """autosint class"""
    def __init__(self, args, parser):
        """start with arguments and parser objects"""

        #import args and parser objects from argparse
        self.args = args
        self.parser = parser

        #version
        self.version = 'v2-09.19.17'

        #defaults
        self.lookup_list = []
        self.client_name = None
        self.autosint_db = 'AutOSINT.db'
        self.report_directory = './reports/'
        self.api_key_directory = './api_keys/'
        self.databse_directory = './database/'



        #module results lists
        self.whois_result = []
        self.dns_result = []
        self.google_dork_result = []
        self.shodan_query_result = []
        self.pastebin_scrape_urls_result = []
        self.pastebin_scrape_content_result = []
        self.theharvester_module_result = []
        self.scrape_result = []
        self.cred_leak_search_result = []
        self.pyfoca_module_result = []
        self.haveibeenpwned_result = []

        #start timer
        self.start_time = time.time()

        #module assign
        self.cred_leaks_module = Credleaks()
        self.pyfoca_module = Pyfoca()
        self.web_scraper_module = Scraper()
        self.theharvester_module = Theharvester()
        self.dns_query_module = Dnsquery()
        self.pastebin_scrape_module = Pastebinscrape()
        self.shodan_search_module = Shodansearch()
        self.google_dork_module = Googledork()
        self.haveibeenpwned_api_module = Haveibeenpwned()
        self.whois_query_module = Whois()
        self.report_generator_module = Reportgen()

        #check dirs
        if not os.path.exists(self.report_directory):
            os.makedirs(self.report_directory)

        if not os.path.exists(self.api_key_directory):
            os.makedirs(self.api_key_directory)

    def clear(self):
        """clean up screen"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def banner(self):
        """verbosity flag to print logo and args"""
        if self.args.verbose is True:
            print('''
    _         _    ___  ____ ___ _   _ _____ 
   / \  _   _| |_ / _ \/ ___|_ _| \ | |_   _|
  / _ \| | | | __| | | \___ \| ||  \| | | |  
 / ___ \ |_| | |_| |_| |___) | || |\  | | |  
/_/   \_\__,_|\__|\___/|____/___|_| \_| |_|\n''')

        if self.args.verbose is True:
            print('AutOSINT.py {}: A way to automate various OSINT tasks and place results into a docx\n'.format(self.version))
        if self.args.verbose is True:
            print(self.args)

    def check_arguments(self):
        """check local dirs for reports, apikey and database"""
        #require at least one argument
        if not (self.args.domain):
            print('[-] No OSINT reference provided, add domain(s) with -d\n')
            parser.print_help()
            sys.exit(0)

        #check to see if an ip or domain name was entered
        if self.args.domain is not None:
            for d in self.args.domain:
                self.lookup_list = self.args.domain
                for l in self.lookup_list:
                    if not os.path.exists(self.report_directory+l):
                        os.makedirs(self.report_directory+l)

        if self.args.verbose is True:
            print ('[+] Lookup Values: '+', '.join(self.lookup_list))

        #check for a supplied client name and exit if none provided
        if self.args.client is None:
            print('\n[!] Client name required, please provide with -c <Clientname>\n')
            parser.print_help()
            sys.exit(0)
        else:
            #strip out specials in client name
            self.client_name = re.sub('\W+', ' ', self.args.client).lower()



    def run_queries(self):
        """invoke all the queries. assumption is that every run will want all data"""
        
        #verified
        self.whois_result = self.whois_query_module.run(self.args, self.lookup_list, self.report_directory)
        
        #verified
        self.dns_result = self.dns_query_module.run(self.args, self.lookup_list, self.report_directory)
        
        #needs work
        self.haveibeenpwned_result = self.haveibeenpwned_api_module.run(self.args, self.lookup_list, self.report_directory)
        
        #verified
        self.google_dork_result = self.google_dork_module.run(self.args, self.lookup_list, self.report_directory)
        
        #verified
        self.shodan_query_result = self.shodan_search_module.run(self.args, self.lookup_list, self.report_directory, self.api_key_directory)
        
        #verified
        self.pastebin_scrape_urls_result = self.pastebin_scrape_module.run(self.args, self.lookup_list, self.report_directory, self.api_key_directory)
        
        #verified
        self.theharvester_module_result = self.theharvester_module.run(self.args, self.lookup_list, self.report_directory)
        
        self.cred_leak_search_result = self.cred_leaks_module.run(self.args, self.lookup_list, self.start_time, self.report_directory)
        
        #needs work
        self.scrape_result = self.web_scraper_module.run(self.args, self.lookup_list, self.report_directory, self.api_key_directory)
        
        #pyfoca has to be present
        self.pyfoca_module_result = self.pyfoca_module.run(self.args, self.lookup_list, self.report_directory)
            
    def report(self):
        """run the docx report. text files happen in the respective functions"""
        self.report_generator_module.run(\
            self.args, \
            self.report_directory, \
            self.lookup_list, \
            self.whois_result, \
            self.dns_result, \
            self.google_dork_result, \
            self.shodan_query_result, \
            self.pastebin_scrape_urls_result, \
            self.theharvester_module_result, \
            self.scrape_result, \
            self.cred_leak_search_result, \
            self.pyfoca_module_result)

    def end(self):
        """ending stuff, right now just shows how long script took to run"""
        print('\nCompleted in {:.2f} seconds\n'.format(time.time() - self.start_time))

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument('-c', '--client', \
        metavar='FooCorp',\
        help='The name you want to call target domain owner\'s name.')
    
    parser.add_argument('-d', '--domain', \
        metavar='foo.com', \
        nargs=1, \
        help='The Domain you want to search.')

    parser.add_argument('-v', '--verbose', \
        help='Verbosity option. Mainly just dumps all output to the screen.', \
        action='store_true')

    parser.add_argument('dorks', metavar='DORKS', type=str, nargs='+', help='user supplied dorks')  
        
    args = parser.parse_args()

    #run functions with arguments passed
    runAutosint = Autosint(args, parser)
    runAutosint.clear()
    runAutosint.banner()
    runAutosint.check_arguments()
    runAutosint.run_queries()
    runAutosint.report()
    runAutosint.end()
    
if __name__ == '__main__':
    main()
