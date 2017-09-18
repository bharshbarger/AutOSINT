#!/usr/bin/env python
"""A tool to automate some OSINT tasks"""
#By @arbitrary_code
#https://github.com/bharshbarger/AutOSINT

#Special thanks to:
#@Beamr
#@tatanus
#unum alces!

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

from resources.reportgen import Reportgen
from resources.dbcommands import DatabaseCommands
from resources.setupDB import SetupDatabase

class Autosint:
    """autosint class"""
    def __init__(self, args, parser):

        #version
        self.version = 'v2-09.18.17'

        #defaults
        self.lookup_list = []
        self.client_name = None
        self.autosint_db = 'AutOSINT.db'
        self.report_directory = './reports/'
        self.api_key_directory = './api_keys/'

        #import args and parser objects from argparse
        self.args = args
        self.parser = parser

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

        #resource assign
        self.report_generator_module = Reportgen()
        self.initialize_database = SetupDatabase()

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
            print('AutOSINT.py {}: A way to automate various OSINT tasks\n'.format(self.version))
        if self.args.verbose is True:
            print(self.args)

    def check_arguments(self):
        """check local dirs for reports, apikey and database"""
        if not os.path.exists(self.report_directory):
            os.makedirs(self.report_directory)

        if not os.path.exists(self.api_key_directory):
            os.makedirs(self.api_key_directory)

        #set True on action store_true args if -a
        if self.args.all is True:
            self.args.creds = True
            self.args.hibp = True
            self.args.foca = True
            self.args.nslookup = True
            self.args.theharvester = True
            self.args.whois = True
            self.args.scraper = True
            self.args.shodan = True
            
        #validate entered IP address? do we even care about IP address? i and d do the same shit
        if self.args.ipaddress is not None:
            for ip in self.args.ipaddress:
                try:
                    socket.inet_aton(ip)
                except socket.error:
                    print('[-] Invalid IP address entered! {}'.format(str(ip)))
                    sys.exit(0)

        #require at least one argument
        if not (self.args.domain or self.args.ipaddress):
            print('[-] No OSINT reference provided, add domain(s) with -d or IP address(es) with -i\n')
            sys.exit(0)

        #if no queries defined, exit. -a sets all so we're good there
        if (self.args.whois is False and \
            self.args.hibp is False and \
            self.args.nslookup is False and \
            self.args.googledork is None and \
            self.args.shodan is False and \
            self.args.creds is False and \
            self.args.theharvester is False and \
            self.args.scraper is False and \
            self.args.pastebinsearch is None and \
            self.args.foca is False):
            print '[-] No options specified, use -h or --help for a list'
            sys.exit(0)

        #check to see if an ip or domain name was entered
        if self.args.domain is not None:
            for d in self.args.domain:
                self.lookup_list = self.args.domain
                for l in self.lookup_list:
                    if not os.path.exists(self.report_directory+l):
                        os.makedirs(self.report_directory+l)
                    
        else:
            for ip in self.args.ipaddress:
                self.lookup_list = self.args.ipaddress
                for l in self.lookup_list:
                    if not os.path.exists(self.report_directory+l):
                        os.makedirs(self.report_directory+l)

        if self.args.verbose is True:
            print '[+] Lookup Values: '+', '.join(self.lookup_list)

        #check for a supplied client name and exit if none provided
        if self.args.client is None:
            print('\n[!] Client name required, please provide with -C <Clientname>\n')
            sys.exit(0)
        else:
            #strip out specials in client name
            self.client_name = re.sub('\W+', ' ', self.args.client).lower()

        #check for database, create if missing
        if not os.path.exists(self.autosint_db):
            print('\n[!] Database missing, creating {} \n'.format(self.autosint_db))
            self.database_commands_module = DatabaseCommands(self.client_name)
            self.initialize_database.createdatabase()

    def run_queries(self):
        """check arguments and run query if supplied"""
        #call function if -w arg
        if self.args.whois is True:
            self.whois_result = self.whois_query_module.run(self.args, self.lookup_list, self.report_directory)

        #call function if -n arg
        if self.args.nslookup is True:
            self.dns_result = self.dns_query_module.run(self.args, self.lookup_list, self.report_directory)

        #call function if -b arg
        if self.args.hibp is True:
            self.haveibeenpwned_result = self.haveibeenpwned_api_module.run(self.args, self.lookup_list, self.report_directory)

        #call function if -g arg

        if self.args.googledork is None:
            #print ('[!] Please provide arguments for google dorking. e.g -g inurl:apsx')
            #sys.exit(0)

            #self.args.googledork = 'password'
            #print('[!] no google dork arg used, defaulting to "%s"' % self.args.googledork)
            pass
        else:
            self.google_dork_result = self.google_dork_module.run(self.args, self.lookup_list, self.report_directory)

        #call function if -s arg
        if self.args.shodan is True:
            self.shodan_query_result = self.shodan_search_module.run(self.args, self.lookup_list, self.report_directory, self.api_key_directory)

        #call function if -p arg
        if self.args.pastebinsearch is None:
            #print ('[!] Please provide arguments for pastebin keywords. e.g -p password id_rsa')
            #sys.exit(0)
            pass
        else:
            self.pastebin_scrape_urls_result = self.pastebin_scrape_module.run(self.args, self.lookup_list, self.report_directory, self.api_key_directory)

        # call function if -t arg
        if self.args.theharvester is True:
            self.theharvester_module_result = self.theharvester_module.run(self.args, self.lookup_list, self.report_directory)

        #call function if -c arg 
        if self.args.creds is True:
            self.cred_leak_search_result = self.cred_leaks_module.run(self.args, self.lookup_list, self.start_time, self.report_directory)

        #call function if -S arg
        if self.args.scraper is True:
            self.scrape_result = self.web_scraper_module.run(self.args, self.lookup_list, self.report_directory, self.api_key_directory)

        #call function if -f arg
        if self.args.foca is True:
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

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument('-a', '--all', \
        help='run All queries', \
        action='store_true')
    
    parser.add_argument('-b', '--hibp', \
        help='Search haveibeenpwned.com for breaches related to a domain', \
        action='store_true')
    
    parser.add_argument('-C', '--client', \
        metavar='FooCorp',\
        help='Supply the client full name.')
    
    parser.add_argument('-c', '--creds', \
        help='Search local copies of credential dumps', \
        action='store_true')
    
    parser.add_argument('-d', '--domain', \
        metavar='foo.com', \
        nargs=1, \
        help='the Domain you want to search.')
    
    parser.add_argument('-f', '--foca', \
        help='invoke pyfoca', \
        action='store_true')
    
    parser.add_argument('-g', '--googledork', \
        metavar='password id_rsa', \
        nargs='+', \
        help='query Google for supplied args that are treated as a dork. \
        i.e. -g password becomes a search for "password site:<domain>". \
        Combine terms inside of quotes like "site:rapid7.com inurl:aspx" ')
    
    parser.add_argument('-i', '--ipaddress', \
        nargs=1, \
        help='The IP address you want to search. Must be a valid IP. ')
    
    parser.add_argument('-n', '--nslookup',\
        help='Name query DNS for supplied -d or -i values. Requires a -d or -i value', \
        action='store_true')
    
    parser.add_argument('-p', '--pastebinsearch', \
        metavar='password id_rsa', \
        nargs='+', \
        help='Search google for <arg> site:pastebin.com. \
        Requires a pro account if you dont want to get blacklisted.')
    
    parser.add_argument('-s', '--shodan',\
        help='query Shodan, API keys stored in ./api_keys/', \
        action='store_true')
    
    parser.add_argument('-S', '--scraper', \
        help='Scrape pastebin, github, indeed, more to be added. API keys stored in ./api_keys/', \
        action='store_true')
    
    parser.add_argument('-t', '--theharvester', \
        help='Invoke theHarvester', \
        action='store_true')
    
    parser.add_argument('-v', '--verbose', \
        help='Verbose', \
        action='store_true')  
    
    parser.add_argument('-w', '--whois', \
        help='query Whois for supplied -d or -i values. Requires a -d value', \
        action='store_true')
        
    args = parser.parse_args()

    #run functions with arguments passed
    runAutosint = Autosint(args, parser)
    runAutosint.clear()
    runAutosint.banner()
    runAutosint.check_arguments()
    runAutosint.run_queries()
    runAutosint.report()
    
if __name__ == '__main__':
    main()
