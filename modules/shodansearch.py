#!/usr/bin/env python
"""module to query shodan via api"""
import getpass
import os
from shodan import Shodan
import sys

class Shodansearch():
    """shodan api search module"""

    def __init__(self):
        """init"""
        #defaults
        self.shodan_query_result = []
        self.shodan_api_key = None
        self.api_key_value = None

    def run(self, args, lookup, report_directory, api_key_directory):
        """main function"""
    
        #first if  https://shodan.readthedocs.io/en/latest/tutorial.html#connect-to-the-api
        #else https://shodan.readthedocs.io/en/latest/tutorial.html#looking-up-a-host

        #check for a stored api key
        if not os.path.exists(api_key_directory + 'shodan.key'):
            print('[!] You are missing {}shodan.key'.format(api_key_directory))
            self.api_key_value = getpass.getpass('[i] Please provide an API Key: ')
            response = raw_input('[i] Would you like to save this key to a file? (y/n): ')
            
            if 'y' in response.lower():
                with open(api_key_directory + 'shodan.key', 'w') as api_key_file:
                    api_key_file.writelines(self.api_key_value)
            else:
                pass

        with open(api_key_directory + 'shodan.key') as f:
            self.api_key_value = f.readlines()[0]

        #invoke api with api key provided
        shodanApi = Shodan(self.api_key_value)

        #roll through the lookup list from -i or -d
        for i, l in enumerate(lookup):
            #open output file
            shodan_text_output=open(report_directory+l+'/'+l+'_shodan.txt','w')
            #user notification that something is happening
            print('[+] Querying Shodan via API search for {}'.format(l))
            try:
                #set results to api search of current lookup value
                #https://shodan.readthedocs.io/en/latest/examples/basic-search.html
                result = shodanApi.search(query="hostname:"+l)
                print('[+] Shodan found: {} hosts'.format(str(result['total'])))
                #for each result
                for service in result['matches']:
                    if args.verbose is True:
                        print(str(service['ip_str'].encode('utf-8')+\
                            ' ISP: '+service['isp'].encode('utf-8')+\
                            ' Last seen: '+service['timestamp'].encode('utf-8')))
                    if args.verbose is True:
                        #print and encode if there are non-us chars
                        print(service['data'].encode('utf-8'))
                    #append to shodanResult list
                    self.shodan_query_result.append(str(\
                        service['ip_str'].encode('utf-8')+\
                        '\nISP:'+service['isp'].encode('utf-8')+\
                        '\nLast seen:'+service['timestamp'].encode('utf-8'))+\
                        '\n'+service['data'].encode('utf-8'))               

            #catch exceptions       
            except Exception as e:
                #print excepted error
                print('[-] Shodan Error: {} '.format(e))
                print('[!] You may need to specify an API key with -s <api key>')
                return
                
        #write contents of shodanResult list. this needs formatted
        shodan_text_output.writelines('[+] Shodan found: {} hosts\n\n'.format(str(result['total'])))
        shodan_text_output.writelines(self.shodan_query_result)

        return self.shodan_query_result
