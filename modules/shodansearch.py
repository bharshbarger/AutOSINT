#!/usr/bin/env python
"""module to query shodan via api"""
import os
from shodan import Shodan
import sys

class Shodansearch():

    def __init__(self):

        #defaults
        self.shodan_query_result = []
        self.shodan_api_key = ''

    def run(self, args, lookup, report_directory, api_key_directory):

        #probably need to customize search type based on -i or -d       
        #first if  https://shodan.readthedocs.io/en/latest/tutorial.html#connect-to-the-api
        #else https://shodan.readthedocs.io/en/latest/tutorial.html#looking-up-a-host
        #check for api key file
        if not os.path.exists(api_key_directory + 'shodan.key'):
            print ('[!] You are missing {}shodan.key'.format(api_key_directory))
            
            api_key_value=raw_input("Please provide an API Key: ")
            
            response=raw_input('Would you like to save this key to a file? (y/n): ')
            if 'y' in response.lower():
                with open(api_key_directory + 'shodan.key', 'w') as api_key_file:
                    api_key_file.writelines(api_key_value)
            else:
                pass

        #read API key
        try:
            with open(api_key_directory + 'shodan.key', 'r') as api_key_file:
                for k in api_key_file:
                    api_key_value = k
        except:
            print ('[-] Error opening {}/shodan.key key file, skipping. '.format(api_key_directory))

        #invoke api with api key provided

        shodanApi = Shodan(api_key_value)

        #roll through the lookup list from -i or -d
        for i, l in enumerate(lookup):
            #open output file
            shodan_text_output=open(report_directory+l+'/'+l+'_shodan.txt','w')

            #maybe just do the rest here instead of py api client?
            #url='https://exploits.shodan.io/api/search?query='+str(l)+'&key='+str(api_key_value)

            #user notification that something is happening
            print ('[+] Querying Shodan via API search for {}'.format(l))
            try:
                #set results to api search of current lookup value
                #https://shodan.readthedocs.io/en/latest/examples/basic-search.html
                result = shodanApi.search(query="hostname:"+l)
                
                print ('[+] Shodan found: {} hosts'.format(str(result['total'])))
                
                #for each result
                for service in result['matches']:
                    
                    if args.verbose is True:
                        
                        print (str(service['ip_str'].encode('utf-8')+\
                            ' ISP: '+service['isp'].encode('utf-8')+\
                            ' Last seen: '+service['timestamp'].encode('utf-8')))
                    
                    if args.verbose is True:
                        print (service['data'].encode('utf-8'))

                    #append to shodanResult list
                    self.shodan_query_result.append(str(\
                        service['ip_str'].encode('utf-8')+\
                        '\nISP:'+service['isp'].encode('utf-8')+\
                        '\nLast seen:'+service['timestamp'].encode('utf-8'))+\
                        '\n'+service['data'].encode('utf-8'))               

                '''exploits=shodanApi.exploits.search(l)
                for ex in exploits:
                    shodanResult.append(str(ex))'''
            #catch exceptions       
            except Exception as e:
                #print excepted error
                print ('[-] Shodan Error: {} '.format(e))
                print ('[!] You may need to specify an API key with -s <api key>')
                return
                
        #write contents of shodanResult list. this needs formatted
        shodan_text_output.writelines('[+] Shodan found: {} hosts\n\n'.format(str(result['total'])))
        shodan_text_output.writelines(self.shodan_query_result)

        return self.shodan_query_result
