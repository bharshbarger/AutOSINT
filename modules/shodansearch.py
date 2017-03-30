#!/usr/bin/env python
from shodan import Shodan
import os
import sys


class Shodansearch():

	def run(self, args, lookup, reportDir, apiKeyDir):


		#probably need to customize search type based on -i or -d		
		#first if  https://shodan.readthedocs.io/en/latest/tutorial.html#connect-to-the-api
		#else https://shodan.readthedocs.io/en/latest/tutorial.html#looking-up-a-host

		#list that we'll return
		shodanResult = []
		shodanApiKey=''

		#check for api key file
		if not os.path.exists(apiKeyDir + 'shodan.key'):
			print '[-] You are missing %s/shodan.key' % apiKeyDir
			#shodanApiKey=raw_input("Please provide an API Key: ")

		#read API key
		try:
			with open(apiKeyDir + 'shodan.key', 'r') as apiKeyFile:
				for k in apiKeyFile:
					shodanApiKey = k
		except:
			print '[-] Error opening %s/shodan.key key file, skipping. ' % apiKeyDir

		#invoke api with api key provided

		shodanApi = Shodan(shodanApiKey)

		#roll through the lookup list from -i or -d
		for i, l in enumerate(lookup):
			#open output file
			shodanFile=open(reportDir+l+'/'+l+'_shodan.txt','w')



			#maybe just do the rest here instead of py api client?
			#url='https://exploits.shodan.io/api/search?query='+str(l)+'&key='+str(shodanApiKey)


			#user notification that something is happening
			print '[+] Querying Shodan via API search for ' + l
			try:
				#set results to api search of current lookup value
				#https://shodan.readthedocs.io/en/latest/examples/basic-search.html
				result = shodanApi.search(query="hostname:"+l)
				print '[+] Shodan found: '+str(result['total'])+' hosts'
				#for each result
				for service in result['matches']:
					if args.verbose is True:print str(service['ip_str'].encode('utf-8')+\
						' ISP: '+service['isp'].encode('utf-8')+\
						' Last seen: '+service['timestamp'].encode('utf-8'))
					if args.verbose is True:print service['data'].encode('utf-8')

					#append to shodanResult list
					shodanResult.append(str(\
						service['ip_str'].encode('utf-8')+\
						'\nISP:'+service['isp'].encode('utf-8')+\
						'\nLast seen:'+service['timestamp'].encode('utf-8'))+\
						'\n'+service['data'].encode('utf-8'))				



				'''exploits=shodanApi.exploits.search(l)
				for ex in exploits:
					shodanResult.append(str(ex))'''
			#catch exceptions		
			except shodan.APIError, e:
				#print excepted error
				print '[-] Shodan Error: %s' % e + ' Skipping!!!'
				print '[!] You may need to specify an API key with -s <api key>'
				return
				
		#write contents of shodanResult list. this needs formatted
		shodanFile.writelines('[+] Shodan found: '+str(result['total'])+' hosts\n\n')
		shodanFile.writelines(shodanResult)

		return shodanResult
