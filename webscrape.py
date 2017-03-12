#!/usr/bin/env python


class Scraper():


	def scrape_sites(args, lookup, reportDir, apiKeyDir):
		scrapeResult=[]
		userAgent = {'User-agent': 'Mozilla/5.0'}
		a=''
		indeedResult=[]
		githubResult=[]
		virusTotalResult=[]
		vtApiKey=''
		vtParams ={}

		if args.scraper is True:
			for i,l in enumerate(lookup):
				scrapeFile=open(reportDir+l+'/'+l+'_scrape.txt','w')

				print '[+] Scraping sites using '+ l
				#http://www.indeed.com/jobs?as_and=ibm.com&as_phr=&as_any=&as_not=&as_ttl=&as_cmp=&jt=all&st=&salary=&radius=25&fromage=any&limit=500&sort=date&psf=advsrch
				#init list and insert domain with tld stripped
				#insert lookup value into static urls
				scrapeUrls = {\
				'indeed':'http://www.indeed.com/jobs?as_and=%s&limit=500&sort=date' % (l.split('.')[0]),\
				'github':'https://api.github.com/search/repositories?q=%s&sort=stars&order=desc' % (l.split('.')[0]),#pull off the tld\
				#'glassdoor':'https://www.glassdoor.com/Reviews/company-reviews.htm?suggestCount=0&suggestChosen=false&clickSource=searchBtn&typedKeyword=%s&sc.keyword=%s&locT=&locId=' % (l.split('.')[0],l.split('.')[0]),\
				#'slideshare':'http://www.slideshare.net/%s' % (l.split('.')[0]),\
				'virustotal':'https://www.virustotal.com/vtapi/v2/domain/report',\
				'censys':'https://www.censys.io/api/v1'\
				#'':''\
				}

				for name,url in scrapeUrls.items():
					#indeed matches jobs. yeah yeah it doesnt use their api yet
					if name == 'indeed':
						if args.verbose is True:print '[+] Searching job postings on indeed.com for %s:' % l.split('.')[0]
						
						#http://docs.python-guide.org/en/latest/scenarios/scrape/
						try:
							ipage = requests.get(url, headers = userAgent)
						except:
							print '[-] Scraping error on ' + url +':'
							continue

						#build html tree
						itree = html.fromstring(ipage.content)

						#count jobs
						jobCount = itree.xpath('//div[@id="searchCount"]/text()')
						print '[+] '+str(''.join(jobCount)) + ' Jobs posted on indeed.com that match %s:' % (l.split('.')[0])
						jobTitle = itree.xpath('//a[@data-tn-element="jobTitle"]/text()')
						indeedResult.append('\n[+] Job postings on indeed.com that match %s \n\n' % l.split('.')[0])
						for t in jobTitle:
							indeedResult.append(t+'\n')

					#github matches search for user supplied domain
					#https://developer.github.com/v3/search/
					#http://docs.python-guide.org/en/latest/scenarios/json/
					if name == 'github':
						if args.verbose is True:print '[+] Searching repository names on Github for %s' % (l.split('.')[0])

						#http://docs.python-guide.org/en/latest/scenarios/scrape/
						try:
							gpage = requests.get(url, headers = userAgent)
						except:
							print '[-] Scraping error on ' + url +':'
							continue

						#read json response
						gitJson = gpage.json()
						
						#grab repo name from json items>index val>full_name
						githubResult.append('[+] Github repositories matching '+(l.split('.')[0])+'\n\n')
						for i,r in enumerate(gitJson['items']):
							githubResult.append(gitJson['items'][i]['full_name']+'\n')

					if name == 'virustotal':
						if not os.path.exists(apiKeyDir + 'virus_total.key'):
							print '[-] You are missing %s/virus_total.key' % apiKeyDir
							#vtApiKey=raw_input("Please provide an API Key: ")

						#read API key
						try:
							with open(apiKeyDir + 'virus_total.key', 'r') as apiKeyFile:
								for k in apiKeyFile:
									vtApiKey = k
						except:
							print '[-] Error opening %s/virus_total.key key file, skipping. ' % apiKeyDir
							continue


						if args.verbose is True: print '[+] VirusTotal domain report for %s' % l
						virusTotalResult.append('[+] VirusTotal domain report for %s' % l)

						vtParams['domain']=l 
						vtParams['apikey']=vtApiKey

						#per their api reference
						response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(vtParams))).read()

						#read json response
						vtJson = json.loads(response)
						#virusTotalResult.append(vtJson)



				#write the file
				for g in githubResult:
					scrapeFile.writelines(''.join(str(g.encode('utf-8'))))
				for i in indeedResult:
					scrapeFile.writelines(''.join(str(i.encode('utf-8'))))
						

				scrapeResult.append(indeedResult)
				scrapeResult.append(githubResult)	

				#verbosity logic
				if args.verbose is True:
					for gr in githubResult: print ''.join(gr.strip('\n'))
					for ir in indeedResult: print ''.join(ir.strip('\n'))

			return scrapeResult