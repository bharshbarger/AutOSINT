#!/usr/bin/env python
try:
	import os
except ImportError as e:
	raise ImportError('Error importing %s' % e)

class Credleaks():

	def run(self, args, lookup, startTime, reportDir):
		#grep through local copies of various password database dumps. 
		#compares to a hashcat potfile as well
		#you'll need a ./credleaks directory and a ./potfile directory populated
		#dumps need to be in uname:hash format
		#this could probably stand to be multi threaded

		potfileDir = './potfile'
		credLeakDir = './credleaks'

		if args.creds is True:

			if not os.path.exists(potfileDir):
				print '[-] The potfile directory is missing. Symlink your location to ./potfile and see if that works'
				return
			

			if not os.path.exists(credLeakDir):
				print '[-] The credleaks directory is missing. Symlink your location to ./credleaks and see if that works'
				return


		
			#for each domain/ip provided
			for l in lookup:
				credFile=open(reportDir+l+'/'+l+'_creds.txt','w')

				#init dictionary
				dumpDict={}
				credResult=[]


				print '[+] Searching credential dumps for entries that contain '+l
				#overall, take the lookup value (preferably a domain) and search the dumps for it
				#for each file in ./credleaks directory
				#really need to get this data out of text files an into an indexed form. it's slow af 
				for credFileName in os.listdir('./credleaks/'):
					#open the file
					credFileOpen = open('./credleaks/'+credFileName, "r")
					j=0
					#i=0
					#for each line in opened file
					for line in credFileOpen:
						#line counter index. i thought maybe i could also display how many lines were searched
						#i=i+1
						#regex search for our current lookup value l
						#if re.search((str(l)), line):
						if str(l) in line:
							#counter index
							j=j+1
							#look for a colon delimiter. dump files should be like email:hash. this of course assumes the creds file has emails as usernames
							if ':' in line:
								#split matches based on colons, sorta like 'awk -F :'. emails shouldnt have colons, right?
								#split on colons and only maxsplit 1
								matchedLine=line.split(":",1)
								#take the split parts, 0 and 1 that are uname and hash, respectively
								#place into a dict and strip the \r\n off of them
								dumpDict[str(matchedLine[1].rstrip("\r\n"))]=str(matchedLine[0].rstrip("\r\n"))
							#otherwise print xxx if theres no hash for the entry. some dumps dont have hashes for everyone...
							else:
								dumpDict['xxx']=str(line.rstrip("\r\n"))
					#print each file searched and how many matches if verbose
					if args.verbose is True: 
						print '[i] Searched ' + str(credFileName)+' and found '+ str(j)

				
				#print hash and user of files if verbose	
				if args.verbose is True:
					for h, u in dumpDict.items():
						print(str(u)) 

				#start printing stuff and appending to credResult
				print '[+] Searching Local Credential Dumps in ./credleaks against potfile in ./potfile '
				credFile.writelines('********EMAILS FOUND BELOW********\n\n\n\n')
				credResult.append('********EMAILS FOUND BELOW********\n\n\n\n')
				
				#iterate the dictionary containing user and hashes
				for h, u in dumpDict.items():
					#write username to text file
					credFile.writelines(str(u)+'\n')
					#write username to credResult for the docx report
					credResult.append(str(u)+'\n')
					
				credFile.writelines('********CREDENTIALS FOUND BELOW*********\n\n\n\n')
				credResult.append('********CREDENTIALS FOUND BELOW*********\n\n\n\n')
				
				#this section 'cracks' the hashes provided a pre-populated pot file
				#still in our lookup value iterate potfiles directory. you can have multiple pots, just in case
				for potFileName in os.listdir('./potfile/'):
					#open a pot file
					with open('./potfile/'+potFileName, 'r') as potFile:
						#tell user you are looking
						print '[i] Any creds you have in your potfile will appear below as user:hash:plain : '
						#then look at every line
						for potLine in potFile:
							#then for every line look at every hash and user in the dict
							for h, u in dumpDict.items():
								#if the hash in the dict matches a line in the potfile
								#that is also the same length as the original hash (this is probably a crappy check tho...)
								if str(h) == str(potLine[0:len(h)]):
									#print the user: and the line from the potfile (hash:plain) to the user
									print str(u)+':'+str(potLine.rstrip("\r\n"))
									#need to append the output to a variable to return or write to the file
									#this is separate because not all found usernames/emails have hashes and not all hashes are cracked
									#write to text file
									credFile.writelines(str(u)+':'+str(potLine[len(h):]))
									#add to credResult for docx report
									credResult.append(str(u)+':'+str(potLine[len(h):]))


				return credResult	
				print credResult
