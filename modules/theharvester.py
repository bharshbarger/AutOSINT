#!/usr/bin/env python

import subprocess

class Theharvester():
    """module to use theharvester"""
    def run(self, args, lookup, reportDir):
        """main function"""
        #init lists
        theharvester_result = []

        #based on domain or ip, enumerate with index and value
        for i, l in enumerate(lookup):
            #open file to write to
            harvesterFile = open(reportDir+l+'/'+l+'_theharvester.txt','w')
            #run harvester with -b google on lookup
            try:
                print ('[+] Running theHarvester -b google -d {} '.format(l))
                harvesterGoogleCmd = subprocess.Popen(['theharvester', '-b', 'google', '-d', str(l), '-l', '500', '-h'], stdout=subprocess.PIPE).communicate()[0].split('\r\n')
            except:
                print ('[-] Error running theharvester. Make sure it is in your PATH and you are connected to the Internet')
                theharvester_result.append('Error running theHarvester')
                continue

            #run harvester with -b linkedin on lookup
            try:
                print ('[+] Running theHarvester -b linkedin -d {} '.format(l))
                harvesterLinkedinCmd = subprocess.Popen(['theharvester', '-b', 'linkedin', '-d', str(l), '-l', '500', '-h'], stdout=subprocess.PIPE).communicate()[0].split('\r\n')
            except:
                print ('[-] Error running theharvester. Make sure it is in your PATH and you are connected to the Internet')
                theharvester_result.append('Error running theHarvester\n')
                continue

            #append lists together
            theharvester_result.append(harvesterGoogleCmd)
            theharvester_result.append(harvesterLinkedinCmd)

            #append resutls and write to lookup result file
            for r in theharvester_result:
                harvesterFile.writelines(r)
        #verbosity
        if args.verbose is True:
            for h in theharvester_result:print (''.join(h))
        #return list object
        return theharvester_result