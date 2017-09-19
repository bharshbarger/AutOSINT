#!/usr/bin/env python
"""module to run the harvester"""
import subprocess

class Theharvester():
    """module class"""
    def __init__(self):
        #init lists
        self.theharvester_result = []
        self.harvester_sources = 'google, linkedin'
    
    def run(self, args, lookup, report_directory):
        """main function"""
        #based on domain or ip, enumerate with index and value
        for i, l in enumerate(lookup):
            #open file to write to
            harvesterFile = open(report_directory+l+'/'+l+'_theharvester.txt', 'w')
            for source in self.harvester_sources:
                try:
                    print('[+] Running theHarvester -b google -d {} '.format(l))
                    bash_command = subprocess.Popen(['theharvester', '-b', '{}'.format(source), '-d', str(l), '-l', '500', '-h'], stdout=subprocess.PIPE).communicate()[0].split('\r\n')
                except:
                    print('[-] Error running theHarvester. Make sure it is in your PATH and you are connected to the Internet')
                    self.theharvester_result.append('Error running theHarvester')
                    continue
            #append lists together
            self.theharvester_result.append(bash_command)
            #append resutls and write to lookup result file
            for r in self.theharvester_result:
                harvesterFile.writelines(r)
        #verbosity
        if args.verbose is True:
            for h in self.theharvester_result:
                print(''.join(h))
        #return list object
        return self.theharvester_result
