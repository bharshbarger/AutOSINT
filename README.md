# AutOSINT
Tool to automate common osint tasks. Probably best run on Kali.



## Dependencies: 

###In your path: 
whois, host, git, theHarvester(https://github.com/laramies/theHarvester), pyFoca(https://github.com/altjx/ipwn)

###python modules: 
python-docx, shodan,  google 

### other files:

a hashcat style pot file(hash:plain), and whatever open source dumps you already have in format user:hash

## Installation:

    $ git clone https://github.com/bharshbarger/AutOSINT.git
    $ chmod +x AutOSINT.py
    $ pip install --upgrade pip (optional)

(if missing modules:)

https://github.com/achillean/shodan-python

    $ pip install shodan

https://pypi.python.org/pypi/google

    $ pip install google

https://python-docx.readthedocs.io/en/latest/user/install.html

    $ pip install python-docx

## Help 
usage: AutOSINT.py [-h] [-a] [-c] [-d DOMAIN [DOMAIN ...]] [-f]
                   [-g GOOGLEDORK [GOOGLEDORK ...]]
                   [-i IPADDRESS [IPADDRESS ...]] [-n]
                   [-p PASTEBINSEARCH [PASTEBINSEARCH ...]] [-s SHODAN]
                   [-S SCRAPER [SCRAPER ...]] [-t] [-v] [-w]

optional arguments:

  -h, --help            show this help message and exit
  
  -a, --all             run All queries
  
  -c, --creds           Search local copies of credential dumps
  
  -d DOMAIN [DOMAIN ...], --domain DOMAIN [DOMAIN ...]
                        the Domain(s) you want to search.
                        
  -f, --foca            invoke pyfoca
  
  -g GOOGLEDORK [GOOGLEDORK ...], --googledork GOOGLEDORK [GOOGLEDORK ...]
                        query Google for supplied args that are treated as a
                        dork. i.e. -g password becomes a search for "password
                        site:<domain>" no option defaults to "password"
                        
  -i IPADDRESS [IPADDRESS ...], --ipaddress IPADDRESS [IPADDRESS ...]
                        the IP address(es) you want to search. Must be a valid
                        IP.
                        
  -n, --nslookup        Name query DNS for supplied -d or -i values. Requires
                        a -d or -i value
                        
  -p PASTEBINSEARCH [PASTEBINSEARCH ...], --pastebinsearch PASTEBINSEARCH [PASTEBINSEARCH ...]
                        Search google for <arg> site:pastebin.com. Requires a
                        pro account if you dont want to get blacklisted.
                        
  -s SHODAN, --shodan SHODAN
                        query Shodan, optionally provide -s <apikey>
                        
  -S SCRAPER [SCRAPER ...], --scraper SCRAPER [SCRAPER ...]
                        Scrape pastebin, github, indeed, more to be added.
                        Args are scrape keywords if applicable
                        
  -t, --theharvester    Invoke theHarvester
  
  -v, --verbose         Verbose
  
  -w, --whois           query Whois for supplied -d or -i values. Requires a
                        -d or -i value
