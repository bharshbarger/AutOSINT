# AutOSINT
Tool to automate common osint tasks. Probably best run on Kali, but tested on Debian 8.

## Dependencies: 

### In your path: 
whois, host, git, theHarvester(https://github.com/laramies/theHarvester), pyFoca(https://github.com/altjx/ipwn)

### python modules: 
python-docx, shodan,  google 

### other files:

A hashcat style pot file(hash:plain), and whatever open source dumps you already have in format user:hash

## Installation:

    $ git clone https://github.com/bharshbarger/AutOSINT.git

### (if missing modules:)

https://github.com/achillean/shodan-python

    $ pip install shodan

https://pypi.python.org/pypi/google

    $ pip install google

https://python-docx.readthedocs.io/en/latest/user/install.html

    $ pip install python-docx
    
### Install all missing modules

    $ pip install -U -r requirements.txt 

## Help 
    usage: AutOSINT.py [-h] [-a] [-b] [-C CLIENT] [-c] [-d foo.com] [-f]
                       [-g password id_rsa [password id_rsa ...]] [-i IPADDRESS]
                       [-n] [-p password id_rsa [password id_rsa ...]] [-s] [-S]
                       [-t] [-v] [-w]

    optional arguments:
      -h, --help            show this help message and exit
      -a, --all             run All queries
      -b, --hibp            Search haveibeenpwned.com for breaches related to a
                            domain
      -C CLIENT, --client CLIENT
                            Supply the client full name, i.e. foo.com would map to
                            Foocorp
      -c, --creds           Search local copies of credential dumps
      -d foo.com, --domain foo.com
                            the Domain you want to search.
      -f, --foca            invoke pyfoca
      -g password id_rsa [password id_rsa ...], --googledork password id_rsa [password id_rsa ...]
                            query Google for supplied args that are treated as a
                            dork. i.e. -g password becomes a search for "password
                            site:<domain>". Combine terms inside of quotes like
                            "site:rapid7.com inurl:aspx"
      -i IPADDRESS, --ipaddress IPADDRESS
                            the IP address you want to search. Must be a valid IP.
      -n, --nslookup        Name query DNS for supplied -d or -i values. Requires
                            a -d or -i value
      -p password id_rsa [password id_rsa ...], --pastebinsearch password id_rsa [password id_rsa ...]
                            Search google for <arg> site:pastebin.com. Requires a
                            pro account if you dont want to get blacklisted.
      -s, --shodan          query Shodan, API keys stored in ./api_keys/
      -S, --scraper         Scrape pastebin, github, indeed, more to be added. API
                            keys stored in ./api_keys/
      -t, --theharvester    Invoke theHarvester
      -v, --verbose         Verbose
      -w, --whois           query Whois for supplied -d or -i values. Requires a
                            -d or -i value
