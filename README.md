# AutOSINT
Tool to automate common osint tasks. Probably best run on Kali, but tested on Debian 8.

## Dependencies: 

### In your path: 
whois, host, git, theHarvester(https://github.com/laramies/theHarvester), pyFoca(https://github.com/altjx/ipwn)

### python modules: 
python-docx, shodan,  google, pypdf (for pyFoca) 

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

    usage: AutOSINT.py [-h] [-c FooCorp] [-d foo.com] [-v] DORKS [DORKS ...]
    
    positional arguments:
      DORKS                 user supplied dorks
    
    optional arguments:
      -h, --help            show this help message and exit
      -c FooCorp, --client FooCorp
                            The name you want to call target domain owner's name.
      -d foo.com, --domain foo.com
                        The Domain you want to search.
      -v, --verbose         Verbosity option. Mainly just dumps all output to the
                            screen.
