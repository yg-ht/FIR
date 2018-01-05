# FIR
## Fast Initial Recon

This is a new project designed to automate early enumeration tasks.  It is designed for time-constrained penetration tests.  Needless to say, this isn't exactly subtle - so I wouldn't use it if you are trying to stay under the radar.

Probably not worth your time yet - best to wait for a version that does something ;-)

## Installation / dependancies

This project is written for Python2.7, so make sure you have the below dependencies installed:

- python-netaddr
- python-nmap
- python-texttable
- python readchar

On ubuntu-based distributions (including Kali) you can use:

    apt install python-netaddr python-nmap python-texttable
    pip install readchar
    #pip install asyncio

You will also need to have Metasploit in good working order as this script takes advantage of the MSFRPCd.

This script should auto-detect MSFRPC running status and start if required, otherwise, to run MSFRPCd you need something like:

    msfrpcd -U fir -P P455WORDh3r3 --ssl
    
## Future features (To do list)

To make this a minimum viable product for initial noisey recon the following must be in place:

- take user input for usernames, hostnames, domain names etc
- DNS enumeration
- null session enumeration
- enum4linux esq stuff
- smtp enum
- multi-thread prep for the below:
- nmap all remaining ports

## Thanks and acknowledgments

Thanks must go to the following people and code repositories as they have been invaluable in making this project:

- many many friends, who I'm sure want to remain nameless
- https://github.com/allfro/pymetasploit