# FIR
## Fast Initial Recon

This is a new project designed to automate early enumeration tasks.

Probably not worth your time yet - best to wait for a version that does something ;-)

## Installation / dependancies

This project is written for Python2.7, so make sure you have the below dependencies installed:

- python-netaddr
- python-nmap
- python-texttable

On ubuntu-based distributions you can use:

    apt install python-netaddr python-nmap python-texttable

You will also need to have Metasploit in good working order as this script takes advantage of the MSFRPCd.

This script should auto-detect MSFRPC running status and start if required, otherwise, to run MSFRPCd you need something like:

    msfrpcd -U fir -P P455WORDh3r3 --ssl
    
## Future features (To do list)

To make this a minimum viable product for initial noisey recon the following must be in place:

- take user input for usernames, hostnames, domain names etc
- multi-thread prep for the below:
- nbtscan
- DNS enumeration
- null session enumeration
- enum4linux
- smbdisco
- smtp enum
- nmap all remaining ports
- display table of results

## Thanks and acknowledgments

The following people and code repositories have been invaluable in making this project:

- https://github.com/allfro/pymetasploit