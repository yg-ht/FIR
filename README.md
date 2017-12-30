# FIR
## Fast Initial Recon

This is a new project designed to automate early enumeration tasks.

Probably not worth your time yet - best to wait for a version that does something ;-)

This project is written for Python2.7, so make sure you have the below dependencies installed:

- netaddr
- nmap

On ubuntu-based distributions you can use:

    sudo apt install python-netaddr python-nmap
    
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