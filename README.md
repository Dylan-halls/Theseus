[![Build Status](https://travis-ci.org/Dylan-halls/Theseus.svg?branch=master)](https://travis-ci.org/Dylan-halls/Theseus)
# Theseus v1.1

## Introduction

Theseus is a Man-In-The-Middle (MITM) attack tool that is capable of hijacking HTTP sessions and then forcing html, css, javacript, images on to the target's browser screen.

With this tool you will not have to worry about having to setup the arpspoof or dnspoof yourself - Theseus will even get the targets mac address for you!

## Installation

First you need to clone a copy of the code to your local machine:

    $ git clone https://github.com/Dylan-halls/Theseus/
    
Now you have a copy you have the choice to either use the default payloads or use your own. To make your own basic payload all you need is a basic knowledge of html or javascript. Theseus acts like a legitimate HTTP server therefore for more complex payloads you can serve up a fully functional html, css, javascript website:

    $ cd src/server/Payloads/

## Running Theseus

To attack a target all you need to know is their IP address, which can be easily obtained with a simple nmap scan of the network or an arp netdiscover scan:

    $ nmap 192.168.1.*
    $ netdiscover

Once you have your targets IP address you can now run Theseus against them.

- use -h/--help for a list of additional switches
- use -t/--target for the targets ip
- use the -i/--interface for your current interface

...and for execution:
    
    $ python3 Theseus.py --target 192.168.1.208 --interface wlan0
    
## How it works

1. First Theseus will configue iptables on your machine, to redirect all victims traffic to the right services on the right port

2. Second Theseus will read the 'theseus.cfg' file in order to be able to get vital infomation that it needs about the machine, like its local ip address and the correct paths to the payloads

3. Third Theseus will start-up the dns server on port 53, the dns server starts up early because it is being ran on its own separate porocces and there for won't clash with the HTTP server on anything

4. Thesues will now send out an arp request on a broudcast mac address (FF:FF:FF:FF:FF:FF) for the targets mac so therefore the entire network will see this and then it will respond with the targets mac address

5. The second it recives the mac address it will begin the arp cache poison stage of the attack, this is used in order to get all of the targets traffic being sent to the outside world to go to us. This is the crux of the attack. In the future Theseus should be able to support icmp redirect spoofing and dhcp spoofing to give the it a bit more functionality

6. Now Theseus will start the HTTP server and then begin the attack. The first part of hijacking the session is that it will sniff for DNS traffic, when it does find some it will decode the packet and then craft a DNS responce, this will enable the target to have its DNS cache posined with the HTTP servers ip address. In version 1.0 Theseus didn't have a DNS spoof functunality and therefore only have a 50% success rate, beacuse the browser knew the real ip address of the web server so therefore made the HTTP servers job alot harder. Once the HTTP server has a connection it will use the user-agents library to be able to class the targets device by its user agent header and then it will send the payload.html file then sit back and just send any requested files after that.
