[![Build Status](https://travis-ci.org/Dylan-halls/Theseus.svg?branch=master)](https://travis-ci.org/Dylan-halls/Theseus)
# Theseus v1.2

## Introduction

Theseus is a Man-In-The-Middle (MITM) attack tool that is capable of hijacking HTTP sessions and then forcing html, css, javacript, images on to the target's browser screen.

With this tool you will not have to worry about having to setup the arpspoof or dnspoof yourself - Theseus will even get the targets mac address for you!

## Installation

First you need to clone a copy of the code to your local machine:

    $ git clone git@github.com:Dylan-halls/Theseus.git

Then you will need to install the dependecies for Theseus by running:
    
    $ chmod +x configure
    $ ./configure
    
## Running Theseus

To attack a target all you need to know is their IP address, which can be easily obtained with a simple nmap scan of the network or an arp netdiscover scan:

    $ nmap 192.168.1.*
    $ netdiscover

Once you have your targets IP address you can now run Theseus against them.

### Options

Some of the unrequired options are:

    --arp-ping 
This command will send a discreet arp ping to the victim before it starts the attack in order to gain its mac address

    --force-content
This command will tell Theseus to open up the server/Payloads dircetory as the root of the webserver and therefore
will force any website inside this folder onto the victims. The main file must be called 'payload.html' so Theseus knows
wich file to send first

    --spoof
This command accepts one argument either 'arp, icmp, dhcp' (only arp is working currently) and will tell Theseus how to become the mitm

    --gateway
This will tell Theseus the gateway ip addres to attack

## Execution

    python3 Theseus.py --target <target ip address> --arp-ping --iface <interface> --force-content --spoof arp --gateway <gateway ip address>
