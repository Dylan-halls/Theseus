# Theseus v1.1
[![Build Status](https://travis-ci.org/Dylan-halls/Theseus.svg?branch=master)](https://travis-ci.org/Dylan-halls/Theseus)

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


