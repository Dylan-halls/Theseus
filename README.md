# Theseus 1.1
https://travis-ci.org/Dylan-halls/Theseus.svg?branch=master

## Introduction

Theseus is a MITM attack tool that is capable of hijacking HTTP sessions and then forcing html, css, javacript, images, etc
on to the targets browser screen.

With this tool you wont have to worry about having to setup the arpspoof or dnspoof your self (Theseus will even get the targets mac address for you)

## Installation

First you need to clone a copy of the code to you local machine

    $ git clone https://github.com/Dylan-halls/Theseus/
    
Now you have a copy you have the choice to either use the defult payloads of use your own. To make your own basic payload all you need is a basic knowledge of html or javascript. For more complex payloads you can since Theseus acts like a legitimate HTTP server you can server up a fully functional html, css, javascript website

    $ cd src/server/Payloads/

## Running Theseus

To attack a target all you need to know is there ip address, which can be easily obtained with a simple nmap scan of the network or an arp netdiscover scan

    $ nmap 192.168.1.*
    $ netdiscover

once you have your targets IP address you can now run Thesues against them.

- use -h/--help for a list of additional switches
- use -t/--target for the targets ip
- use the -i/--interface for your current interface

And for execution
    
    $ python3 Theseus.py --target 192.168.1.208 --interface wlan0
    
## How it works


