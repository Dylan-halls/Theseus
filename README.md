# Theseus

This tool is designed to make it super easy for you to directly inject content into a victims web session

# How it works

Theseus uses an arp cache poison to redirect the victims traffic to the attackes box then will configue
iptables from you so all you have to do is give it a couple of IPs and you content to inject!

It has a HTTP proxy running on port 9000 meaning that the victim will connect to this thinking its the real
server, from here you have a choice how you want to mess with the content.
SSL isn't much of a problem because there is a SSL proxy running on port 4444 this will recive a connect request
from the browser and then will reply with a 200 OK, then the victims browser will send the encrypted data to the
proxy, it will just keep hold of it so that if any thing the browser will get a time out error rather that a scarey
encryption error.

# Future

In the future theseus will also run a DNS server so it can then fully convince the browser that the SSL proxy is
the real deal and therefore open up communication with it
