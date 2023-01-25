#!/bin/bash

apt-get update

apt-get install python3-nmap python3-termcolor python3-prettytable python3-builtwith python3-requests python3-beautifulsoup4 python3-colorama python3-whois python3-socket

apt-get install python3-pip

pip3 install --upgrade pip

pip3 install nmap termcolor prettytable builtwith requests beautifulsoup4 colorama python-whois

sudo mv samoom.py /usr/local/bin/

sudo chmod +x /usr/local/bin/samoom.py

sudo ln -sf /usr/local/bin/samoom.py /usr/local/bin/samoom
