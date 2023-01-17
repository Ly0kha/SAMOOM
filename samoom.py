import nmap
from termcolor import colored
from prettytable import PrettyTable
import builtwith 
import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style
import whois
import socket

##
def print_logo():
    logo = """
  /$$$$$$   /$$$$$$  /$$      /$$  /$$$$$$   /$$$$$$  /$$      /$$
 /$$__  $$ /$$__  $$| $$$    /$$$ /$$__  $$ /$$__  $$| $$$    /$$$
| $$  \__/| $$  \ $$| $$$$  /$$$$| $$  \ $$| $$  \ $$| $$$$  /$$$$
|  $$$$$$ | $$$$$$$$| $$ $$/$$ $$| $$  | $$| $$  | $$| $$ $$/$$ $$
 \____  $$| $$__  $$| $$  $$$| $$| $$  | $$| $$  | $$| $$  $$$| $$
 /$$  \ $$| $$  | $$| $$\  $ | $$| $$  | $$| $$  | $$| $$\  $ | $$
|  $$$$$$/| $$  | $$| $$ \/  | $$|  $$$$$$/|  $$$$$$/| $$ \/  | $$
 \______/ |__/  |__/|__/     |__/ \______/  \______/ |__/     |__/
                                                                  
"""
    colored_logo = ""
    for line in logo.split("\n"):
        colored_logo += colored(line, "green") + "\n"
    print(colored_logo)
## 
def live_hosts_scan():
    ip_range = input("Enter the IP range to scan (e.g. 192.168.1.0/24): ")
    nm = nmap.PortScanner()
    nm.scan(ip_range, arguments='-p 21,22,25,80')
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    live_hosts = []
    for host, status in hosts_list:
        if status == "up":
            open_ports = []
            for port in [21, 22, 25, 80]:
                if nm[host]['tcp'][port]['state'] == 'open':
                    open_ports.append(port)
            if open_ports:
                live_hosts.append((host, open_ports))
    print("Live Hosts:")
    table = PrettyTable()
    table.field_names = ["Host IP", "Open Ports"]
    for host, ports in live_hosts:
        table.add_row([host, ports])
    print(table)
    #

#whois lookup

def whois_whois(domain):
    ip = None
    try:
        ip = socket.gethostbyname(domain)
        print(Fore.GREEN + f"DNS: {domain} - IP: {ip}" + Style.RESET_ALL)
    except socket.gaierror:
        try:
            domain = socket.gethostbyaddr(domain)[0]
            ip = socket.gethostbyname(domain)
            print(Fore.GREEN + f"DNS: {domain} - IP: {ip}" + Style.RESET_ALL)
        except socket.herror:
            print(Fore.RED + f"{domain} is not a valid domain or IP address." + Style.RESET_ALL)
            return
    try:
        w = whois.whois(domain)
        table = PrettyTable()
        table.field_names = [Fore.GREEN + "Property" + Style.RESET_ALL, Fore.GREEN + "Value" + Style.RESET_ALL]
        table.add_row([Fore.GREEN + "Registrant" + Style.RESET_ALL, w.registrant])
        table.add_row([Fore.GREEN + "Registrar" + Style.RESET_ALL, w.registrar])
        table.add_row([Fore.GREEN + "Creation Date" + Style.RESET_ALL, w.creation_date])
        table.add_row([Fore.GREEN + "Expiration Date" + Style.RESET_ALL, w.expiration_date])
        table.add_row([Fore.GREEN + "Name servers" + Style.RESET_ALL , w.name_servers])
        print(table)
    except Exception as e:
        print(e)
#
def website_tech_scan():
    url = input("Enter the URL to scan: ")
    if not url.startswith("http"):
        url = "http://" + url
    technologies = builtwith.parse(url)
    table = PrettyTable()
    table.field_names = ["Technology", "Version"]
    for tech, versions in technologies.items():
        for version in versions:
            table.add_row([tech, version])
    print(table)
#
def search_subdomains(main_domain):
    subdomains = []
    search_url = f"https://www.google.com/search?q=site%3A*.{main_domain}"
    response = requests.get(search_url)
    soup = BeautifulSoup(response.text, 'html.parser')
    for link in soup.find_all('a'):
        url = link.get('href')
        if '/url?q=' in url:
            url = url.split('/url?q=')[1]
            if url.startswith(f"http"):
                subdomain = url.split(".")[0]
                if subdomain not in subdomains:
                    subdomains.append(subdomain)
    table = PrettyTable()
    table.field_names = ["Subdomains"]
    table.align = "c"
    for subdomain in subdomains:
        table.add_row([f"{subdomain}.{main_domain}"])
    print(table)
    print(colored("Please note that this search result is only based on Google search results. If you are looking for a more in-depth search, it is recommended to use another alternative tool.", "red", attrs=["bold"]))




#
def scan_ports():
    host = input("Enter the host IP to scan: ")
    common_ports = "20,21,22,25,53,80,137,139,443,1433,1434,3306,3389,8080,8443,5431"
    nm = nmap.PortScanner()
    nm.scan(host, f'{common_ports}')
    open_ports = []
    for port in nm[host]['tcp']:
        if nm[host]['tcp'][port]['state'] == 'open':
            open_ports.append(port)
    if open_ports:
        print("\nAll ports listed below are open:")
        table = PrettyTable()
        table.field_names = ["Port", "Status", "Service","Version"]
        for port in open_ports:
            state = nm[host]['tcp'][port]['state']
            service = nm[host]['tcp'][port]['name']
            version = nm[host]['tcp'][port]['version']
            table.add_row([port, state, service, version])
        print(table)
    else:
        print("No open ports found.")



# #
def main():
    while True:
        try:
            print_logo()
            print(Fore.CYAN + "SAMOM - Simple Automated Multi-purpose Offensive Manager" + Style.RESET_ALL)
            print("Please choose an option:")
            print(Fore.GREEN + "1- Port Scanning" + Style.RESET_ALL)
            print(Fore.GREEN + "2- Live Hosts Scanning" + Style.RESET_ALL)
            print(Fore.GREEN + "3- Website technologies Scanning" + Style.RESET_ALL)
            print(Fore.GREEN + "4- Search for Subdomains" + Style.RESET_ALL)
            print(Fore.GREEN + "5- WHOIS Lookup" + Style.RESET_ALL)
            print(Fore.RED + "6- Exit" + Style.RESET_ALL)
            choice = input()
            if choice == "1":
                scan_ports()
            elif choice == "2":
                live_hosts_scan()
            elif choice == "3":
                website_tech_scan()
            elif choice == "4":
                main_domain = input("Enter the main domain: ")
                search_subdomains(main_domain)
            elif choice == "5":
                domain = input("Enter the domain for WHOIS lookup: ")
                whois_whois(domain)
            elif choice == "6":
                break
            else:
                print(Fore.RED + "Invalid choice. Please try again." + Style.RESET_ALL)
        except KeyboardInterrupt:
            print(Fore.GREEN + "Exiting program..." + Style.RESET_ALL)
            break

if __name__ == '__main__':
    main()
