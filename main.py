import os
import sys
import socket
import smtplib
import requests
import configparser
import argparse
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_network
from colorama import init, Fore, Style
from tqdm import tqdm
import subprocess
import webbrowser
import time

init(autoreset=True)

TELEGRAM_LINK = 'https://t.me/cwelplus'  

def clear_console():
    """Clears the console based on the operating system."""
    os.system('cls' if os.name == 'nt' else 'clear')

def open_telegram_link():
    """Opens the Telegram link in the default web browser."""
    webbrowser.open(TELEGRAM_LINK)

required_modules = ['colorama', 'requests', 'tqdm']

def install_missing_modules():
    """Install any missing Python modules."""
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            print(Fore.YELLOW + f"[!] Module '{module}' not found. Installing...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", module])

install_missing_modules()

import colorama
import requests
from tqdm import tqdm

logging.basicConfig(
    filename='scanner.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

config = configparser.ConfigParser()

if not os.path.exists('config.ini'):
    print(Fore.RED + "[!] config.ini not found. Please create one based on config_example.ini.")
    logging.error("config.ini not found. Exiting.")
    sys.exit(1)

config.read('config.ini')

IPINFO_TOKEN = config.get('API', 'ipinfo_token', fallback='')
HACKERTARGET_KEY = config.get('API', 'hackertarget_key', fallback='')
SMTP_PORTS = [int(port.strip()) for port in config.get('SCAN', 'smtp_ports', fallback='25,465,587,2525').split(',')]
THREADS = config.getint('SCAN', 'threads', fallback=100)
RATE_LIMIT = config.getfloat('SCAN', 'rate_limit', fallback=0.1)  

def fetch_ip_ranges(domain):
    print(Fore.CYAN + f"[+] Fetching IP ranges for domain: {domain}")
    logging.info(f"Fetching IP ranges for domain: {domain}")
    try:

        asn_response = requests.get(f"https://ipinfo.io/{domain}/json?token={IPINFO_TOKEN}")
        if asn_response.status_code != 200:
            print(Fore.RED + f"[-] Failed to get ASN for {domain}. Status Code: {asn_response.status_code}")
            logging.error(f"Failed to get ASN for {domain}. Status Code: {asn_response.status_code}")
            return []

        asn_info = asn_response.json()
        asn = asn_info.get('org', '').split(' ')[0]
        if not asn:
            print(Fore.RED + f"[-] ASN not found for {domain}.")
            logging.error(f"ASN not found for {domain}.")
            return []

        hackertarget_response = requests.get(f"https://api.hackertarget.com/aslookup/?q={asn}")
        if 'error' in hackertarget_response.text.lower():
            print(Fore.RED + f"[-] Error fetching IP ranges from hackertarget: {hackertarget_response.text}")
            logging.error(f"Error fetching IP ranges from hackertarget: {hackertarget_response.text}")
            return []

        ip_ranges = hackertarget_response.text.strip().split('\n')
        print(Fore.GREEN + f"[+] Retrieved {len(ip_ranges)} IP ranges for ASN: {asn}")
        logging.info(f"Retrieved {len(ip_ranges)} IP ranges for ASN: {asn}")
        return ip_ranges

    except Exception as e:
        print(Fore.RED + f"[-] Exception occurred while fetching IP ranges: {e}")
        logging.error(f"Exception occurred while fetching IP ranges: {e}")
        return []

def generate_hosts(ranges):
    hosts = []
    for ip_range in ranges:
        try:
            network = ip_network(ip_range, strict=False)
            for ip in network.hosts():
                hosts.append(str(ip))
        except ValueError as ve:
            print(Fore.YELLOW + f"[!] Invalid IP range '{ip_range}': {ve}")
            logging.warning(f"Invalid IP range '{ip_range}': {ve}")
    print(Fore.GREEN + f"[+] Generated {len(hosts)} hosts from IP ranges.")
    logging.info(f"Generated {len(hosts)} hosts from IP ranges.")
    return hosts

def check_smtp_ports(ip):
    open_ports = []
    for port in SMTP_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=2):
                open_ports.append(port)
        except (socket.timeout, ConnectionRefusedError, OSError):
            continue
    if open_ports:
        for port in open_ports:
            return f"{ip}:{port}"
    return None

def smtp_scan(ip_port):
    ip, port = ip_port.split(':')
    try:
        server = smtplib.SMTP(ip, int(port), timeout=5)
        server.ehlo_or_helo_if_needed()

        from_address = "test@example.com"
        to_address = "victim@example.com"
        subject = "SMTP Open Relay Test"
        body = f"SMTP Server Info:\nIP: {ip}\nPort: {port}\n\nThis is a test email to check for open relay."
        message = f"Subject: {subject}\n\n{body}"
        server.sendmail(from_address, to_address, message)
        server.quit()
        print(Fore.GREEN + f"[+] Open Relay Found: {ip}:{port}")
        logging.info(f"Open Relay Found: {ip}:{port}")
        return f"{ip}:{port}"
    except smtplib.SMTPException:
        print(Fore.RED + f"[-] SMTP server not open relay: {ip}:{port}")
        logging.info(f"SMTP server not open relay: {ip}:{port}")
        return None
    except Exception as e:
        print(Fore.YELLOW + f"[!] Error scanning {ip}:{port} - {e}")
        logging.error(f"Error scanning {ip}:{port} - {e}")
        return None

def parse_arguments():
    parser = argparse.ArgumentParser(
        description='SMTP Station - Advanced SMTP Scanner',
        epilog=f"Join our Telegram channel for support and updates: {TELEGRAM_LINK}",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-d', '--domain', type=str, help='Domain to perform ASN Lookup')
    parser.add_argument('-t', '--threads', type=int, default=THREADS, help='Number of concurrent threads (default: 100)')
    parser.add_argument('-p', '--ports', type=str, default=','.join(map(str, SMTP_PORTS)), help='Comma-separated list of SMTP ports to scan (default: 25,465,587,2525)')
    parser.add_argument('-r', '--rate', type=float, default=RATE_LIMIT, help='Rate limit in seconds between connections (default: 0.1)')
    parser.add_argument('-f', '--format', type=str, choices=['txt', 'json', 'csv'], default='txt', help='Output format for results (default: txt)')
    return parser.parse_args()

def main():

    clear_console()

    open_telegram_link()

    args = parse_arguments()

    global THREADS, SMTP_PORTS, RATE_LIMIT
    THREADS = args.threads
    SMTP_PORTS = [int(port.strip()) for port in args.ports.split(',')]
    RATE_LIMIT = args.rate

    print(Fore.MAGENTA + f"""
    ===============================================
               SMTP Station - Advanced SMTP Scanner
    ===============================================
    Join our Telegram channel for support and updates: {TELEGRAM_LINK}
    ===============================================
    """)
    logging.info("SMTP Station started.")

    if not os.path.exists('ranges.txt'):
        domain = args.domain if args.domain else input("Enter a domain to perform ASN Lookup: ").strip()
        if not domain:
            print(Fore.RED + "[-] No domain provided. Exiting.")
            logging.error("No domain provided. Exiting.")
            sys.exit(1)
        ip_ranges = fetch_ip_ranges(domain)
        if not ip_ranges:
            print(Fore.RED + "[-] No IP ranges fetched. Exiting.")
            logging.error("No IP ranges fetched. Exiting.")
            sys.exit(1)
        with open('ranges.txt', 'w') as f:
            for ip_range in ip_ranges:
                f.write(ip_range + '\n')
    else:
        with open('ranges.txt', 'r') as f:
            ip_ranges = [line.strip() for line in f if line.strip()]
        print(Fore.CYAN + f"[+] Loaded {len(ip_ranges)} IP ranges from ranges.txt")
        logging.info(f"Loaded {len(ip_ranges)} IP ranges from ranges.txt")

    hosts = generate_hosts(ip_ranges)

    print(Fore.CYAN + "[+] Starting SMTP port scanning...")
    logging.info("Starting SMTP port scanning.")
    open_smtp_hosts = []

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        future_to_ip = {executor.submit(check_smtp_ports, ip): ip for ip in hosts}
        for future in tqdm(as_completed(future_to_ip), total=len(future_to_ip), desc="Scanning SMTP Ports", unit="host"):
            result = future.result()
            if result:
                open_smtp_hosts.append(result)
                with open('list.txt', 'a') as list_file:
                    list_file.write(result + '\n')
                print(Fore.GREEN + f"[+] Open SMTP Port Found: {result}")
                logging.info(f"Open SMTP Port Found: {result}")
            time.sleep(RATE_LIMIT)

    print(Fore.CYAN + "[+] SMTP port scanning completed. Results saved to list.txt")
    logging.info("SMTP port scanning completed.")

    if not open_smtp_hosts:
        print(Fore.YELLOW + "[-] No open SMTP ports found. Exiting.")
        logging.info("No open SMTP ports found. Exiting.")
        sys.exit(0)

    print(Fore.CYAN + "[+] Starting mass SMTP scan for open relay...")
    logging.info("Starting mass SMTP scan for open relay.")
    open_relays = []

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        future_to_smtp = {executor.submit(smtp_scan, host): host for host in open_smtp_hosts}
        for future in tqdm(as_completed(future_to_smtp), total=len(future_to_smtp), desc="Scanning SMTP Relays", unit="host"):
            result = future.result()
            if result:
                open_relays.append(result)
                with open('open_relays.txt', 'a') as relay_file:
                    relay_file.write(result + '\n')

            time.sleep(RATE_LIMIT)

    if open_relays:
        print(Fore.GREEN + f"[+] Open relay SMTP servers found: {len(open_relays)}")
        logging.info(f"Open relay SMTP servers found: {len(open_relays)}")
    else:
        print(Fore.YELLOW + "[-] No open relay SMTP servers found.")
        logging.info("No open relay SMTP servers found.")

    print(Fore.CYAN + "[+] Mass SMTP scan completed.")
    logging.info("Mass SMTP scan completed.")

    print(Fore.MAGENTA + f"""
    ===============================================
    Thank you for using SMTP Station!
    Join our Telegram channel for support and updates: {TELEGRAM_LINK}
    ===============================================
    """)

if __name__ == "__main__":
    main()