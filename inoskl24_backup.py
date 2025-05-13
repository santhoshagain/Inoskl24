import whois
import requests
import socket
import ssl
from bs4 import BeautifulSoup
import nmap
import argparse
from ipwhois import IPWhois
import time
import json
import sys
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import customtkinter as ctk
import threading
import dns.resolver  # Add this import

# Hardcoded API keys and URLs
VT_API_URL = "https://www.virustotal.com/api/v3"
VT_SCAN_ENDPOINT = "/files"
VT_SCAN_URL_ENDPOINT = "/urls"
VT_REPORT_ENDPOINT = "/analyses/{}"

# API keys should be stored in environment variables or a separate configuration file
VT_API_KEY = "your_virustotal_api_key_here"
GITHUB_TOKEN = "your_github_token_here"
RAPIDAPI_KEY = "your_rapidapi_key_here"
PHONE_API_KEY = "your_phone_api_key_here"

VT_HEADERS = {
    "x-apikey": VT_API_KEY
}


def banner():
    print("+=====================================================+")
    print("| ___ _   _  ___  ____  _  ___       _   ____  _  _   |")
    print("||_ _| \\ | |/ _ \\/ ___|| |/ / |     ( ) |___ \\| || |  |")
    print("| | ||  \\| | | | \\___ \\| ' /| |     |/    __) | || |_ |")
    print("| | || |\\  | |_| |___) | . \\| |___       / __/|__   _||")
    print("||___|_| \\_|\\___/|____/|_|\\_\\_____|     |_____|  |_|  |")
    print("+=====================================================+")

def print_help_menu():
    print("""
    Available Options:
    1. Fetch Domain Information (Includes VirusTotal Scan)
    2. Fetch IP Information (Includes Nmap Scan)
    3. Fetch Phone Number Information
    4. Check GitHub Leaks 
    5. Check Virus in File or Link Using VirusTotal
    6. Search User Accounts
    """)

def generate_report(data, report_name, folder):
    os.makedirs(folder, exist_ok=True)
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>OSINT Report</title>
        <style>
            body {{ background-color: #1d1d1d; color: #a8ff60; font-family: "Courier New", Courier, monospace; }}
            h1 {{ text-align: center; }}
            .box {{ background-color: #333; padding: 15px; margin: 15px 0; border-radius: 10px; }}
            .box-title {{ font-weight: bold; }}
            ul {{ padding-left: 20px; }}
            pre {{ white-space: pre-wrap; }}
            table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
            th, td {{ border: 1px solid #555; padding: 10px; text-align: left; }}
            th {{ background-color: #444; }}
        </style>
    </head>
    <body>
        <h1>OSINT Report for {report_name}</h1>
    """

    for key, value in data.items():
        html_content += f"<div class='box'><div class='box-title'>{key}</div>"
        if isinstance(value, dict):
            html_content += "<table>"
            for sub_key, sub_value in value.items():
                html_content += f"<tr><th>{sub_key}</th><td>{sub_value}</td></tr>"
            html_content += "</table>"
        elif isinstance(value, list):
            html_content += "<ul>"
            for item in value:
                html_content += f"<li>{item}</li>"
            html_content += "</ul>"
        else:
            html_content += f"<div>{value}</div>"
        html_content += "</div>"

    html_content += "</body></html>"

    with open(os.path.join(folder, f"{report_name}.html"), "w", encoding="utf-8") as file:
        file.write(html_content)

    print(f"Report saved as {os.path.join(folder, f'{report_name}.html')}")

def fetch_domain_info(domain_name):
    def get_whois_info(domain):
        try:
            w = whois.whois(domain)
            return {
                "Domain Name": w.domain_name,
                "Registrar": w.registrar,
                "Registrar URL": w.registrar_url,
                "Updated Date": str(w.updated_date),
                "Creation Date": str(w.creation_date),
                "Expiration Date": str(w.expiration_date),
                "Name Servers": ', '.join(w.name_servers) if w.name_servers else "N/A",
                "Organization": w.org,
                "State/Province": w.state,
                "Country": w.country,
                "Domain Status": w.status,
                "DNSSEC": w.dnssec
            }
        except Exception as e:
            return {"Error": str(e)}

    def get_dns_info(domain):
        try:
            ip = socket.gethostbyname(domain)
            response = requests.get(f"https://ipinfo.io/{ip}/json")
            if response.status_code == 200:
                ip_info = response.json()
                return {
                    "IP Address": ip,
                    "Server Location": f"{ip_info.get('city', 'N/A')}, {ip_info.get('country', 'N/A')}",
                    "Server Provider": ip_info.get('org', 'N/A')
                }
            else:
                return {"IP Address": ip, "Server Location": "N/A"}
        except socket.gaierror:
            return {"Error": "Unable to resolve domain."}
        except requests.RequestException:
            return {"Error": "Failed to fetch DNS information."}

    def get_ssl_info(domain):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        "SSL Issuer": dict(x[0] for x in cert.get('issuer')),
                        "Valid From": cert.get('notBefore'),
                        "Valid To": cert.get('notAfter'),
                        "Common Name": dict(x[0] for x in cert.get('subject')).get('commonName')
                    }
        except Exception as e:
            return {"Error": str(e)}

    def get_headers(domain):
        try:
            response = requests.get(f"http://{domain}", timeout=5)
            return dict(response.headers)
        except requests.RequestException as e:
            return {"Error": str(e)}

    def get_robots_txt(domain):
        try:
            response = requests.get(f"http://{domain}/robots.txt", timeout=5)
            if response.status_code == 200:
                return response.text.splitlines()
            else:
                return ["No robots.txt found"]
        except requests.RequestException as e:
            return [f"Error: {str(e)}"]

    def get_linked_pages(domain):
        try:
            response = requests.get(f"http://{domain}", timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            links = [link.get('href') for link in soup.find_all('a', href=True)]
            return links if links else ["No linked pages found."]
        except requests.RequestException as e:
            return [f"Error: {str(e)}"]

    def get_social_tags(domain):
        try:
            response = requests.get(f"http://{domain}", timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            og_tags = {meta.get('property'): meta.get('content') for meta in soup.find_all('meta') if
                       'og:' in (meta.get('property') or '')}
            twitter_tags = {meta.get('name'): meta.get('content') for meta in soup.find_all('meta') if
                            'twitter:' in (meta.get('name') or '')}
            return {"OpenGraph Tags": og_tags, "Twitter Tags": twitter_tags}
        except requests.RequestException as e:
            return {"Error": str(e)}

    def get_server_status(domain):
        try:
            response = requests.get(f"http://{domain}", timeout=5)
            return {"HTTP Status Code": response.status_code}
        except requests.RequestException as e:
            return {"Error": str(e)}

    def get_dns_records(domain):
        try:
            result = {}
            for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']:
                answers = dns.resolver.resolve(domain, record_type, raise_on_no_answer=False)
                result[record_type] = [str(rdata) for rdata in answers]
            return result
        except Exception as e:
            return {"Error": str(e)}

    def get_http_security_headers(domain):
        try:
            response = requests.get(f"http://{domain}", timeout=5)
            security_headers = {
                "Strict-Transport-Security": response.headers.get("Strict-Transport-Security", "Not Present"),
                "Content-Security-Policy": response.headers.get("Content-Security-Policy", "Not Present"),
                "X-Content-Type-Options": response.headers.get("X-Content-Type-Options", "Not Present"),
                "X-Frame-Options": response.headers.get("X-Frame-Options", "Not Present"),
                "X-XSS-Protection": response.headers.get("X-XSS-Protection", "Not Present"),
                "Referrer-Policy": response.headers.get("Referrer-Policy", "Not Present"),
                "Permissions-Policy": response.headers.get("Permissions-Policy", "Not Present")
            }
            return security_headers
        except requests.RequestException as e:
            return {"Error": str(e)}

    # Collect all domain info
    domain_info_result = get_whois_info(domain_name)
    dns_info_result = get_dns_info(domain_name)
    ssl_info_result = get_ssl_info(domain_name)
    headers_result = get_headers(domain_name)
    robots_txt_result = get_robots_txt(domain_name)
    linked_pages_result = get_linked_pages(domain_name)
    social_tags_result = get_social_tags(domain_name)
    server_status_result = get_server_status(domain_name)
    dns_records_result = get_dns_records(domain_name)
    http_security_headers_result = get_http_security_headers(domain_name)

    # Combine all results into a single dictionary
    data = {
        **domain_info_result,
        **dns_info_result,
        **ssl_info_result,
        "Headers": headers_result,
        "Robots.txt": robots_txt_result,
        "Linked Pages": linked_pages_result,
        "Social Tags": social_tags_result,
        **server_status_result,
        "DNS Records": dns_records_result,
        "HTTP Security Headers": http_security_headers_result,
    }

    # Automatically scan the domain with VirusTotal
    vt_scan_result = scan_url(domain_name)

    # If VirusTotal scan was successful, add its results
    if vt_scan_result:
        vt_analysis_id = vt_scan_result['data']['id']
        vt_report = get_url_report(vt_analysis_id)
        if vt_report:
            data["VirusTotal Report"] = parse_report(vt_report)

    generate_report(data, domain_name, "output/domain_info")

def fetch_ip_info(ip_address):
    def get_geolocation(ip):
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json")
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            return {"Error": str(e)}

    def get_host_port_info(ip):
        try:
            nm = nmap.PortScanner()
            nm.scan(ip, arguments='-F')  # Fast scan for most common ports
            ports = []
            for proto in nm[ip].all_protocols():
                lport = nm[ip][proto].keys()
                for port in lport:
                    ports.append(f"Port: {port}, State: {nm[ip][proto][port]['state']}")
            return ports if ports else ["No open ports found."]
        except Exception as e:
            return [f"Error: {str(e)}"]

    def get_ip_bgp_info(ip):
        try:
            obj = IPWhois(ip)
            results = obj.lookup_whois()
            return {
                "ASN": results.get('asn'),
                "ASN Registry": results.get('asn_registry'),
                "ASN Country Code": results.get('asn_country_code'),
                "ASN CIDR": results.get('asn_cidr'),
                "Network Name": results.get('network', {}).get('name')
            }
        except Exception as e:
            return {"Error": str(e)}

    def get_reverse_dns(ip):
        try:
            result = socket.gethostbyaddr(ip)
            return {"Reverse DNS": result[0]}
        except socket.herror:
            return {"Reverse DNS": "No PTR record found"}
        except Exception as e:
            return {"Error": str(e)}

    def get_ip_reputation(ip):
        try:
            response = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", headers={
                "Key": "711058cca2339fcf5c698550951268544a452d8726391957a8a754ead819033c601e1604c2749b1f",
                "Accept": "application/json"
            })
            response.raise_for_status()
            data = response.json()
            return {
                "IP Reputation": data.get('data', {}).get('abuseConfidenceScore', "N/A"),
                "Reports": data.get('data', {}).get('totalReports', "N/A")
            }
        except requests.RequestException as e:
            return {"Error": str(e)}

    geolocation_result = get_geolocation(ip_address)
    host_port_result = get_host_port_info(ip_address)
    bgp_info_result = get_ip_bgp_info(ip_address)
    reverse_dns_result = get_reverse_dns(ip_address)
    ip_reputation_result = get_ip_reputation(ip_address)

    data = {
        "Geolocation": geolocation_result,
        "Open Ports": host_port_result,
        **bgp_info_result,
        **reverse_dns_result,
        **ip_reputation_result
    }

    generate_report(data, ip_address, "output/ip_info")

def fetch_phone_info(phone_number, api_key):
    api_url = f"http://apilayer.net/api/validate?access_key={api_key}&number={phone_number}"

    try:
        response = requests.get(api_url)
        response.raise_for_status()  # Raise an error for bad status codes
        data = response.json()

        if not data.get('valid'):
            return {"Error": "The phone number is not valid."}

        # Extract additional useful information
        phone_info = {
            "Valid": data.get('valid'),
            "Number": data.get('number'),
            "Local Format": data.get('local_format'),
            "International Format": data.get('international_format'),
            "Country Prefix": data.get('country_prefix'),
            "Country Code": data.get('country_code'),
            "Country Name": data.get('country_name'),
            "Location": data.get('location'),
            "Carrier": data.get('carrier'),
            "Line Type": data.get('line_type')
        }

        generate_report(phone_info, phone_number, "output/phone_info")
    except requests.exceptions.HTTPError as http_err:
        return {"Error": f"HTTP error occurred: {http_err}"}    
    except Exception as err:
        return {"Error": f"An error occurred: {err}"}

def check_github_leak(email):
    headers = {
        'Accept': 'application/vnd.github.v3+json',
        'Authorization': f'token {GITHUB_TOKEN}'
    }
    query = f'"{email}"'
    url = f'https://api.github.com/search/code?q={query}&per_page=100&sort=indexed'

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        
        if data['total_count'] > 0:
            report = f"<html><body><h2>Email Leaks Found on GitHub for {email}</h2><ul>"
            for item in data['items']:
                repo_name = item['repository']['full_name']
                file_path = item['path']
                html_url = item['html_url']
                report += f"<li>Repository: <a href='{html_url}'>{repo_name}</a><br>File: {file_path}</li>"
            report += "</ul></body></html>"
            os.makedirs('output/github_leaks', exist_ok=True)
            with open(f'output/github_leaks/github_leaked_{email}.html', 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"Leak report generated for {email}. Check output/github_leaks/github_leaked_{email}.html")
        else:
            print(f"No leaks found for {email} on GitHub.")
    except requests.RequestException as e:
        print(f"Error during GitHub email leak search: {str(e)}")

def check_breach_directory(identifier):
    url = 'https://breachdirectory.p.rapidapi.com/'
    headers = {
        'X-RapidAPI-Host': 'breachdirectory.p.rapidapi.com',
        'X-RapidAPI-Key': RAPIDAPI_KEY,
    }
    params = {'func': 'auto', 'term': identifier}

    result_data = {}

    try:
        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            result = response.json()
            if result.get('success') and result.get('found'):
                result_data = {
                    'Breach Data': result.get('result'),
                }
                print(f"Data related to '{identifier}' found in breaches:")
                for breach in result['result']:
                    print(f"• {breach}")  # Bullet points for console output
            else:
                print(f"No breached data found for '{identifier}'.")
        else:
            print(f"Error: Received status code {response.status_code}.")
            result_data = {"Error": f"Received status code {response.status_code}."}
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while checking breaches for {identifier}: {str(e)}")
        result_data = {"Error": str(e)}

    generate_report(result_data, identifier, "output/breach_directory")

def upload_file(file_path):
    url = VT_API_URL + VT_SCAN_ENDPOINT
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f)}
            response = requests.post(url, headers=VT_HEADERS, files=files)
        response.raise_for_status()
        data = response.json()
        analysis_id = data.get('data', {}).get('id')
        if analysis_id:
            print(f"[+] File uploaded successfully. Analysis ID: {analysis_id}")
            return analysis_id
        else:
            print("[-] Failed to retrieve Analysis ID.")
            sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"[-] Error uploading file: {e}")
        sys.exit(1)

def get_analysis_report(analysis_id):
    url = VT_API_URL + VT_REPORT_ENDPOINT.format(analysis_id)
    try:
        response = requests.get(url, headers=VT_HEADERS)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"[-] Error fetching analysis report: {e}")
        return None

def scan_url(url):
    headers = {
        "x-apikey": VT_API_KEY
    }

    response = requests.post(VT_API_URL + VT_SCAN_URL_ENDPOINT, headers=headers, data={'url': url})

    if response.status_code == 200:
        print("URL scanned successfully.")
        return response.json()
    else:
        print(f"Failed to scan URL: {response.status_code}")
        return None

def get_url_report(analysis_id):
    report_url = f"{VT_API_URL}{VT_REPORT_ENDPOINT.format(analysis_id)}"
    headers = {
        "x-apikey": VT_API_KEY
    }

    response = requests.get(report_url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to retrieve report: {response.status_code}")
        return None

def parse_report(report):
    status = report.get('data', {}).get('attributes', {}).get('status')
    report_data = {
        "Status": status,
        "Stats": report['data']['attributes']['stats'],
        "Results": report['data']['attributes']['results'],
        "Scan Date": report['data']['attributes']['date'],
        "URL": report['data']['attributes'].get('url', 'N/A'),
        "File Type": report['data']['attributes'].get('type_description', 'N/A')
    }
    return report_data

def main_vt_analysis(file_path, polling_interval, max_polls):
    if not os.path.isfile(file_path):
        print(f"[-] File not found: {file_path}")
        sys.exit(1)

    print(f"[+] Starting analysis for file: {file_path}")
    analysis_id = upload_file(file_path)

    polls = 0
    while polls < max_polls:
        report = get_analysis_report(analysis_id)
        if report:
            parsed_data = parse_report(report)
            generate_report(parsed_data, f"VT_Report_{analysis_id}", "output/virus_analysis")
            break
        else:
            print("[-] Failed to retrieve report.")

        polls += 1
        if polls < max_polls:
            time.sleep(polling_interval)
        else:
            print("[-] Maximum polling attempts reached. Exiting.")
            sys.exit(1)

def search_username(username):
    platforms = {
        "Facebook": f"https://www.facebook.com/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "Instagram": f"https://www.instagram.com/{username}",
        "GitHub": f"https://github.com/{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "Pinterest": f"https://www.pinterest.com/{username}",
        "YouTube": f"https://www.youtube.com/@{username}",
        "Snapchat": f"https://www.snapchat.com/add/{username}",
        "Twitch": f"https://www.twitch.tv/{username}",
        "Discord": f"https://discord.com/users/{username}",
        "TikTok": f"https://www.tiktok.com/@{username}",
        "Medium": f"https://medium.com/@{username}",
        "Tumblr": f"https://{username}.tumblr.com",
        "Vimeo": f"https://vimeo.com/{username}",
        "Flickr": f"https://www.flickr.com/people/{username}",
        "SoundCloud": f"https://soundcloud.com/{username}",
        "DeviantArt": f"https://www.deviantart.com/{username}",
        "Behance": f"https://www.behance.net/{username}",
        "Dribbble": f"https://dribbble.com/{username}",
        "Goodreads": f"https://www.goodreads.com/{username}",
        "GitLab": f"https://gitlab.com/{username}",
        "Bitbucket": f"https://bitbucket.org/{username}",
        "Steam": f"https://steamcommunity.com/id/{username}",
        "Telegram": f"https://t.me/{username}",
        "Threads": f"https://www.threads.net/{username}"
    }

    found_links = []

    for platform, url in platforms.items():
        try:
            response = requests.get(url, headers={"User-Agent": "Mozilla/5.0"})
            if response.status_code == 200:
                found_links.append((platform, url))
        except requests.RequestException:
            continue

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Social Media Profiles for {username}</title>
        <style>
            body {{ background-color: #1d1d1d; color: #a8ff60; font-family: "Courier New", Courier, monospace; }}
            h1 {{ text-align: center; }}
            .box {{ background-color: #333; padding: 15px; margin: 15px 0; border-radius: 10px; }}
            ul {{ padding-left: 20px; }}
            a {{ color: #a8ff60; text-decoration: none; }}
        </style>
    </head>
    <body>
        <h1>Social Media Profiles for {username}</h1>
        <div class='box'>
            <h2>Social media profiles found:</h2>
            <ul>
    """

    for platform, link in found_links:
        html_content += f"<li>{platform}: <a href='{link}' target='_blank'>{link}</a></li>"

    html_content += """
            </ul>
        </div>
    </body>
    </html>
    """

    os.makedirs('output/username_search', exist_ok=True)
    with open(f'output/username_search/{username}_profiles.html', 'w', encoding='utf-8') as file:
        file.write(html_content)

    print(f"Report saved as output/username_search/{username}_profiles.html")

def create_gui():
    def run_feature():
        feature = feature_var.get()
        input_value = input_entry.get()
        status_label.configure(text="Running...", text_color="yellow")
        progress_bar.start()

        if feature == "IP Info":
            thread = threading.Thread(target=fetch_ip_info_thread, args=(input_value,), daemon=True)
            thread.start()
        else:
            thread = threading.Thread(target=perform_other_operations, args=(feature, input_value), daemon=True)
            thread.start()

    def fetch_ip_info_thread(ip_address):
        try:
            fetch_ip_info(ip_address)
            root.after(0, lambda: messagebox.showinfo("Info", "IP Information fetched successfully. Check output folder."))
        except Exception as e:
            root.after(0, lambda: messagebox.showerror("Error", f"Failed to fetch IP info: {str(e)}"))
        finally:
            root.after(0, lambda: update_status("Completed", "green"))

    def perform_other_operations(feature, input_value):
        try:
            if feature == "Domain Info":
                fetch_domain_info(input_value)
            elif feature == "Phone Info":
                fetch_phone_info(input_value, os.getenv("PHONE_API_KEY"))
            elif feature == "GitHub Leaks":
                check_github_leak(input_value)
            elif feature == "Virus Check":
                if input_value.startswith("http"):
                    scan_result = scan_url(input_value)
                    if scan_result:
                        analysis_id = scan_result['data']['id']
                        report = get_url_report(analysis_id)
                        if report:
                            generate_report(report, f"VT_URL_Report_{analysis_id}", "output/url_analysis")
                else:
                    main_vt_analysis(input_value, 15, 10)
            elif feature == "User Accounts":
                search_username(input_value)

            root.after(0, lambda: messagebox.showinfo("Info", "Operation completed. Check the output folder for results."))
        except Exception as e:
            root.after(0, lambda: messagebox.showerror("Error", f"Operation failed: {str(e)}"))
        finally:
            root.after(0, lambda: update_status("Completed", "green"))

    def browse_file():
        file_path = filedialog.askopenfilename()
        input_entry.delete(0, ctk.END)
        input_entry.insert(0, file_path)

    def on_feature_change(choice):
        if choice == "Virus Check":
            browse_button.pack(side="left", padx=10)
        else:
            browse_button.pack_forget()
        update_help_text(choice)

    def update_help_text(feature):
        help_texts = {
            "Domain Info": "Fetch WHOIS, DNS, SSL details about a domain.",
            "IP Info": "Retrieve geolocation, open ports, and security details.",
            "Phone Info": "Validate phone numbers and fetch carrier info.",
            "GitHub Leaks": "Check for leaks associated with an email on GitHub.",
            "Virus Check": "Scan a file or URL using VirusTotal.",
            "User Accounts": "Search for social media accounts linked to a username."
        }
        help_label.configure(text=help_texts.get(feature, ""))

    def update_status(message, color):
        status_label.configure(text=message, text_color=color)
        progress_bar.stop()

    root = ctk.CTk()
    root.title("Advanced OSINT Tool")
    root.geometry("800x600")

    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")

    title_label = ctk.CTkLabel(root, text="OSINT Investigation Toolkit", font=("Arial", 24, "bold"))
    title_label.pack(pady=15)

    # Add banner to GUI
    banner_frame = ctk.CTkFrame(root)
    banner_frame.pack(pady=10, padx=20, fill="x")
    banner_label = ctk.CTkLabel(banner_frame, text="+=====================================================+\n| ___ _   _  ___  ____  _  ___       _   ____  _  _   |\n||_ _| \\ | |/ _ \\/ ___|| |/ / |     ( ) |___ \\| || |  |\n| | ||  \\| | | | \\___ \\| ' /| |     |/    __) | || |_ |\n| | || |\\  | |_| |___) | . \\| |___       / __/|__   _||\n||___|_| \\_|\\___/|____/|_|\\_\\_____|     |_____|  |_|  |\n+=====================================================+", font=("Courier New", 12))
    banner_label.pack()

    feature_var = ctk.StringVar()
    features = [
        "Domain Info",
        "IP Info",
        "Phone Info",
        "GitHub Leaks",
        "Virus Check",
        "User Accounts"
    ]

    feature_dropdown = ctk.CTkComboBox(root, values=features, variable=feature_var, command=on_feature_change)
    feature_dropdown.pack(pady=10)
    feature_dropdown.set(features[0])

    input_frame = ctk.CTkFrame(root)
    input_frame.pack(pady=10, padx=20, fill="x")

    input_label = ctk.CTkLabel(input_frame, text="Input:", font=("Arial", 16))
    input_label.pack(side="left", padx=10)

    input_entry = ctk.CTkEntry(input_frame, width=400)
    input_entry.pack(side="left", padx=10)

    browse_button = ctk.CTkButton(input_frame, text="Browse", command=browse_file)

    run_button = ctk.CTkButton(root, text="Run", command=run_feature, fg_color="#1E90FF", text_color="white", font=("Arial", 16, "bold"))
    run_button.pack(pady=10)

    progress_bar = ctk.CTkProgressBar(root, mode="indeterminate")
    progress_bar.pack(pady=10, padx=20, fill="x")

    status_label = ctk.CTkLabel(root, text="", font=("Arial", 14), text_color="lightgray")
    status_label.pack(pady=5)

    help_label = ctk.CTkLabel(root, text="", wraplength=600, font=("Arial", 14), text_color="lightgray")
    help_label.pack(pady=5)

    update_help_text(features[0])

    # Add a status bar
    status_bar = ctk.CTkLabel(root, text="Ready", font=("Arial", 12), text_color="lightgray")
    status_bar.pack(side="bottom", fill="x")

    root.mainloop()

if __name__ == "__main__":
    create_gui()