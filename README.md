
# Advanced OSINT Investigation Toolkit

## Overview
The **Advanced OSINT Investigation Toolkit** is a comprehensive tool designed for Open Source Intelligence (OSINT) investigations. It provides a wide range of features to gather information about domains, IP addresses, phone numbers, social media accounts, and more. The toolkit also integrates with VirusTotal, GitHub, and other APIs to enhance its capabilities.

This project is built using Python and includes a graphical user interface (GUI) for ease of use.

---

## Features
1. **Domain Information**  
   - Fetch WHOIS, DNS, and SSL details about a domain.
   - Automatically scan domains with VirusTotal.

2. **IP Information**  
   - Retrieve geolocation, open ports, and security details.
   - Perform Nmap scans and fetch BGP information.

3. **Phone Number Information**  
   - Validate phone numbers and fetch carrier and location details.

4. **GitHub Leaks**  
   - Search for email leaks in public GitHub repositories.

5. **Virus Scanning**  
   - Scan files or URLs using VirusTotal and retrieve detailed reports.

6. **Social Media Account Search**  
   - Search for social media accounts linked to a username across multiple platforms.

7. **Breach Directory Check**  
   - Check if an email or username is part of any known data breaches.

8. **Report Generation**  
   - Generate detailed HTML reports for all investigations.

9. **Graphical User Interface (GUI)**  
   - A user-friendly GUI built with `customtkinter` for easy interaction.

---

## Installation

### Prerequisites
- Python 3.8 or higher
- Pip (Python package manager)

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/Advanced-OSINT-Toolkit.git
   cd Advanced-OSINT-Toolkit
   ```

2. Create a virtual environment:
   ```bash
   python -m venv .venv
   ```

3. Activate the virtual environment:
   - On Windows:
     ```bash
     .venv\Scriptsctivate
     ```
   - On macOS/Linux:
     ```bash
     source .venv/bin/activate
     ```

4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

5. Run the application:
   ```bash
   python inosk124.py
   ```

---

## Usage
1. Launch the application by running the script.
2. Use the GUI to select a feature (e.g., Domain Info, IP Info, etc.).
3. Enter the required input (e.g., domain name, IP address, etc.).
4. Click "Run" to start the investigation.
5. Check the output folder for generated reports.

---

## Dependencies
The project uses the following Python libraries:
- `whois`
- `requests`
- `beautifulsoup4`
- `python-nmap`
- `ipwhois`
- `customtkinter`
- `argparse`
- `tkinter`
- `threading`
- `dnspython`

Install all dependencies using the `requirements.txt` file.

---

## API Keys
The toolkit requires API keys for the following services:

1. **VirusTotal**  
   Add your VirusTotal API key in the `inosk124.py` file:
   ```python
   VT_API_KEY = "your_virustotal_api_key"
   ```

2. **GitHub**  
   Add your GitHub token in the `inosk124.py` file:
   ```python
   GITHUB_TOKEN = "your_github_token"
   ```

3. **Phone Validation API**  
   Add your phone validation API key in the `inosk124.py` file:
   ```python
   PHONE_API_KEY = "your_phone_api_key"
   ```

4. **RapidAPI (Breach Directory)**  
   Add your RapidAPI key in the `inosk124.py` file:
   ```python
   RAPIDAPI_KEY = "your_rapidapi_key"
   ```

---

## Output
Investigation results are saved as HTML reports in the `output` folder. The reports are categorized based on the type of investigation (e.g., `domain_info`, `ip_info`, `phone_info`, etc.).

---

## Screenshots
**Main GUI**  
![Main GUI](https://via.placeholder.com/800x400?text=Main+GUI+Screenshot)

**Sample Report**  
![Sample Report](https://via.placeholder.com/800x400?text=Sample+Report+Screenshot)

---

## Contributing
Contributions are welcome! If you'd like to contribute, please fork the repository and submit a pull request.

---

## License
This project is licensed under the MIT License. See the LICENSE file for details.

---

## Disclaimer
This tool is intended for educational and ethical purposes only. The author is not responsible for any misuse of this tool.
