import argparse
import requests
from prettytable import PrettyTable
from tqdm import tqdm
print("""


 888888ba                    dP                         .d88888b    dP              dP                        
 88    `8b                   88                         88.    "'   88              88                        
a88aaaa8P' .d8888b. dP    dP 88d888b. .d8888b. 88d888b. `Y88888b. d8888P .d8888b. d8888P dP    dP .d8888b.    
 88        Y8ooooo. 88    88 88'  `88 88ooood8 88'  `88       `8b   88   88'  `88   88   88    88 Y8ooooo.    
 88              88 88.  .88 88.  .88 88.  ... 88       d8'   .8P   88   88.  .88   88   88.  .88       88    
 dP        `88888P' `8888P88 88Y8888' `88888P' dP        Y88888P    dP   `88888P8   dP   `88888P' `88888P'    
oooooooooooo.d88888bo~~~~.88~ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo
            88.    "'d8888P                                                                                   
            `Y88888b. .d8888b. .d8888b. 88d888b. 88d888b. .d8888b. 88d888b.                                   
                  `8b 88'  `"" 88'  `88 88'  `88 88'  `88 88ooood8 88'  `88                                   
            d8'   .8P 88.  ... 88.  .88 88    88 88    88 88.  ... 88                                         
             Y88888P  `88888P' `88888P8 dP    dP dP    dP `88888P' dP                                         
oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo - Efficiently scan and analyze large lists of domains with PsyberStatus Scanner
         
PsyberStatus Scanner is intended for legitimate and ethical use only. The creators of this tool are not responsible for any unauthorized or illegal use of this tool. By using PsyberStatus Scanner, you agree to use it only for lawful purposes and in compliance with all applicable laws.               
	""")                                                                                        
                                                                                                                            


def check_status_codes_from_file(file_path, timeout):
    try:
        with open(file_path, 'r') as f:
            domains = f.read().splitlines()
    except FileNotFoundError:
        print(f"The file {file_path} does not exist.")
        return

    x = PrettyTable()
    x.field_names = ["Domain", "HTTP", "HTTPS", "Redirection Location"]
    try:
        for domain in tqdm(domains, desc="Scan Progress", unit="domain"):
            protocol_status_code = {"http": None, "https": None}
            redirection_location = None
            for protocol in ["http", "https"]:
                url = f"{protocol}://{domain}"
                try:
                    response = requests.get(url, timeout=timeout, allow_redirects=False)
                    status_code = response.status_code
                    protocol_status_code[protocol] = status_code
                    if status_code in [301, 302]:
                        redirection_location = response.headers.get('location')
                except requests.exceptions.RequestException as e:
                    protocol_status_code[protocol] = "unreachable"
            x.add_row([domain, protocol_status_code["http"], protocol_status_code["https"], redirection_location])
    except KeyboardInterrupt:
        print("\nScan Cancelled by user")
    print(x)
    
    

if __name__ == "__main__":
  
    parser = argparse.ArgumentParser(description="Check status codes of domains from a file")
    parser.add_argument("-dl", "--domains-list", required=True, help="File containing the list of domains")
    parser.add_argument("-t", "--timeout", type=int, default=5, help="Timeout for the HTTP request")
    args = parser.parse_args()

    file_path = args.domains_list
    timeout = args.timeout
    results = check_status_codes_from_file(file_path, timeout)
