# PsyberStatusScanner
A tool for finding the status and redirection location of a massive list of domains and sub-domains.

### Introduction

PsyberStatus Scanner is a tool designed for bug bounty hunters and penetration testers to quickly and easily check the status of a large list of domains. It can check for both HTTP and HTTPS status, as well as check for redirection locations. The tool is designed to be easy to use and to provide clear and concise results.

**Created By**

![](https://cdn.buymeacoffee.com/uploads/profile_pictures/2023/01/ffFiHxCLZLCcIuA7.png@300w_0e.webp)

Checkout [Psyberbook.com](https://www.psyberbook.com/ "Psyberbook.com") for our CybserSecurity Blogs

## Requirements
- Python 3.x
- requests library
- argparse library
- PrettyTable library


## Usage

use the command pip install -r requirements.txt to install all the necessary packages and their versions.

=============

    usage: psyberstatusscanner.py [-h] -dl DOMAIN_LIST [-t TIMEOUT] [-rl NUM_THREADS]
    
    Example : python psyberstatusscanner.py -dl domain_list.txt -t 5 -rl 20
    
    Check status codes for a list of domains
    
    options:
      -h, --help            show this help message and exit
      -dl DOMAIN_LIST, --domain_list DOMAIN_LIST
                            File path of the list of domains
      -t TIMEOUT, --timeout TIMEOUT
                            Timeout for the HTTP requests
      -rl NUM_THREADS, --num_threads NUM_THREADS
                            Number of threads for the scanning
    
       
  
-dl : specify the input file containing the list of domains
-t :   specify the Timeout for the HTTP request
## Acknowledgements
- Jr_hackerman for creating the tool
- Jr_hackerman for contributing to the development of the tool
- Jr_hackerman for providing support for the tool

## Screenshot
[![psyberstatus scanner](https://blogger.googleusercontent.com/img/b/R29vZ2xl/AVvXsEjqzUGHVvy8nHd9VSfpi9ciVT5bK-YKg-wXC0D1r-qJ51_vaqT5tPWv43xuPVFowCoIQTIQXO5wD50zwG0T60WFgZv07T943iOg7Zf1DRSPW6TFQpQVjdtTN0AY84GOoq0sLbxFEW5OZPIqEBfEv4I5EoSxX-It3X6mDU9dY5oKWltxYzKcBD4OQsVWVA/w640-h304/WhatsApp%20Image%202023-01-26%20at%2010.17.08%20PM.jpeg "psyberstatus scanner")](http://psyberbook.com "psyberstatus scanner")

## Authors
- Jr_hackerman

## Disclaimer
This tool is intended for legal and ethical use only. The authors are not responsible for any illegal or unethical use of the tool. Use of this tool for any illegal or unethical purpose is strictly prohibited.

### Conclusion

PsyberStatus Scanner is a powerful tool for quickly and easily checking the status of a large list of domains. It is designed to be easy to use and to provide clear and concise results. With the help of this tool, bug bounty hunters and penetration testers can save a lot of time and effort in their work.

Please use this tool responsibly and in compliance with all relevant laws and regulations.

=========================================================
####  Fuel your hacking with a hot cup of coffee, buy me one!
<a href="https://www.buymeacoffee.com/PsyberBook" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>

