import requests
import os
import xml.etree.ElementTree as ET
from cryptography import x509
from colorama import Fore, Style
import sys

# URL to check certificate status
crl = requests.get('https://android.googleapis.com/attestation/status', headers={'Cache-Control':'max-age=0'}).json()

# Function to parse a certificate and extract serial number
def parse_cert(cert):
    cert = "\n".join(line.strip() for line in cert.strip().split("\n"))
    parsed = x509.load_pem_x509_certificate(cert.encode())
    return f'{parsed.serial_number:x}'

# Function to process each XML file
def check_keybox(file_path):
    certs = [elem.text for elem in ET.parse(file_path).getroot().iter() if elem.tag == 'Certificate']

    if len(certs) < 4:
        print(f"Invalid certificate count in {file_path}")
        return

    # Extract EC and RSA cert serial numbers
    ec_cert_sn, rsa_cert_sn = parse_cert(certs[0]), parse_cert(certs[3])

    print(f'{os.path.basename(file_path)}:')
    print(f'EC Cert SN: {ec_cert_sn}')

    # Check if the certs are revoked
    if any(sn in crl["entries"].keys() for sn in (ec_cert_sn, rsa_cert_sn)):
        print(f'{Fore.RED}REVOKED')
        print(Style.RESET_ALL)
    else:
        print(f'{Fore.GREEN}VALID')
        print(Style.RESET_ALL)

# Main function to check all XML files in a directory
def check_directory(directory):
    for filename in os.listdir(directory):
        if filename.endswith(".xml"):
            file_path = os.path.join(directory, filename)
            check_keybox(file_path)

# Determine the directory path:
if len(sys.argv) > 1:
    # If a directory is provided as a command-line argument, use that
    directory_path = sys.argv[1]
else:
    # Default to the current directory where the script is located
    directory_path = os.path.dirname(os.path.abspath(__file__))

check_directory(directory_path)
