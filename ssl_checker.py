import urllib.parse
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from datetime import datetime

def check_ssl_expiry(url):
    try:
        parsed_url = urllib.parse.urlparse(url)
        domain = parsed_url.netloc
        cert = ssl.get_server_certificate((domain, 443))
        x509cert = x509.load_pem_x509_certificate(cert.encode(), default_backend())
        expiry_date = x509cert.not_valid_after_utc
        return expiry_date
    except ssl.SSLError as e:
        if 'certificate verify failed' in str(e):
            return None  # Placeholder for SSL certificate error
        else:
            print(f"SSL Certificate Error: {e}")
            return None
    except Exception as e:
        if 'getaddrinfo failed' in str(e):
            return None
        else:
            print(f"Error: {e}")
            return None


if __name__ == "__main__":
    url = "insanertech.com"  # Change this to the URL you want to check
    expiry_date = check_ssl_expiry(url)
    if expiry_date:
        print(f"The SSL certificate for {url} expires on: {expiry_date}")
    else:
        print(f"Failed to retrieve SSL certificate expiry for {url}")
