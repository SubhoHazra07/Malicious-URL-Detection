import re
from googlesearch import search
from urllib.parse import urlparse
from tld import get_tld
import os.path

#Use of IP Address in Domain
def having_ip_address(url):
    match=re.search('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4 with port
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
        '([0-9]+(?:\.[0-9]+){3}:[0-9]+)|'
        '((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)', url) #IPv6
    if match:
        return 1
    else:
        return 0
    

#Finding Abnormal URLs(Having diff types of keywords or not seen in usual URL)
def abnormal_url(url):
    hostname=urlparse(url).hostname
    hostname=str(hostname)
    match=re.search(hostname, url)
    if match:
        return 1
    else:
        return 0

#Find the URL is Google Index or not
def google_index(url):
    site=search(url,5)
    if site:
        return 1
    else:
        return 0

#Count the Dots[.] in the URL
def count_dots(url):
    return url.count('.')
    
#Count the www(World Wide Web)
def count_www(url):
    return url.count('www')

#Count At The Rate[@] in the URL
def count_attherate(url):
    return url.count('@')

#Count the No of Directories[/] in the URL
def no_of_dir(url):
    urldir=urlparse(url).path
    return urldir.count('/')

#Count No of Embeddings in the URL
def no_of_embeddings(url):
    urldir=urlparse(url)
    return urldir.count('//')

#Shorten The Huge URL
def shorten_url(url):
    match=re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                    'tr\.im|link\.zip\.net',
                    url)
    if match:
        return 1
    else:
        return 0
    
#Count No of 'https' in the URL
def count_https(url):
    return url.count('https')

#Count No of 'http' in the URL
def count_http(url):
    return url.count('http')

#Count No of Percentage[%] in the URL
def count_percentage(url):
    return url.count('%')

#Count No of Question Mark[?] in the URL
def count_question(url):
    return url.count('?')

#Count No of Hyphen[-] in the URL
def count_hyphen(url):
    return url.count('-')

#Count No of Equal To[=] in the URL
def count_equalto(url):
    return url.count('=')

#Calculate the Length of the URL
def url_length(url):
    return len(str(url))

#Calculate the Length of HostName
def hostname_length(url):
    return len(urlparse(url).netloc)

#Find the Suspicious Word from URL
def suspicious_words(url):
    match=re.search('paypal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',url)
    if match:
        return 1
    else:
        return 0
    
#Count No of Digits in URL
def digit_count(url):
    digits=0
    for i in url:
        if i.isnumeric():
            digits+=1
    return digits

#Count No of Letters in URL
def letter_count(url):
    letters=0
    for i in url:
        if i.isalpha():
            letters+=1
    return letters

#Find First Directory Length
def fd_length(url):
    url_path=urlparse(url).path
    try:
        return len(url_path.split('/')[1])
    except:
        return 0

#Find length of Top Level Domain
def tld_length(tld):
    try:
        return len(tld)
    except:
        return -1

