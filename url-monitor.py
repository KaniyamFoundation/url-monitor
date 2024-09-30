import datetime
import whois
import arrow
import urllib.request
import sys
import traceback
import OpenSSL
import ssl
import tldextract
import time
from urllib.request import Request, urlopen
import logging
import os
import requests
import html


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)



ts = time.time()
timestamp  = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d-%H-%M-%S')


if not os.path.isdir("./log"):
    os.mkdir("./log")


# create a file handler
log_file = './log/url_monitor__' + timestamp + '_log.txt'

handler = logging.FileHandler(log_file)
handler.setLevel(logging.INFO)

# create a logging format

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)

# add the handlers to the logger

logger.addHandler(handler)




def get_cert_expiry_date(domain):
    try:
        cert=ssl.get_server_certificate((domain, 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        bytes=x509.get_notAfter()

        timestamp = bytes.decode('utf-8')
        domain_exp_date = datetime.datetime.strptime(timestamp, '%Y%m%d%H%M%S%z').date().isoformat()

        now = datetime.date.today()

        today = arrow.get(now)
        exp = arrow.get(domain_exp_date)

        delta = (exp-today)
        return(delta.days)

    except Exception as e:
        print(e)
        traceback_text = traceback.format_exc()
        print(traceback_text)
        logger.error(traceback_text)
        return -1

def find_expiry_days(domain):
    try:
        w = whois.whois(domain)


        if type(w.expiration_date) is list:
            exp_date = w.expiration_date[0]
        else:
            exp_date = w.expiration_date

        now = datetime.date.today()

        today = arrow.get(now)
        exp = arrow.get(exp_date)

        delta = (exp-today)
        return(delta.days)


    except Exception as e:
        print(e)
        traceback_text = traceback.format_exc()
        print(traceback_text)

        logger.error(traceback_text)        
        logger.info(w)
        
        return -1



def find_http_code(domain):
    try:
        req = Request('http://'+domain, headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/33.0.1750.149 Safari/537.36' })
        http_code = urlopen(req).code
        return http_code

    except Exception as e:
        print(e)
        traceback_text = traceback.format_exc()
        print(traceback_text)
        logger.error(traceback_text)
        
        return -1




def find_website_is_alive(domain):

    try:
        headers = {
            'authority': 'stackoverflow.com',
            'cache-control': 'max-age=0',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'referer': 'https://stackoverflow.com/questions/tagged/python?sort=newest&page=2&pagesize=15',
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'en-US,en;q=0.9,tr-TR;q=0.8,tr;q=0.7',
            'cookie': 'prov=6bb44cc9-dfe4-1b95-a65d-5250b3b4c9fb; _ga=GA1.2.1363624981.1550767314; __qca=P0-1074700243-1550767314392; notice-ctt=4%3B1550784035760; _gid=GA1.2.1415061800.1552935051; acct=t=4CnQ70qSwPMzOe6jigQlAR28TSW%2fMxzx&s=32zlYt1%2b3TBwWVaCHxH%2bl5aDhLjmq4Xr',
    }

        response = requests.get('http://' + domain,timeout=15, headers=headers)    
    
        site_content = html.unescape(response.text)

        if domain in site_content:
            return 1
        else:
            
            response = requests.get('http://www.' + domain,timeout=15, headers=headers)    
    
            site_content = html.unescape(response.text)

            if domain in site_content:
                return 1

            else:
                return 0
    

    except Exception as e:
        print(e)
        traceback_text = traceback.format_exc()
        print(traceback_text)
#        logger.error(traceback_text)
        
        return -1

    

domain_details = open("domain_details_current.prom","w")

def get_domain_details(domain):

    try:
        http_code = find_http_code(domain)
        site_alive = find_website_is_alive(domain)
        domain_expiry_days = find_expiry_days(domain)
        cert_expiry_days = get_cert_expiry_date(domain)


        domain_exp_days_data = 'domain_expiry_days{domain="'+domain+'"} '+ str(domain_expiry_days)
        cert_exp_days_data = 'cert_expiry_days{domain="'+domain+'"} '+ str(cert_expiry_days)
        http_code_data = 'domain_http_code{domain="'+domain+'"} ' + str(http_code) 
        site_alive_data = 'domain_site_alive{domain="'+domain+'"} ' + str(site_alive) 

        
        domain_details.write(domain_exp_days_data + "\n")
        domain_details.write(cert_exp_days_data + "\n")
        domain_details.write(http_code_data + "\n")
        domain_details.write(site_alive_data + "\n")

        
        logger.info(domain_exp_days_data)
        logger.info(cert_exp_days_data)
        logger.info(http_code_data)
        logger.info(site_alive_data)
        logger.info("\n")
        

    except Exception as e:
        print(e)
        traceback_text = traceback.format_exc()
        print(traceback_text)
        logger.error(traceback_text)

domain_list = open("domains.txt","r").readlines()


# https://pypi.org/project/tldextract/
#use tldextract to get the correct domain from any URL


try:
    for domain in domain_list:
        ext = tldextract.extract(domain)
        correct_domain = ext.fqdn.replace("www.",'')
    
        logger.info("Getting details for " + correct_domain)

    
        get_domain_details(correct_domain)
#        time.sleep(1)

    os.system('cp domain_details_current.prom domain_details.prom')
    
except Exception as e:
    print(e)
    traceback_text = traceback.format_exc()
    print(traceback_text)
    logger.error(traceback_text)

    


domain_details.close()
        



