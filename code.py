import requests
import os
import sys
import json
from dns import resolver    # DNS Lookup
from bs4 import BeautifulSoup as bs
from urllib.parse import urlparse
import socket                    

"""
Note: Each entry in g_whitelist is a key-value pair => {key, val} = {domain, ip}
"""
g_whitelist = {}
g_phishing_sites = []
num_urls = 0
g_threshold = 1010

# Create an account, add user_agent to request, and parse json data -> Currently being rate limited
# Scrapes active phishing sites from the list of sites (Fine repo in README) 
def load_phishing_sites():
    global g_phishing_sites
    content = None
    option = int(input("Enter: \n1. Phishing Repo\n2. PhishTank (data from paper)\n"))
    if option == 1:
        url = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE-TODAY.txt"
        content = requests.get(url).iter_lines()
        for i in content:
            link = i.decode("utf-8")
            print(link)
            g_phishing_sites.append(link)
    elif option == 2:
        option = int(input("Enter: \n1. Fetch data (Don't do this because API calls)\n2. Load data from test_data.json\n"))
        if option == 1:
            url = "http://data.phishtank.com/data/online-valid.json"
            content = requests.get(url)
            print(content)
        else:
            with open("FULL.json", "r") as f:
                content = json.load(f)
                g_phishing_sites, num_urls = get_urls_from_json(content)
                print("URLs:")
                [print(url) for url in g_phishing_sites]
                print(f'Number of urls: {num_urls}')
                
            
# Grabs all of the urls from the json content from PhishTank dataset
def get_urls_from_json(content):
    urls = []
    for entry in content:
        url = entry['url']
        # print(url)
        urls.append(url)
    return urls, len(urls)
    
# Not sure if this will be used since paper states whitelist starts empty
#! TODO: Not tested
# Loads the whitelist values into the script
def load_whitelist():
    with open("whitelist.txt", "r") as f:
       whitelist_line = f.readlines().split(",")
       domain = whitelist_line[0] 
       ip = whitelist_line[1]
       g_whitelist[domain] = ip

# Initializes an empty dictionary
def init_whitelist():
    g_whitelist = {}

# Adds a new key-value pair to the whitelist
def update_whitelist(domain: str, ip: str):
    g_whitelist[domain] = ip

# Save the current whitelist locally to whitelist.txt
def save_whitelist():
    with open("whitelist.txt", "w") as f:
        
        # Dump contents of dictionary to file as json object
        f.write(json.dumps(g_whitelist))


#! TODO: Clean up url to extract domain name 
# i.e. www.facebook.com/thisisanexample/... -> facebook.com
def clean(url: str):
    cleaned_url = url

    # Clean url here

    return cleaned_url

#! TODO: Need to make sure that dns lookup is done correctly and aligns with what the authors intended
# Do a DNS lookup
# Return None if bad otherwise return IP
def dns_lookup(url: str):
    print(f"Name: {url}")
    res = None
    try:
        res = socket.gethostbyname(url)
        print(f"Host: {res}")
        return res
    except Exception as e:
        return None

#! TODO: Write this function
def is_match():
    return

# Extract the hyperlink set from the given webpage
def calculate_hyperlink(url: str):
    url_p=urlparse(url)
    domain='{uri.scheme}://{uri.netloc}/'.format(uri=url_p) # TODO: Unused -> was there a reason for this or was it just copied and pasted over?
    resp=requests.get(url)
    soup=bs(resp.text,'html.parser')
    num_links=0
    link_set = []
    for link in soup.find_all('a'):
        temp=link.get('href')
        link_set.append(temp)
        num_links=num_links+1
    return link_set, num_links

# Count number of hyperlinks pointing to own domain
def get_self_ref_links(url: str):
    url_p=urlparse(url)
    domain='{uri.scheme}://{uri.netloc}/'.format(uri=url_p)
    resp=requests.get(url)
    soup=bs(resp.text,'html.parser')
    num_links=0
    for link in soup.find_all('a'):
        temp=link.get('href')
        if temp is not None and domain in temp: # TODO: I think the None has to be a #, but im not sure
          num_links=num_links+1
    return num_links

# Get percentage of "#" hyperlinks in link set
def get_percentage_null_hyperlinks(link_set):
  num_links=0
  for link in link_set:
    if(link == "#"):
      num_links=num_links+1
  return ((num_links / len(link_set)) * 100)

#! TODO: Not Tested
# This should be done since this is directly from the paper
# Ratio of hyperlinks points to foreign domains / total numer of hyperlinks
# ratio = [1 - (count_self_ref_links / num_hyperlinks)]
def calc_ratio(webpage: str, hyperlinks_set, num_hyperlinks: int, count_self_ref_links: int):
    ratio = 1 - (count_self_ref_links / num_hyperlinks)
    return ratio

#! TODO: Not Tested
# This is the algorithm defined in the paper. Check the README for the
# link to the paper.
# Returns 0 if page is phishing, otherwise returns 1
def phishing_identification_algo(webpage: str):

    # Extract hyperlink data and number of hyperlinks on a given page
    hyperlinks_set, num_hyperlinks = calculate_hyperlink(webpage)    

    if len(hyperlinks_set) == 0:
        print("Webpage is Phishing")
        return 0

    for link in hyperlinks_set:
        if link is None:
            print("Webpage is Phishing")
            return 0
    
    count_self_ref_links = get_self_ref_links(webpage)

    ratio = calc_ratio(webpage, hyperlinks_set, num_hyperlinks, count_self_ref_links)

    if ratio > g_threshold:
        print("Webpage is Phishing")
        return 0
    else:
        print("Webpage is Legitimate")

        # Add valid domain to whitelist
        update_whitelist()

    return 1

#! TODO: Need to implement phishing model for both modules
# Module1: URL AND DNS MATCHING
# Module2: PHISHING IDENTIFICATION
def run(webpage: str):
    """
    This function should model the system described in the paper.
    """

    if page in g_whitelist:
        # Check if Domain Matched from DNS lookup
        '''
        If so:
            if IP address matched
                then Legitimate site
            else if IP address not matched:
                then Phishing site
        else Domain not matched:
            then call phishing_identifcation_module
        '''
        pass
    else: # page not in whitelist
        ret_val = phishing_identification_algo(webpage)
        if ret_val != 0:
            # not phishing
            pass
        else: 
            # phishing
            pass

    pass

def main():
    g_threshold = int(input("Adjust threshold: "))

    init_whitelist()
    load_phishing_sites()
    
    for site in g_phishing_sites:
        run(site)
    

    save_whitelist()

if __name__ == "__main__":
    # main()
    load_phishing_sites()
    # dns_lookup('facebook.com')
