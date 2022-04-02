import requests
import os
import sys
import json
from dns import resolver    # DNS Lookup
from bs4 import BeautifulSoup as bs
from urllib.parse import urlparse
import socket 
import random                   

"""
Note: Each entry in g_whitelist is a key-value pair => {key, val} = {domain, ip}
"""
g_whitelist = {}
g_phishing_sites = []
domains = []
num_urls = 0
g_threshold = 1010

# % GOOD
# Create an account, add user_agent to request, and parse json data -> Currently being rate limited
# Scrapes active phishing sites from the list of sites (Fine repo in README) 
def load_phishing_sites():
    global g_phishing_sites
    global domains
    content = None
    option = int(input("Enter: \n1. Phishing Repo\n2. PhishTank (data from paper)\n"))
    if option == 1:
        url = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE-TODAY.txt"
        content = requests.get(url).iter_lines()
        for i in content:
            link = i.decode("utf-8")
            print(link)
            g_phishing_sites.append(link)
        
        print("\nHere are the results. It is likely that some pages are not found because they were probably already taken down.")
    elif option == 2:
        option = int(input("Enter: \n1. Fetch data (Don't do this because API calls)\n2. Load data from test_data.json\n"))
        if option == 1:
            url = "http://data.phishtank.com/data/online-valid.json"
            content = requests.get(url)
            print(content)
        else:
            with open("json_data/FULL.json", "r") as f:
                content = json.load(f)
                g_phishing_sites, num_urls = get_urls_from_json(content)
                print("URLs:")
                domains = extract_domains(g_phishing_sites)     # Takes out only the domain name from each site
                # [print(url) for url in domains]
                print(f'Number of urls: {num_urls}')
                
                for i in range(len(g_phishing_sites)):
                    print(f"~~~~~~~\nurl: {g_phishing_sites[i]}\ndomain: {domains[i]}\n~~~~~~~")
                
                len_g_p_sites = len(g_phishing_sites)
                len_domains = len(domains)
                print(f"Length of g_phishing_sites: {len_g_p_sites}")
                print(f"Length of domains: {len_domains}")
                
# % GOOD               
# Grabs all of the urls from the json content from PhishTank dataset
def get_urls_from_json(content):
    urls = []
    for entry in content:
        url = entry['url']
        # print(url)
        urls.append(url)
    return urls, len(urls)
    
# % GOOD
# Loads the whitelist values into the script
def load_whitelist():
    global g_whitelist
    with open("whitelist.txt", "r") as f:
       g_whitelist = json.load(f)

# % GOOD
# Initializes an empty dictionary
def init_whitelist():
    g_whitelist = {}

# % GOOD
# Adds a new key-value pair to the whitelist
def update_whitelist(domain: str, ip: str):
    g_whitelist[domain] = ip

# % GOOD
# Save the current whitelist locally to whitelist.txt
def save_whitelist():
    with open("whitelist.txt", "w") as f:
        
        # Dump contents of dictionary to file as json object
        f.write(json.dumps(g_whitelist))

# % GOOD
def test_whitelist():
    num_entries = int(input("How many entries: "))
    print(f"num_entries: {num_entries}")
    init_whitelist()
    for i in range(num_entries):
        print(i)
        str_t = "a"*random.randint(1,5)
        str_c = "b"*random.randint(1,5)
        update_whitelist(str_t, str_c)
    print(g_whitelist)
    print("^ before saving")
    save_whitelist()
    print("Saved whitelist")
        
    print("Testing load_whitelist()")
    load_whitelist()
    print(g_whitelist)

# % GOOD
# i.e. www.facebook.com/thisisanexample/... -> facebook.com
def extract_domains(domains: list):
    return [urlparse(site).netloc.replace("www.", "") for site in domains]

#! TODO: Need to make sure that dns lookup is done correctly and aligns with what the authors intended
#! Read up on DNS poisoning
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

# % GOOD
# Extract the hyperlink set from the given webpage
def calculate_hyperlink(url: str):
    resp=requests.get(url)
    soup=bs(resp.text,'html.parser')
    num_links=0
    link_set = []
    for link in soup.find_all('a'):
        temp=link.get('href')
        link_set.append(temp)
        num_links=num_links+1
    return link_set, num_links

def is_self_referencing(url: str):
    return True

# ! TEST
# Count number of hyperlinks pointing to own domain
def get_self_ref_links(url: str):
    
    url_p=urlparse(url)
    domain = url_p.netloc
    print(f"url: {url}\tdomain: {domain}")
    
    resp=requests.get(url)
    soup=bs(resp.text,'html.parser')
    num_links=0
    
    for link in soup.find_all('a'):
        temp=link.get('href')
        print(temp)
        # if temp is not None and domain in temp:
        if is_self_referencing(temp):
            num_links=num_links+1
    return num_links

# % GOOD
# Get percentage of "#" hyperlinks in link set
def get_percentage_null_hyperlinks(link_set):
  num_links=0
  for link in link_set:
    if(link == "#"):    # NULL link  = "#"
      num_links=num_links+1
  return ((num_links / len(link_set)) * 100)

# Test to see if all the link extraction functions are working as described from the paper
def test_extraction_functions():
    link = input("Enter a link: ")
    print(f"Testing: calculate_hyperlink() with URL: {link}\n")
    link_set, num_links = calculate_hyperlink(link)
    print(f"Results:\nlink_set: {link_set}\nnum_links: {num_links}\n")
    print(f"Testing: get_self_ref_links() with URL: {link}\n")
    num_self_ref_links = get_self_ref_links(link)
    print(f"Results:\n Number of self referencing links: {num_self_ref_links}")
    print(f"Testing: get_percentage_null_hyperlinks() with URL: {link}")
    ret_val = get_percentage_null_hyperlinks(link_set)
    print(f"Results: %/ null links: {ret_val}")


# % GOOD
# This should be done since this is directly from the paper
# Ratio of hyperlinks points to foreign domains / total numer of hyperlinks
# ratio = [1 - (count_self_ref_links / num_hyperlinks)]
def calc_ratio(num_hyperlinks: int, count_self_ref_links: int):
    ratio = 1 - (count_self_ref_links / num_hyperlinks)
    return ratio

# % Good: Structure conforms to Algorithm described in the paper
# ! Bad: Need to ensure the functions are working as intended as described in paper
# This is the algorithm defined in the paper. Check the README for the
# link to the paper.
# Returns 0 if page is phishing, otherwise returns 1
def phishing_identification_algo(webpage: str):

    # ! TODO: unsure of calculate_hyperlink is working but will assume it does for now
    # Extract hyperlink data and number of hyperlinks on a given page
    hyperlinks_set, num_hyperlinks = calculate_hyperlink(webpage)    

    if len(hyperlinks_set) == 0:
        print("There are no hyperlinks extracted from webpage")
        print("Webpage is Phishing")
        return 0

    # Check for null hyperlinks
    #! TODO: Paper says more than 80% of the hyperlinks are NULL
    for link in hyperlinks_set:
        if link is None:
            print("Webpage is Phishing")
            return 0
    
    #! TODO: Need to ensure that this function is correct
    count_self_ref_links = get_self_ref_links(webpage)

    # TODO: This function relies on the results of the other two functions
    ratio = calc_ratio(num_hyperlinks, count_self_ref_links)

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
    
    return 
    for site in g_phishing_sites:
        run(site)
    

if __name__ == "__main__":
    # main()
    # load_phishing_sites()
    # test_whitelist()
    test_extraction_functions()
    # dns_lookup('facebook.com')
