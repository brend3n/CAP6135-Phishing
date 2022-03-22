import requests
import os
import sys
import json
import extern_logger as logger
from dns import resolver    # DNS Lookup

"""
Note: Each entry in g_whitelist is a key-value pair => {key, val} = {domain, ip}
"""
g_whitelist = {}

g_phishing_sites = []
g_threshold = 1010

#! TODO: PhishTank option seems better but need to do the following
# Create an account, add user_agent to request, and parse json data -> Currently being rate limited
# Scrapes active phishing sites from the list of sites (Fine repo in README) 
def load_phishing_sites():
    option = int(input("Enter: \n1. Phishing Repo\n2. PhishTank (data from paper)\n"))
    if option == 1:
        url = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE-TODAY.txt"
        content = requests.get(url).iter_lines()
        for i in content:
            link = i.decode("utf-8")
            print(link)
            g_phishing_sites.append(link)
    elif option == 2:
        url = "http://data.phishtank.com/data/online-valid.json"
        content = requests.get(url)
        print(content)
        
    

# Not sure if this will be used since paper states whitelist starts empty
#! TODO: Not tested
# Loads the whitelist values into the script
def load_whitelist():
    with open("whitelist.txt", "r") as f:
       whitelist_line = f.readlines().split(",")
       domain = whitelist_line[0] 
       ip = whitelist_line[1]
       g_whitelist[domain] = ip

#! TODO: Not tested
# Initializes an empty dictionary
def init_whitelist():
    g_whitelist = {}


#! TODO: Not tested
# Adds a new key-value pair to the whitelist
def update_whitelist(domain: str, ip: str):
    g_whitelist[domain] = ip


#! TODO: Not tested
# Save the current whitelist locally to whitelist.txt
def save_whitelist():
    with open("whitelist.txt", "w") as f:
        # Dump contents of dictionary to file as json object
        f.write(json.dumps(g_whitelist))


#! TODO: Write this function
# Extract the hyperlink set from the given webpage
def calculate_hyperlink(webpage: str):

    link_set = []
    num_links = 0

    # Code goes here

    # 1. linkset :=  all links
    # 2. num_links := length of linkset
    
    return link_set, num_links

#! TODO: Write this function
# Count number of hyperlinks pointing to own domain
def get_self_ref_links(webpage: str):
    count = 0

    # count := number of self-referencing links

    return count

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
def phishing_identification_algo(webpage: str):

    # Extract hyperlink data and number of hyperlinks on a given page
    hyperlinks_set, num_hyperlinks = calculate_hyperlink(webpage)    

    if len(hyperlinks_set) == 0:
        print("Webpage is Phishing")
        return

    for link in hyperlinks_set:
        if link is None:
            print("Webpage is Phishing")
            return
    
    count_self_ref_links = get_self_ref_links(webpage)

    ratio = calc_ratio(webpage, hyperlinks_set, num_hyperlinks, count_self_ref_links)

    if ratio > g_threshold:
        print("Webpage is Phishing")
    else:
        print("Webpage is Legitimate")

        # Add valid domain to whitelist
        update_whitelist()

    return

#! TODO: Need to implement phishing model for both modules
# Module1: URL AND DNS MATCHING
# Module2: PHISHING IDENTIFICATION
def run(webpage: str):
    """
    This function should model the system described in the paper.
    """
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
