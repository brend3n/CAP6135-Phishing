import requests
import os
import sys

g_whitelist = []
g_phishing_sites = []
g_threshold = 1010

#! TODO: Write this function
# Scrapes active phishing sites from the list of sites (Fine repo in README) 
def load_phishing_sites():
    # Set g_phishing_sites to list [] of strings representing the sites
    pass

#! TODO: Not tested
# Loads the whitelist values into the script
def load_whitelist():
    with open("whitelist.txt", "r") as f:
       g_whitelist = f.readlines()

#! TODO: Not tested
# Updates the whitelist with a new entry
def update_whitelist(entry: str):
    g_whitelist.append(entry)

#! TODO: Not tested
# Save the current whitelist locally to whitelist.txt
def save_whitelist():
    with open("whitelist.txt", "") as f:
        pass


#! TODO: Write this function
# Extract the hyperlink set from the given webpage
def calculate_hyperlink(webpage: str):

    link_set = []
    num_links = 0

    return link_set, num_links

#! TODO: Write this function
# Count number of hyperlinks pointing to own domain
def get_self_ref_links(webpage: str):
    pass

#! TODO: Not Tested
# Ratio of hyperlinks points to foreign domains / total numer of hyperlinks
# ratio = [1 - (count_self_ref_links / num_hyperlinks)]
def calc_ratio(webpage: str, hyperlinks_set, num_hyperlinks: int, count_self_ref_links: int)

    ratio = 1 - (count_self_ref_links / num_hyperlinks)
    return ratio

#! TODO: Not Tested
# This is the algorithm defined in the paper. Check the README for the
# link to the paper.
def phishing_detection_algo(webpage: str):

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

    if ratio > threshold:
        print("Webpage is Phishing")
    else:
        print("Webpage is Legitimate")

        # Add valid domain to whitelist
        update_whitelist()
    
def main():
    g_threshold = int(input("Adjust threshold: "))

    load_whitelist()
    load_phishing_sites()
    
    for site in g_phishing_sites:
        phishing_detection_algo(site)

    save_whitelist()

if __name__ == "__main__":
    main()
