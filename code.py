import requests # Making GET requests
import os   
import sys
from dns import resolver # DNS Lookup
from bs4 import BeautifulSoup as bs
from urllib.parse import urlparse
import socket
import json
import random # Testing
from alive_progress import alive_bar # Progress bar
import threading # Multithreading for faster scanning
from whitelist import load_whitelist, init_whitelist, update_whitelist, save_whitelist

"""
Note: Each entry in g_whitelist is a key-value pair => {key, val} = {domain, ip}
"""
g_whitelist = {}

# Stores all sites from dataset
g_phishing_sites = []
g_valid_sites = []

# Stores the domains for each site from dataset
domains = []

# Count of urls
num_urls = 0

# Threshold value for phishing identification module from paper
g_threshold = 1010

# Sites that are determined to be safe or phishing
g_determined_phishing = []
g_determined_legitimate = []

# Metrics
true_positive_sum = 0
false_positive_sum = 0
false_negative_sum = 0
true_negative_sum = 0

# Used for Table 3 of the paper for comparisons
no_links_count_legit = 0
null_links_count_legit = 0
over_threshold_count_legit = 0

no_links_count_phishing = 0
null_links_count_phishing = 0
over_threshold_count_phishing = 0

total_pages_processed = 0
total_failed = 0 

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
            # content = requests.get(url).text[0]
            content = requests.get(url).json()
            g_phishing_sites, num_urls = get_urls_from_json(content)
            domains = extract_domains(g_phishing_sites)
            
        else:
            with open("json_data/FULL.json", "r") as f:
                content = json.load(f)
                g_phishing_sites, num_urls = get_urls_from_json(content)
                print("URLs:")
                domains = extract_domains(g_phishing_sites)     # Takes out only the domain name from each site
                # # [print(url) for url in domains]
                # print(f'Number of urls: {num_urls}')
                
                # for i in range(len(g_phishing_sites)):
                #     print(f"~~~~~~~\nurl: {g_phishing_sites[i]}\ndomain: {domains[i]}\n~~~~~~~")
                
                # len_g_p_sites = len(g_phishing_sites)
                # len_domains = len(domains)
                # print(f"Length of g_phishing_sites: {len_g_p_sites}")
                # print(f"Length of domains: {len_domains}")

# % GOOD
def scrape_valid_sites():
    with open("valid_sites.txt", "w") as f:
        content = requests.get("https://moz.com/top500")
        soup = bs(content.text, "html.parser")
        fun_dumpy = {}
        for ele in soup.find_all('a', {'class':'ml-2'}):
            buff = f"{ele['href']}\n"
            # print(buff)
            f.write(buff)

# % GOOD
def load_valid_sites():
    global g_valid_sites
    with open("./text_files/valid_sites.txt", "r") as f:
        lines = f.readlines()
        for line in lines:
            g_valid_sites.append(line[:-1])
    # print(g_valid_sites)


# ! TODO
# Still need to test this to make sure its good
# Include this in the main code to run on. Also, change call to chunkify when this gets passed
# to the threads
def prepare_data_for_run():
    """
    There are valid sites and phishing sites. To get results that we can compare to the author's,
    we need to run on both valid and phishing sites and update the metrics based on how this program
    characterizes each site. To do this, we need some sort of data structure where we can add the site
    and whether that site is phishing or not. Something like this:
    
    # Structure to represent a site
    data_model ={
            "site": url, 
            "domain": domain, 
            "phishing": boolean
        }
    
    # Array of data_models for each site
    test_data = [data_model]
    
    In the data model, we can include whether or not the site is phishing so we can determine
    the metrics that are used in the paper.
    
    All of the functions that are passing around data will need to be slightly modified to take
    care of this new structure. In fact, there will just be a refactoring of most of the code. But,
    at least right now things are working well enough.    
    """
    # Stores the new structure
    test_data = []
    
    # Setting the phishing sites
    for site in g_phishing_sites:
        test_data.append({
            "site":site,
            "domain":get_domain(site).replace("www", ""),
            "is_phishing": True
        })
    
    # Setting the valid sites
    for site in g_valid_sites:
        test_data.append({
            "site":site,
            "domain":get_domain(site).replace("www", ""),
            "is_phishing": False
        })
    
    return test_data


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
# i.e. www.facebook.com/thisisanexample/... -> facebook.com
def extract_domains(domains: list):
    return [urlparse(site).netloc.replace("www.", "") for site in domains]


#! TODO: Need to make sure that dns lookup is done correctly and aligns with what the authors intended
#! Read up on DNS poisoning
# Do a DNS lookup
# Return None if bad otherwise return IP
def dns_lookup(url: str):
    # Old way might also change gethostbyname->getaddrinfo
    """
    res = None
    try:
        res = socket.gethostbyname(url)
        # print(f"Host: {res}")
        return res
    except Exception as e:
        return None
    """
    # DNS resolve method from paper using dns.google from DNS translation
    url_to_search = url.replace("www.","")
    dns_query_string = f"https://dns.google/resolve?name={url_to_search}&type=A"
    response = requests.get(dns_query_string).json()
    if "Answer" not in response:
        print("Invalid Hostname")
        return False
    dns_translation = response["Answer"][0]["data"]
    # print(f"Full Response:\n{response}")
    # print(f"IP Translation:\n {dns_translation}")
    return dns_translation    

# TODO: TEST
def ip_match(domain: str, ip_to_match: str):
    return True if g_whitelist[domain] == ip_to_match else False

# Returns the domain of a url
def get_domain(webpage: str):
    domain = urlparse(webpage).netloc
    return domain

# % GOOD/
# Extract the hyperlink set from the given webpage
def calculate_hyperlink(url: str):
    resp=requests.get(url,timeout=5)
    soup=bs(resp.text,'html.parser')
    num_links=0
    link_set = []
    for link in soup.find_all('a'):
        temp=link.get('href')
        link_set.append(temp)
        num_links=num_links+1
    return link_set, num_links

# % GOOD -> Might do additional refining if other test cases arise
def is_self_referencing(url: str, page_domain: str):
    # print(f"url: {url} \t domain: {page_domain}\n")
    if len(url) > 0 and url[0] == "/": return True              # Link to a page on the site (file structure)
    elif page_domain.replace("www.", "") in url: return True    # Link has the same domain
    elif len(url) > 1 and url[0] == "#": return True            # ie. #head -> Scrolling link to certain html-ID is self-referencing on the page -> automatic scrolling on page

    # print("Not self referencing\n\n")
    return False

# % GOOD -> Seems good at the moment
# Count number of hyperlinks pointing to own domain
def get_self_ref_links(url: str):
    
    url_p=urlparse(url)
    domain = url_p.netloc
    
    resp=requests.get(url, timeout=5)
    soup=bs(resp.text,'html.parser')
    num_links=0
    
    for link in soup.find_all('a'):
        temp=link.get('href')
        if is_self_referencing(temp, domain):
            num_links=num_links+1
    return num_links

# % GOOD
# Get percentage of "#" hyperlinks in link set
def get_percentage_null_hyperlinks(link_set):
    
    global null_links_count
    
    num_links=0
    for link in link_set:
        if(link == "#"):    # NULL link  = "#"
            num_links=num_links+1
    if len(link_set) > 0:
        return ((num_links / len(link_set)) * 100), num_links
    else:
        return 0,0

# % GOOD
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
    print(f"Results: % null links: {ret_val}")


# % GOOD
# This should be done since this is directly from the paper
# Ratio of hyperlinks points to foreign domains / total numer of hyperlinks
# ratio = [1 - (count_self_ref_links / num_hyperlinks)]
def calc_ratio(num_hyperlinks: int, count_self_ref_links: int):
    if num_hyperlinks > 0:
        return (1 - (count_self_ref_links / num_hyperlinks))
    else:
        return 0

# % Good: Structure conforms to Algorithm described in the paper
# This is the algorithm defined in the paper. Check the README for the
# link to the paper.
# Returns 0 if page is phishing, otherwise returns 1
def phishing_identification_algo(webpage):
    
    global g_whitelist
    
    global over_threshold_count_legit
    global no_links_count_legit
    global null_links_count_legit
    
    global over_threshold_count_phishing
    global no_links_count_phishing
    global null_links_count_phishing
    
    # Flag if a page is phishing
    is_phishing = False
    
    # Extract hyperlink data and number of hyperlinks on a given page
    hyperlinks_set, num_hyperlinks = calculate_hyperlink(webpage["site"])    

    # No hyperlinks on webpage
    if len(hyperlinks_set) == 0:
        # print("There are no hyperlinks extracted from webpage")
        # print("Webpage is Phishing")
    
        if webpage["is_phishing"] == True:
            no_links_count_phishing += 1
        else:
            no_links_count_legit += 1
            
        is_phishing = True

    # Check for null hyperlinks
    # ? Paper says more than 80% of the hyperlinks are NULL then phishing
    ret_val, ret_num_links = get_percentage_null_hyperlinks(hyperlinks_set)
    
    # Page contains at least one null link
    if ret_num_links > 0:
        if webpage["is_phishing"] == True:
            null_links_count_phishing += 1
        else:
            null_links_count_legit += 1
        
    if ret_val > 80.0:
        # print("Webpage is Phishing")
        is_phishing = True
    
    count_self_ref_links = get_self_ref_links(webpage["site"])

    # ? This function relies on the results of the other two functions
    ratio = calc_ratio(num_hyperlinks, count_self_ref_links)

    if ratio > g_threshold:
        # print("Webpage is Phishing")
        
        if webpage["is_phishing"] == True:
            over_threshold_count_phishing += 1
        else:
            over_threshold_count_legit += 1
            
        is_phishing = True
    else:
        # print("Webpage is Legitimate")

        # Get domain and ip
        # domain = get_domain(webpage["site"])
        domain = webpage["domain"]
        dns_res = dns_lookup(domain)
        
        # Couldn't resolve hostname so declare as phishing
        if dns_res == False:
            return 0
        
        # Add valid domain to whitelist
        update_whitelist(domain, dns_res, g_whitelist)
        save_whitelist(g_whitelist)
        
    
    if is_phishing == True:
        return 0
    else:
        return 1


# Returns True if Legitimate page, otherwise returns False
def run(webpage):
    
    global g_determined_legitimate
    global g_determined_phishing
    
    """
    This function should model the system described in the paper.
    """

    # Need to get domain from webpage to check if in whitelist
    # OLD: domain = get_domain(webpage).replace("www.", "")
    domain = webpage["domain"]
    
    if domain in g_whitelist:
        # Check if Domain Matched from DNS lookup
        dns_res = dns_lookup(webpage["site"])
        
        # Couldn't resolve hostname so declare as phishing
        if dns_res == False:
            return False
        
        if ip_match(domain, dns_res): # IP matched
            # Legitimate page
            # print("Webpage is Legitimate")
            return True
        else: # IP Did not match
            # Phishing site
            # print("Webpage is Phishing")
            return False
    else: # page not in whitelist
        ret_val = phishing_identification_algo(webpage)
        if ret_val != 0:
            # not phishing
            g_determined_legitimate.append(webpage["site"])
            return True
        else: 
            # phishing
            g_determined_phishing.append(webpage["site"])
            return False

# Mirror the same analysis as found in the paper
def analyze_results():
    # global over_threshold_count_legit
    # global no_links_count_legit
    # global null_links_count_legit
    
    # global over_threshold_count_phishing
    # global no_links_count_phishing
    # global null_links_count_phishing
    
    total_legit = len(g_valid_sites)
    total_phishing = len(g_phishing_sites)
    
    if total_phishing > 0 and total_legit > 0:
        true_positive_rate = (true_positive_sum / total_phishing) * 100
        false_positive_rate = (false_positive_sum / total_phishing ) * 100
        false_negative_rate = (false_negative_sum / total_legit) * 100
        true_negative_rate = (true_negative_sum / total_legit) * 100
        accuracy = ((true_negative_sum + true_positive_sum) / (total_legit + total_failed)) * 100
    
        print("\nCompare to Table 4 in paper")
        print(f"Total Phishing: {total_phishing}")
        print(f"\nTotal Legitimate: {total_legit}")
        print(f"Phishing classified as Phishing: {true_positive_sum}\tTrue Positive Rate: {true_positive_rate}")
        print(f"Phishing classified as Legitimate: {false_positive_sum}\tFalse Positive Rate: {false_positive_rate}")
        print(f"Legitimate classified as Phishing: {false_negative_sum}\tFalse Negative Rate: {false_negative_rate}")
        print(f"Legitmate classified as Legitimate: {true_negative_sum}\tTrue Negative Rate: {true_negative_rate}")
        print(f"Accuracy: {accuracy}")
    
    
        print("\nCompare to Table 3 in paper")
        print(f"Total Phishing: {total_phishing}")
        print(f"No. of webpages that contain no hyperlinks: {no_links_count_phishing}")
        print(f"No. of webpages that contain null links: {null_links_count_phishing}")
        print(f"No. of webpages pointing to a foreign domain(>= threshold): {over_threshold_count_phishing}")
        print(f"Total Legitimate: {total_legit}")
        print(f"No. of webpages that contain no hyperlinks: {no_links_count_legit}")
        print(f"No. of webpages that contain null links: {null_links_count_legit}")
        print(f"No. of webpages pointing to a foreign domain(>= threshold): {over_threshold_count_legit}")
        
        
        percent_phishing = 100 * (len(g_determined_phishing) / (total_legit + total_phishing))
        percent_legit = 100 * (len(g_determined_legitimate) / (total_legit + total_phishing))
        
        print("\nCompare to Table 2 in paper")
        print(f"Threshold (%): {g_threshold}")
        print(f"Phishing Webpages: {percent_phishing}")
        print(f"Legitimate Webpages: {percent_legit}")
        
        print(f"Total pages failed to run: {total_pages_processed}")
        print(f"Total pages that ran succesfully: {total_failed}")
    
    
    
    

# Used for making chunks
def chunkify(lst,n):
    return [lst[i::n] for i in range(n)]

# Use threads to speed up scanning
def launch_threads(prog_bar_obj, num_threads, test_data):
    
    # Divide chunks of webpages to each thread
    chunks = chunkify(test_data, num_threads)
    
    # Holds the Thread objects
    threads = []
    
    # Give each thread webpages
    for i in range(num_threads):
        t = threading.Thread(name=f"Thread {i}", target=do_threading, args=(chunks[i],prog_bar_obj,) )
        t.setDaemon(True)
        threads.append(t)
    
    # Start threads
    print(f"Starting {num_threads} threads.")
    for i in range(num_threads):
        threads[i].start()
    
    # Join threads
    # ! If this is excluded, it breaks code
    for i in range(num_threads):
        threads[i].join()
    
        

def main():
    global g_whitelist
    global g_threshold
    global total_pages_processed
    global total_failed
    
    res = int(input("Choose one of the following:\n1. Non-threading (Not recommended)\n2. Threading (Do this)\n"))
    if res == 1:
        do_regular()
    else:
        # Need to pass threshold 
        g_threshold = int(input("Adjust threshold: "))
        num_threads = int(input("Enter number of threads to use: "))

        # Init whitelist as empty
        g_whitelist = init_whitelist()
        
        # Load in the site data for testing
        load_phishing_sites()
        load_valid_sites()
        
        # Pack data for testing
        test_data = prepare_data_for_run()  
        
        print("Launching threads")  
        with alive_bar(len(test_data)) as bar:  
            launch_threads(bar, num_threads, test_data)
    
    analyze_results()

# No threading here -> too slow
def do_regular():
    
    g_threshold = int(input("Adjust threshold: "))
    
    init_whitelist()
    load_phishing_sites()
    load_valid_sites()
    
    total_pages_processed = 0
    total_failed = 0    
    
    with alive_bar(len(g_phishing_sites)) as bar:
        for site in g_phishing_sites:
            # print(f"Running: {site}")
            total_pages_processed+=1
            bar()
            try:
                res = run(site)
            except Exception as e:
                # Uncomment to see the exception raised
                # print(f"Exception caught: {e}")
                total_failed+=1
                continue
            os.system('clear')
            positionStr = 'Total pages processed: ' + str(total_pages_processed).rjust(5)
            positionStr += '\nTotal Failed:          ' + str(total_failed).rjust(5)
            positionStr += '\nTotal Legitimate:      ' + str(len(g_determined_legitimate)).rjust(5)
            positionStr += '\nTotal Phishing:        ' + str(len(g_determined_phishing)).rjust(5)
            print(positionStr, end='\n')
            print('\b' * len(positionStr), end='', flush=True)    

# Check to see if site was classified correctly 
# res will be False if it is phishing, otherwise its True
def assert_res(site, res):
    
    global true_positive_sum
    global false_positive_sum 
    global false_negative_sum
    global true_negative_sum
    
    # Site is Phishing but model says its le
    if site["is_phishing"] == True and res == True:
        # % False Positive
        # print("False Positive")
        false_positive_sum+=1
    # Site is Phishing and model says its phishing
    elif site["is_phishing"] == True and res == False:
        # % True Positive
        # print("True Positive")
        true_positive_sum+=1
    # Site is Legit and model says its legit
    elif site["is_phishing"] == False and res == True:
        # % True Negative
        # print("True Negative")
        true_negative_sum+=1
    # Site is Legit but model says its phishing
    elif site["is_phishing"] == False and res == False:
        # % False Negative
        # print("False Negative")
        false_negative_sum+=1
    
    # print("HERE")
        
# This is used 
def do_threading(sites, bar):
    global total_pages_processed
    global total_failed

    for site in sites:
        # print(f"Running: {site}")
        bar()
        try:
            res = run(site)
            
            assert_res(site, res)
        except Exception as e:
            # Uncomment to see the exception raised
            # print(f"Exception caught: {e}")
            total_failed += 1
            continue
        total_pages_processed += 1
   
if __name__ == "__main__":
    main()
    # load_phishing_sites()
    # test_whitelist()l
    # test_extraction_functions()
    # dns_lookup('facebwook.com')
    # load_valid_sites()
        