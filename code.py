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
true_positive_rate = 1
false_positive_rate = 1
false_negative_rate = 1
true_negative_rate = 1
accuracy = 1

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
    with open("valid_sites.txt", "r") as f:
        lines = f.readlines()
        for line in lines:
            g_valid_sites.append(line[:-1])
    print(g_valid_sites)

# ! TODO
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
    
    pass


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
  num_links=0
  for link in link_set:
    if(link == "#"):    # NULL link  = "#"
      num_links=num_links+1
  return ((num_links / len(link_set)) * 100)

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
    ratio = 1 - (count_self_ref_links / num_hyperlinks)
    return ratio

# % Good: Structure conforms to Algorithm described in the paper
# This is the algorithm defined in the paper. Check the README for the
# link to the paper.
# Returns 0 if page is phishing, otherwise returns 1
def phishing_identification_algo(webpage: str):

    # Extract hyperlink data and number of hyperlinks on a given page
    hyperlinks_set, num_hyperlinks = calculate_hyperlink(webpage)    

    if len(hyperlinks_set) == 0:
        # print("There are no hyperlinks extracted from webpage")
        # print("Webpage is Phishing")
        return 0

    # Check for null hyperlinks
    # ? Paper says more than 80% of the hyperlinks are NULL then phishing
    if get_percentage_null_hyperlinks(hyperlinks_set) > 80.0:
        # print("Webpage is Phishing")
        return 0
    
    count_self_ref_links = get_self_ref_links(webpage)

    # ? This function relies on the results of the other two functions
    ratio = calc_ratio(num_hyperlinks, count_self_ref_links)

    if ratio > g_threshold:
        # print("Webpage is Phishing")
        return 0
    else:
        # print("Webpage is Legitimate")

        # Get domain and ip
        domain = get_domain(webpage)
        dns_res = dns_lookup(domain)
        
        # Couldn't resolve hostname so declare as phishing
        if dns_res == False:
            return 0
        
        # Add valid domain to whitelist
        update_whitelist(domain, dns_res)
        save_whitelist()

    return 1

# !! Need to modify this function to put if site is actually phishing or not for
# !! updating the metrics. Also, have this function update the global metrics as well
# Returns 1 if Legitimate page, otherwise returns 0
def run(webpage: str):
    
    """
    This function should model the system described in the paper.
    """

    # Need to get domain from webpage to check if in whitelist
    domain = get_domain(webpage).replace("www.", "")
    
    if domain in g_whitelist:
        # Check if Domain Matched from DNS lookup
        dns_res = dns_lookup(webpage)
        
        # Couldn't resolve hostname so declare as phishing
        if dns_res == False:
            return 0
        
        if ip_match(domain, dns_res): # IP matched
            # Legitimate page
            # print("Webpage is Legitimate")
            return 1
        else: # IP Did not match
            # Phishing site
            # print("Webpage is Phishing")
            return 0
    else: # page not in whitelist
        ret_val = phishing_identification_algo(webpage)
        if ret_val != 0:
            # not phishing
            g_determined_legitimate.append(webpage)
            return 1
        else: 
            # phishing
            g_determined_phishing.append(webpage)
            return 0
    
# ! TODO
# !! Need to use the metrics that are updated from the function above.
# Mirror the same analysis as found in the paper
def analyze_results():
    print("Analyzing the results.")
    print(f"True Positive Rate: {true_positive_rate}")
    print(f"False Positive Rate: {false_positive_rate}")
    print(f"False Negative Rate: {false_negative_rate}")
    print(f"True Negative Rate: {true_negative_rate}")
    print(f"Accuracy: {accuracy}")
    
    

# Used for making chunks
def chunkify(lst,n):
    return [lst[i::n] for i in range(n)]

# Use threads to speed up scanning
def launch_threads(prog_bar_obj, num_threads):
    # Divide chunks of webpages to each thread
    chunks = chunkify(g_phishing_sites, num_threads)
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
    res = int(input("Choose one of the following:\n1. Non-threading (regular)\n2. Threading\n"))
    if res == 1:
        do_regular()
    else:
        g_threshold = int(input("Adjust threshold: "))
        num_threads = int(input("Enter number of threads to use: "))

        init_whitelist()
        load_phishing_sites()
        load_valid_sites()
        total_pages_processed = 0
        total_failed = 0    
        print("Launching threads")  
        with alive_bar(len(g_phishing_sites)) as bar:  
            launch_threads(bar, num_threads)
    
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
    
def do_threading(sites, bar):

    for site in sites:
        # print(f"Running: {site}")
        bar()
        try:
            res = run(site)
        except Exception as e:
            # Uncomment to see the exception raised
            # print(f"Exception caught: {e}")
            continue
            
    
   
if __name__ == "__main__":
    main()
    # load_phishing_sites()
    # test_whitelist()l
    # test_extraction_functions()
    # dns_lookup('facebwook.com')
    # load_valid_sites()
        