import random
import json

# % GOOD
# Loads the whitelist values into the script
def load_whitelist():
    # global g_whitelist
    with open("whitelist.txt", "r") as f:
       g_whitelist = json.load(f)
    
    return g_whitelist

# % GOOD
# Initializes an empty dictionary
def init_whitelist():
    g_whitelist = {}
    return g_whitelist

# % GOOD
# Adds a new key-value pair to the whitelist
def update_whitelist(domain: str, ip: str, g_whitelist: dict):
    g_whitelist[domain] = ip

# % GOOD
# Save the current whitelist locally to whitelist.txt
def save_whitelist(g_whitelist):
    with open("whitelist.txt", "w") as f:
        
        # Dump contents of dictionary to file as json object
        f.write(json.dumps(g_whitelist))

# % GOOD
def test_whitelist(g_whitelist):
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