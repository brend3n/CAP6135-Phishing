import requests
import os
import sys

g_whitelist = []


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

def main():
    load_whitelist()
    
    save_whitelist()

if __name__ == "__main__":
    main()
