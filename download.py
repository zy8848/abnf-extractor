import urllib.request
import os
import re
from bs4 import BeautifulSoup
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor


# Specify the directory to save the files
save_dir = "abnf/rfc_docs"

# If the directory does not exist, create it
if not os.path.exists(save_dir):
    os.makedirs(save_dir)

# Get all RFC file list
def get_rfc_list():
    url = "https://www.rfc-editor.org/rfc/"
    req = urllib.request.Request(
        url,
        headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36'
        }
    )
    content = urllib.request.urlopen(req).read()
    soup = BeautifulSoup(content, "html.parser")
    links = soup.find_all("a")
    rfc_files = [link.get('href') for link in links if re.match(r"rfc\d+\.txt$", link.get('href', ''))]
    return rfc_files

# Download the specified RFC file
def download_rfc(rfc_file):
    # Construct URL
    url = f"https://www.rfc-editor.org/rfc/{rfc_file}"

    # Specify the path to save the file
    save_path = os.path.join(save_dir, rfc_file)

    # Try to download the file and save it to the specified directory, return None if download fails
    try:
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36'
            }
        )
        with urllib.request.urlopen(req) as response, open(save_path, 'wb') as out_file:
            data = response.read()  # a `bytes` object
            out_file.write(data)

        
    except Exception as e:
        print(f"An error occurred when downloading {rfc_file}, skipping this document")
        print(e)

# Get RFC file list
rfc_files = get_rfc_list()

print("Start downloading RFC files from https://www.rfc-editor.org/rfc")

# Use a ThreadPool to download RFC files, and use tqdm to display the progress bar
with ThreadPoolExecutor(max_workers=50) as executor:
    list(tqdm(executor.map(download_rfc, rfc_files), total=len(rfc_files)))

print("All RFC documents have been downloaded!")
