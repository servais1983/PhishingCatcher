# sandbox_script.py - Version 1.2 avec webdriver-manager

import sys
import json
import socket
import base64 # To encode the image
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager

def analyze_url(url):
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    # We define a window size for consistent screenshot
    chrome_options.add_argument("--window-size=1280,800")
    chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36")

    # Using webdriver-manager to automatically manage ChromeDriver
    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=chrome_options)
    
    result = { "status": "error" } # Initialization

    try:
        driver.get(url)
        # We wait a bit for the page to load (e.g., body to be present)
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "body")))

        final_url = driver.current_url
        domain = final_url.split('/')[2]
        ip_address = "N/A"
        try:
            ip_address = socket.gethostbyname(domain)
        except socket.gaierror:
            pass # Address could not be resolved

        # Taking screenshot
        screenshot_bytes = driver.get_screenshot_as_png()
        screenshot_base64 = base64.b64encode(screenshot_bytes).decode('utf-8')

        # Preparing JSON result
        result = {
            "initial_url": url,
            "final_url": final_url,
            "final_ip": ip_address,
            "screenshot_base64": screenshot_base64, # We add the encoded image
            "status": "success"
        }
    except Exception as e:
        result["error"] = str(e)
    finally:
        driver.quit()

    # The result is printed in JSON to be retrieved by the main application
    print(json.dumps(result))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        url_to_analyze = sys.argv[1]
        analyze_url(url_to_analyze)
    else:
        print(json.dumps({"status": "error", "error": "No URL provided"})) 