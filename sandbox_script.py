# sandbox_script.py - Version 1.2 avec webdriver-manager

import sys
import json
import socket
import base64 # Pour encoder l'image
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
    # On définit une taille de fenêtre pour avoir une capture d'écran cohérente
    chrome_options.add_argument("--window-size=1280,800")
    chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36")

    # Utilisation de webdriver-manager pour gérer ChromeDriver automatiquement
    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=chrome_options)
    
    result = { "status": "error" } # Initialisation

    try:
        driver.get(url)
        # On attend un peu que la page se charge (ex: que le body soit présent)
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "body")))

        final_url = driver.current_url
        domain = final_url.split('/')[2]
        ip_address = "N/A"
        try:
            ip_address = socket.gethostbyname(domain)
        except socket.gaierror:
            pass # L'adresse n'a pas pu être résolue

        # Prise de la capture d'écran
        screenshot_bytes = driver.get_screenshot_as_png()
        screenshot_base64 = base64.b64encode(screenshot_bytes).decode('utf-8')

        # Préparation du résultat en JSON
        result = {
            "initial_url": url,
            "final_url": final_url,
            "final_ip": ip_address,
            "screenshot_base64": screenshot_base64, # On ajoute l'image encodée
            "status": "success"
        }
    except Exception as e:
        result["error"] = str(e)
    finally:
        driver.quit()

    # Le résultat est printé en JSON pour être récupéré par l'application principale
    print(json.dumps(result))

if __name__ == "__main__":
    if len(sys.argv) > 1:
        url_to_analyze = sys.argv[1]
        analyze_url(url_to_analyze)
    else:
        print(json.dumps({"status": "error", "error": "No URL provided"})) 