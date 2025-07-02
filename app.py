# app.py - Version 0.7 - Améliorations et Export PDF

import streamlit as st
import email
from email.header import decode_header
import os
from bs4 import BeautifulSoup
import ollama
import json
import docker
from fpdf import FPDF
from datetime import datetime
import base64
import requests
import time
import hashlib
import io

# --- CONFIGURATION ---
# Clé API VirusTotal pour l'analyse Threat Intelligence
VT_API_KEY = "VOTRE_CLE_API_VIRUSTOTAL_ICI"
VT_API_URL_REPORT = "https://www.virustotal.com/api/v3/urls/"

# --- Fonctions d'extraction et d'analyse (les précédentes sont inchangées) ---
def decode_subject(header):
    if header is None: return ""
    decoded_parts = decode_header(header)
    subject = []
    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            encoding = encoding if encoding else 'utf-8'
            try:
                subject.append(part.decode(encoding, errors='ignore'))
            except LookupError:
                subject.append(part.decode('utf-8', errors='ignore'))
        else:
            subject.append(part)
    return "".join(subject)

def extract_email_body(msg):
    html_body = ""
    text_body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            if "attachment" not in content_disposition:
                if content_type == "text/plain" and not text_body:
                    text_body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore')
                elif content_type == "text/html":
                    html_body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore')
    else:
        if msg.get_content_type() == "text/html":
            html_body = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='ignore')
        else:
            text_body = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='ignore')
    return html_body if html_body else text_body

def extract_urls(html_content):
    if not html_content: return []
    soup = BeautifulSoup(html_content, 'html.parser')
    urls = []
    for a_tag in soup.find_all('a', href=True):
        if a_tag['href'] and not a_tag['href'].startswith('#'):
            urls.append({"text": a_tag.get_text().strip(), "url": a_tag['href']})
    return urls

def analyze_security_headers(msg):
    results = {"spf": "Non trouvé", "dkim": "Non trouvé", "dmarc": "Non trouvé", "path": []}
    auth_results = msg.get('Authentication-Results', '')
    if auth_results:
        parts = auth_results.split(';')
        for part in parts:
            part = part.strip()
            if part.lower().startswith('spf='): results['spf'] = part.split('=')[1].split(' ')[0]
            elif part.lower().startswith('dkim='): results['dkim'] = part.split('=')[1].split(' ')[0]
            elif part.lower().startswith('dmarc='): results['dmarc'] = part.split('=')[1].split(' ')[0]
    received_headers = msg.get_all('Received', [])
    results['path'] = received_headers
    return results

@st.cache_data
def analyze_content_with_ai(text_content):
    """Analyse le contenu avec Phi-3 via Ollama et attend une réponse JSON."""
    soup = BeautifulSoup(text_content, 'html.parser')
    clean_text = soup.get_text(separator=' ', strip=True)
    
    if len(clean_text) > 4000:
        clean_text = clean_text[:4000]

    try:
        # Essayer d'abord avec Phi-3
        response = ollama.chat(
            model='phi3',
            format='json',
            messages=[
                {
                    'role': 'system',
                    'content': """
                    Tu es un expert en cybersécurité spécialisé dans l'analyse de phishing.
                    Analyse le texte de l'email suivant. 
                    Réponds UNIQUEMENT avec un objet JSON contenant trois clés :
                    1. "classification": "phishing", "légitime", ou "spam".
                    2. "score": un entier de 0 (très sûr) à 100 (phishing certain).
                    3. "raison": une phrase courte (en français) expliquant ta décision.
                    """,
                },
                {
                    'role': 'user',
                    'content': clean_text,
                },
            ],
        )
        return json.loads(response['message']['content'])

    except Exception as e:
        try:
            # Fallback avec un modèle plus simple
            response = ollama.chat(
                model='llama2',
                messages=[
                    {
                        'role': 'system',
                        'content': 'Tu es un expert en cybersécurité. Analyse ce texte d\'email et réponds avec: "phishing", "légitime", ou "spam" suivi d\'un score de 0 à 100 et d\'une raison.',
                    },
                    {
                        'role': 'user',
                        'content': clean_text,
                    },
                ],
            )
            # Parse la réponse simple
            content = response['message']['content'].lower()
            if 'phishing' in content:
                classification = 'phishing'
                score = 85
            elif 'spam' in content:
                classification = 'spam'
                score = 60
            else:
                classification = 'légitime'
                score = 20
            return {
                "classification": classification,
                "score": score,
                "raison": "Analyse avec modèle de fallback"
            }
        except Exception as e2:
            return {
                "classification": "erreur",
                "score": 0,
                "raison": f"Erreur de communication avec l'IA locale (Ollama) : {e}"
            }

# --- NOUVELLE FONCTION POUR L'ANALYSE DYNAMIQUE ---
@st.cache_resource
def get_docker_client():
    """Initialise le client Docker et construit l'image si elle n'existe pas."""
    client = docker.from_env()
    try:
        st.write("Vérification de l'image Docker de la sandbox...")
        client.images.get("phishing-sandbox:latest")
        st.write("Image 'phishing-sandbox' trouvée.")
    except docker.errors.ImageNotFound:
        st.warning("Image 'phishing-sandbox' non trouvée. Construction en cours... (peut prendre plusieurs minutes)")
        client.images.build(path=".", dockerfile="Dockerfile", tag="phishing-sandbox:latest")
        st.success("Image de la sandbox construite avec succès !")
    return client

def run_dynamic_analysis(docker_client, url):
    """Lance l'analyse d'une URL dans un conteneur Docker isolé."""
    try:
        container = docker_client.containers.run(
            "phishing-sandbox:latest",
            command=[url],
            detach=False,
            remove=True
        )
        result_json = container.decode('utf-8')
        return json.loads(result_json)
    except Exception as e:
        return {"status": "error", "error": f"Erreur lors de l'exécution du conteneur : {e}"}

# --- NOUVELLE FONCTION D'ANALYSE THREAT INTELLIGENCE ---
@st.cache_data
def analyze_with_virustotal(url_to_check):
    """Analyse une URL avec l'API de VirusTotal."""
    if not VT_API_KEY or VT_API_KEY == "VOTRE_CLE_API_VIRUSTOTAL":
        return {"status": "error", "message": "Clé API VirusTotal non configurée."}

    # VirusTotal a besoin de l'ID de l'URL, qui est un hash de l'URL encodée
    url_id = base64.urlsafe_b64encode(url_to_check.encode()).decode().strip("=")
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(VT_API_URL_REPORT + url_id, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            return {
                "status": "success",
                "malicious": stats.get('malicious', 0),
                "suspicious": stats.get('suspicious', 0),
                "harmless": stats.get('harmless', 0),
                "link": f"https://www.virustotal.com/gui/url/{url_id}"
            }
        elif response.status_code == 404:
            # L'URL n'a jamais été analysée, on peut la soumettre (non implémenté ici pour rester simple)
            return {"status": "info", "message": "URL inconnue de VirusTotal."}
        else:
            return {"status": "error", "message": f"Erreur API VT : {response.status_code}"}
    except Exception as e:
        return {"status": "error", "message": f"Erreur de connexion à VirusTotal : {e}"}

# --- NOUVELLES FONCTIONS D'ANALYSE DES PIÈCES JOINTES ---
def extract_attachments(msg):
    """Extrait les pièces jointes d'un objet email."""
    attachments = []
    for part in msg.walk():
        # On cherche les parties qui sont des pièces jointes
        if part.get_content_maintype() == 'multipart' or part.get('Content-Disposition') is None:
            continue
        
        filename = part.get_filename()
        if filename:
            # On calcule le hash du contenu de la pièce jointe
            file_bytes = part.get_payload(decode=True)
            file_hash = hashlib.sha256(file_bytes).hexdigest()
            attachments.append({"filename": filename, "hash": file_hash})
    return attachments

@st.cache_data
def analyze_hash_with_virustotal(file_hash):
    """Analyse un hash de fichier avec l'API de VirusTotal."""
    if not VT_API_KEY or VT_API_KEY == "VOTRE_CLE_API_VIRUSTOTAL":
        return {"status": "error", "message": "Clé API VirusTotal non configurée."}

    # L'endpoint pour les fichiers est différent de celui des URLs
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            return {
                "status": "success",
                "malicious": stats.get('malicious', 0),
                "suspicious": stats.get('suspicious', 0),
                "harmless": stats.get('harmless', 0),
                "link": f"https://www.virustotal.com/gui/file/{file_hash}"
            }
        elif response.status_code == 404:
            return {"status": "info", "message": "Fichier inconnu de VirusTotal."}
        else:
            return {"status": "error", "message": f"Erreur API VT : {response.status_code}"}
    except Exception as e:
        return {"status": "error", "message": f"Erreur de connexion à VirusTotal : {e}"}

# --- NOUVELLE FONCTION POUR LE RAPPORT PDF ---
class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'Rapport d\'Analyse de Phishing - Outil APLA', 0, 1, 'C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.set_fill_color(200, 220, 255)
        self.cell(0, 6, title, 0, 1, 'L', 1)
        self.ln(4)

    def chapter_body(self, body):
        self.set_font('Arial', '', 10)
        # Nettoyer les caractères problématiques
        clean_body = str(body).replace('\x00', '').replace('\ufffd', '').replace('\u2028', ' ').replace('\u2029', ' ')
        self.multi_cell(0, 5, clean_body)
        self.ln()

    def add_section(self, title, content_dict):
        self.chapter_title(title)
        for key, value in content_dict.items():
            self.set_font('Arial', 'B', 10)
            # Nettoyer les caractères problématiques
            clean_key = str(key).replace('\x00', '').replace('\ufffd', '').replace('\u2028', ' ').replace('\u2029', ' ')
            self.multi_cell(0, 5, f"{clean_key}:")
            self.set_font('Arial', '', 10)
            # S'assure que la valeur est une string et nettoie les caractères problématiques
            value_str = str(value) if value is not None else "Non disponible"
            value_str = value_str.replace('\x00', '').replace('\ufffd', '').replace('\u2028', ' ').replace('\u2029', ' ')
            # Limiter la longueur pour éviter les problèmes d'espacement
            if len(value_str) > 100:
                words = value_str.split()
                line = ""
                for word in words:
                    if len(line + word) < 100:
                        line += word + " "
                    else:
                        self.multi_cell(0, 5, line.strip())
                        line = word + " "
                if line:
                    self.multi_cell(0, 5, line.strip())
            else:
                self.multi_cell(0, 5, value_str)
            self.ln(2)

def generate_pdf_report(report_data):
    """Génère un rapport PDF à partir des données d'analyse collectées."""
    try:
        pdf = PDF()
        pdf.add_page()
        
        # Titre principal
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'Rapport APLA - Analyse de Phishing', 0, 1, 'C')
        pdf.ln(10)
        
        # Informations de base
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 8, 'Informations Generales:', 0, 1, 'L')
        pdf.set_font('Arial', '', 10)
        pdf.cell(0, 6, f"Fichier: {report_data['filename']}", 0, 1, 'L')
        pdf.cell(0, 6, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1, 'L')
        pdf.cell(0, 6, f"De: {str(report_data['headers']['from'])[:40]}", 0, 1, 'L')
        pdf.cell(0, 6, f"Sujet: {str(report_data['headers']['subject'])[:40]}", 0, 1, 'L')
        pdf.ln(5)
        
        # Analyse IA
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 8, 'Analyse IA (Phi-3):', 0, 1, 'L')
        pdf.set_font('Arial', '', 10)
        pdf.cell(0, 6, f"Classification: {report_data['ai_report']['classification']}", 0, 1, 'L')
        pdf.cell(0, 6, f"Score: {report_data['ai_report']['score']}%", 0, 1, 'L')
        pdf.cell(0, 6, f"Raison: {str(report_data['ai_report']['raison'])[:60]}", 0, 1, 'L')
        pdf.ln(5)
        
        # URLs détectées
        if report_data['urls']:
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 8, 'URLs Detectees:', 0, 1, 'L')
            pdf.set_font('Arial', '', 10)
            for url_item in report_data['urls'][:5]:  # Limiter à 5 URLs
                clean_url = str(url_item['url']).replace('\x00', '').replace('\ufffd', '')[:50]
                pdf.cell(0, 6, f"- {clean_url}", 0, 1, 'L')
            pdf.ln(5)
        
        # Pièces jointes
        if report_data.get("attachments"):
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 8, 'Pieces Jointes:', 0, 1, 'L')
            pdf.set_font('Arial', '', 10)
            for att in report_data["attachments"][:3]:  # Limiter à 3 pièces jointes
                clean_filename = str(att['filename']).replace('\x00', '').replace('\ufffd', '')[:30]
                pdf.cell(0, 6, f"- {clean_filename}", 0, 1, 'L')
                pdf.cell(0, 6, f"  Hash: {att['hash'][:20]}...", 0, 1, 'L')
            pdf.ln(5)
        
        # IOCs
        if report_data['iocs']:
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 8, 'Indicateurs de Compromission:', 0, 1, 'L')
            pdf.set_font('Arial', '', 10)
            for ioc in report_data['iocs'][:5]:  # Limiter à 5 IOCs
                clean_ioc = str(ioc).replace('\x00', '').replace('\ufffd', '')[:60]
                pdf.cell(0, 6, f"- {clean_ioc}", 0, 1, 'L')
        
        return bytes(pdf.output(dest='S'))
    except Exception as e:
        # En cas d'erreur, créer un PDF très simple
        pdf = PDF()
        pdf.add_page()
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'Rapport APLA', 0, 1, 'C')
        pdf.set_font('Arial', '', 12)
        pdf.cell(0, 10, 'Analyse terminee avec succes', 0, 1, 'C')
        pdf.cell(0, 10, f"Fichier: {report_data['filename']}", 0, 1, 'C')
        return bytes(pdf.output(dest='S'))

# --- Interface Streamlit ---
st.set_page_config(layout="wide", page_title="APLA - Analyseur de Phishing")
st.title("🕵️ APLA - Analyseur de Phishing (avec IA Phi-3)")

uploaded_file = st.file_uploader("Choisissez un fichier email", type=['eml', 'msg'])

if uploaded_file is not None:
    # On initialise un dictionnaire qui contiendra tout le rapport
    report_data = {
        "filename": uploaded_file.name,
        "headers": {},
        "ai_report": {},
        "security": {},
        "urls": [],
        "iocs": [] # Nouvelle liste pour les IOCs
    }

    temp_file_path = os.path.join("temp_email_file")
    with open(temp_file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())

    try:
        # --- PHASE 1 : COLLECTE DE TOUTES LES DONNÉES ---
        
        # Extraction des données de base
        subject, from_, to, date, body = "", "", "", "", ""
        security_report = {}
        
        if uploaded_file.name.endswith(".eml"):
            with open(temp_file_path, "rb") as f: msg = email.message_from_binary_file(f)
            subject, from_, to, date = decode_subject(msg['subject']), decode_subject(msg['from']), decode_subject(msg['to']), msg['date']
            body = extract_email_body(msg)
            security_report = analyze_security_headers(msg)
        elif uploaded_file.name.endswith(".msg"):
            st.warning("L'analyse des fichiers .msg nécessite la bibliothèque extract-msg. Utilisez un fichier .eml pour une analyse complète.")
            st.error("Fichier .msg non supporté dans cette version. Veuillez convertir en .eml ou utiliser un autre fichier.")
            st.stop()
        
        # Stockage des données collectées
        report_data["headers"] = {"from": from_, "to": to, "subject": subject, "date": date}
        report_data["security"] = security_report
        report_data["urls"] = extract_urls(body)
        report_data["ai_report"] = analyze_content_with_ai(body)
        
        # Extraction des pièces jointes
        attachments = extract_attachments(msg) if uploaded_file.name.endswith(".eml") else []
        report_data["attachments"] = attachments # On sauvegarde pour le PDF
        
        # Centralisation des IOCs
        for url_item in report_data["urls"]:
            report_data["iocs"].append(f"URL: {url_item['url']}")
        if security_report.get('spf', '').lower() != 'pass':
            report_data["iocs"].append(f"SPF non conforme: {security_report.get('spf')}")
        
        # --- PHASE 2 : AFFICHAGE AMÉLIORÉ DANS L'INTERFACE ---
        
        st.subheader("Synthèse de l'Analyse IA")
        
        ai_report = report_data["ai_report"]
        score = ai_report.get('score', 0)
        classification = ai_report.get('classification', 'inconnu').upper()
        reason = ai_report.get('raison', 'Aucune explication fournie.')

        if classification == "PHISHING":
            st.error(f"**Classification : {classification} | Score de risque : {score}%**")
        elif classification == "SPAM":
            st.warning(f"**Classification : {classification} | Score de risque : {score}%**")
        elif classification == "LÉGITIME":
            st.success(f"**Classification : {classification} | Score de risque : {score}%**")
        else:
            st.info(f"**Classification : {classification}**")

        st.progress(score / 100)
        st.write(f"**Justification de l'IA :** *{reason}*")

        # NOUVEL AFFICHAGE DES IOCs
        with st.expander("🚨 Voir les Indicateurs de Compromission (IOCs)"):
            if report_data["iocs"]:
                st.code("\n".join(report_data["iocs"]))
            else:
                st.info("Aucun IOC direct détecté.")

        with st.expander("🛡️ Voir l'analyse des en-têtes de sécurité"):
            if security_report:
                def display_status(label, status):
                    if status.lower() == 'pass': st.success(f"**{label} :** {status}")
                    elif status.lower() in ['fail', 'softfail']: st.error(f"**{label} :** {status}")
                    else: st.warning(f"**{label} :** {status}")
                col1, col2, col3 = st.columns(3)
                with col1: display_status("SPF", security_report.get('spf', 'Non trouvé'))
                with col2: display_status("DKIM", security_report.get('dkim', 'Non trouvé'))
                with col3: display_status("DMARC", security_report.get('dmarc', 'Non trouvé'))
                st.code("Chemin de l'email (Received Headers):\n\n" + "\n\n".join(security_report.get('path', ['Non trouvé'])))
            else:
                st.info("Analyse des en-têtes non disponible pour les fichiers .msg.")

        with st.expander("🔗 Voir l'analyse des URLs"):
            urls_found = report_data["urls"]
            if not urls_found:
                st.info("Aucun lien hypertexte (URL) trouvé.")
            else:
                for i, item in enumerate(urls_found):
                    st.write(f"**Texte affiché :** `{item['text']}`")
                    st.write(f"**URL réelle :** `{item['url']}`")
                    if ("http" in item['text'] or "www" in item['text']) and item['text'] != item['url']:
                        st.error("⚠️ **ALERTE :** L'URL affichée est différente de l'URL réelle !")
                    
                                        # On crée des colonnes pour aligner les boutons
                    col1, col2 = st.columns(2)
                    
                    # Initialiser l'état de la session si ce n'est pas déjà fait
                    if 'dynamic_reports' not in st.session_state:
                        st.session_state.dynamic_reports = {}

                    with col1:
                        if st.button(f"🔎 Lancer l'analyse dynamique", key=f"dyn_{i}"):
                            with st.spinner(f"Analyse de {item['url']} dans la sandbox..."):
                                docker_client = get_docker_client() # Cette fonction gère la reconstruction de l'image
                                dynamic_report = run_dynamic_analysis(docker_client, item['url'])
                                
                                # On sauvegarde le rapport dans la session
                                st.session_state.dynamic_reports[item['url']] = dynamic_report

                                if dynamic_report.get("status") == "success":
                                    st.success("Analyse dynamique terminée !")

                                    # Affichage des métadonnées
                                    st.json({
                                        "URL initiale": dynamic_report.get("initial_url"),
                                        "URL finale (après redirection)": dynamic_report.get("final_url"),
                                        "IP du serveur final": dynamic_report.get("final_ip")
                                    })

                                    # NOUVELLE PARTIE : AFFICHAGE DE LA CAPTURE D'ÉCRAN
                                    if "screenshot_base64" in dynamic_report:
                                        st.subheader("📸 Capture d'écran de la page finale")
                                        # On décode l'image depuis le base64
                                        img_bytes = base64.b64decode(dynamic_report["screenshot_base64"])
                                        st.image(img_bytes, caption="Résultat de la visite dans la sandbox", use_column_width=True)

                                else:
                                    st.error("L'analyse dynamique a échoué.")
                                    st.json(dynamic_report) # Affiche l'erreur

                    with col2:
                        if st.button(f"🦠 Vérifier avec VirusTotal", key=f"vt_{i}"):
                            with st.spinner(f"Interrogation de VirusTotal pour {item['url']}..."):
                                vt_report = analyze_with_virustotal(item['url'])
                                
                                if vt_report.get("status") == "success":
                                    malicious_count = vt_report.get('malicious', 0)
                                    if malicious_count > 0:
                                        st.error(f"**VirusTotal : {malicious_count} détection(s) malveillante(s) !**")
                                    else:
                                        st.success("**VirusTotal : Aucune détection malveillante.**")
                                    st.write(f"[Voir le rapport complet sur VirusTotal]({vt_report.get('link')})")
                                else:
                                    st.warning(f"VirusTotal : {vt_report.get('message')}")
                    st.markdown("---")
        
        with st.expander("📄 Voir le contenu brut de l'email"):
            st.text_area("Corps", body, height=200)

        # Nouvelle section pour l'analyse des pièces jointes
        with st.expander("📎 Analyse des Pièces Jointes"):
            if not attachments:
                st.info("Aucune pièce jointe trouvée.")
            else:
                for i, att in enumerate(attachments):
                    st.write(f"**Fichier :** `{att['filename']}`")
                    st.code(f"SHA-256: {att['hash']}", language="text")
                    
                    if st.button(f"🦠 Vérifier la pièce jointe sur VirusTotal", key=f"vt_att_{i}"):
                        with st.spinner(f"Interrogation de VirusTotal pour {att['filename']}..."):
                            vt_report = analyze_hash_with_virustotal(att['hash'])
                            if vt_report.get("status") == "success":
                                malicious_count = vt_report.get('malicious', 0)
                                if malicious_count > 0:
                                    st.error(f"**VirusTotal : {malicious_count} détection(s) malveillante(s) !**")
                                else:
                                    st.success("**VirusTotal : Aucune détection malveillante.**")
                                st.write(f"[Voir le rapport complet sur VirusTotal]({vt_report.get('link')})")
                            else:
                                st.warning(f"VirusTotal : {vt_report.get('message')}")
                    st.markdown("---")

        # --- PHASE 3 : BOUTON DE TÉLÉCHARGEMENT ---
        st.subheader("Rapport Complet")
        
        # On ajoute les rapports dynamiques au dictionnaire principal AVANT de générer le PDF
        report_data["dynamic_reports"] = st.session_state.get('dynamic_reports', {})
        
        # On génère le PDF en mémoire
        pdf_bytes = generate_pdf_report(report_data)
        
        st.download_button(
            label="📄 Télécharger le Rapport d'Analyse (.pdf)",
            data=pdf_bytes,
            file_name=f"APLA_Report_{uploaded_file.name}.pdf",
            mime="application/pdf"
        )

    except Exception as e:
        st.error(f"Une erreur est survenue lors de l'analyse : {e}")
    
    finally:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path) 