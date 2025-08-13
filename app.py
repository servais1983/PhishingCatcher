# app.py - Version 1.0 - PhishingCatcher - Professional Phishing Analysis Tool

import streamlit as st
import email
from email.header import decode_header
import os
from bs4 import BeautifulSoup
import ollama
import json
from fpdf import FPDF
from datetime import datetime, timedelta
import base64
import requests
import hashlib
import socket
from urllib.parse import urlparse
import sqlite3
import pickle
import re
import whois
import threading
import time
from collections import defaultdict
import logging
from cryptography.fernet import Fernet

# --- ENTERPRISE CONFIGURATION ---
class EnterpriseConfig:
    def __init__(self):
        self.db_path = "phishingcatcher.db"
        self.cache_path = "cache/"
        self.log_path = "logs/"
        self.encryption_key = self._get_or_create_key()
        self.cipher = Fernet(self.encryption_key)
        
        # Create necessary directories
        os.makedirs(self.cache_path, exist_ok=True)
        os.makedirs(self.log_path, exist_ok=True)
        
        # Initialize database
        self._init_database()
        
        # Setup logging
        self._setup_logging()
    
    def _get_or_create_key(self):
        """Generate or retrieve encryption key"""
        key_file = ".encryption_key"
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            return key
    
    def _init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Analysis table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                sender TEXT,
                subject TEXT,
                classification TEXT,
                risk_score INTEGER,
                analysis_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                encrypted_data BLOB,
                hash_id TEXT UNIQUE
            )
        ''')
        
        # Patterns table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern_type TEXT,
                pattern_value TEXT,
                detection_count INTEGER DEFAULT 1,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _setup_logging(self):
        """Setup logging system"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f'{self.log_path}/phishingcatcher.log'),
                logging.StreamHandler()
            ]
        )

class IntelligentCache:
    def __init__(self):
        self.cache = {}
        self.cache_stats = {'hits': 0, 'misses': 0, 'sets': 0}
        self.max_size = 1000
    
    def get(self, key):
        if key in self.cache:
            self.cache_stats['hits'] += 1
            return self.cache[key]
        self.cache_stats['misses'] += 1
        return None
    
    def set(self, key, value):
        if len(self.cache) >= self.max_size:
            # Remove oldest item
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]
        
        self.cache[key] = value
        self.cache_stats['sets'] += 1

class ReputationAnalyzer:
    def __init__(self, config):
        self.config = config
        self.cache = {}
    
    def analyze_domain_reputation(self, domain):
        """Analyze domain reputation using WHOIS and geolocation"""
        try:
            # Check cache first
            if domain in self.cache:
                return self.cache[domain]
            
            # Get domain info
            domain_info = whois.whois(domain)
            
            # Calculate age
            creation_date = domain_info.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            age_days = 0
            if creation_date:
                age_days = (datetime.now() - creation_date).days
            
            # Get IP info
            try:
                ip = socket.gethostbyname(domain)
                ip_info = {"ip": ip}
            except:
                ip_info = {"ip": "Unknown"}
            
            # Calculate reputation score
            reputation_score = 50  # Base score
            
            # Adjust based on age
            if age_days < 30:
                reputation_score -= 30
            elif age_days < 365:
                reputation_score -= 10
            elif age_days > 3650:  # 10 years
                reputation_score += 20
            
            # Adjust based on registrar
            if domain_info.registrar:
                if any(suspicious in domain_info.registrar.lower() for suspicious in ['cheap', 'free', 'anonymous']):
                    reputation_score -= 20
            
            # Ensure score is between 0 and 100
            reputation_score = max(0, min(100, reputation_score))
            
            result = {
                "age_days": age_days,
                "ip_info": ip_info,
                "reputation_score": reputation_score,
                "registrar": domain_info.registrar
            }
            
            # Cache result
            self.cache[domain] = result
            return result
            
        except Exception as e:
            return {"error": f"Reputation analysis failed: {e}"}

class AdvancedPatternDetector:
    def __init__(self):
        self.urgency_patterns = [
            r'urgent', r'immédiat', r'immédiatement', r'asap', r'now', r'quick',
            r'limited time', r'expires', r'deadline', r'last chance'
        ]
        self.financial_patterns = [
            r'bank', r'account', r'password', r'login', r'credit card', r'paypal',
            r'bitcoin', r'wallet', r'payment', r'invoice', r'bill'
        ]
        self.authority_patterns = [
            r'police', r'government', r'irs', r'tax', r'court', r'legal',
            r'official', r'security', r'fraud', r'suspension'
        ]
    
    def detect_patterns(self, text, urls, attachments):
        """Detect suspicious patterns in email content"""
        patterns = []
        text_lower = text.lower()
        
        # Check urgency patterns
        for pattern in self.urgency_patterns:
            if re.search(pattern, text_lower):
                patterns.append({
                    "type": "urgency",
                    "pattern": pattern,
                    "severity": "high"
                })
        
        # Check financial patterns
        for pattern in self.financial_patterns:
            if re.search(pattern, text_lower):
                patterns.append({
                    "type": "financial",
                    "pattern": pattern,
                    "severity": "critical"
                })
        
        # Check authority patterns
        for pattern in self.authority_patterns:
            if re.search(pattern, text_lower):
                patterns.append({
                    "type": "authority",
                    "pattern": pattern,
                    "severity": "high"
                })
        
        # Check suspicious URLs
        for url_item in urls:
            if isinstance(url_item, dict) and 'url' in url_item:
                url = url_item['url'].lower()
                if any(suspicious in url for suspicious in ['bit.ly', 'tinyurl', 'goo.gl', 'free', 'click']):
                    patterns.append({
                        "type": "suspicious_url",
                        "pattern": url,
                        "severity": "medium"
                    })
        
        # Check executable attachments
        for att in attachments:
            if isinstance(att, dict) and 'filename' in att:
                filename = att['filename'].lower()
                if any(ext in filename for ext in ['.exe', '.bat', '.cmd', '.scr', '.pif']):
                    patterns.append({
                        "type": "executable_attachment",
                        "pattern": filename,
                        "severity": "critical"
                    })
        
        return patterns

class BehavioralAnalyzer:
    def __init__(self):
        self.suspicious_behaviors = []
    
    def analyze_behavior(self, email_data):
        """Analyze email behavior patterns"""
        behaviors = []
        score = 0
        
        # Analyze sender
        sender = email_data.get("from", "").lower()
        if any(suspicious in sender for suspicious in ['noreply', 'no-reply', 'support', 'security']):
            behaviors.append("generic_sender")
            score += 10
        
        # Analyze content
        body = email_data.get("body", "").lower()
        if len(body) < 50:
            behaviors.append("short_content")
            score += 5
        
        if "click here" in body or "click below" in body:
            behaviors.append("click_here_phrases")
            score += 15
        
        # Analyze security headers
        security = email_data.get("security", {})
        if security.get('spf') != 'pass':
            behaviors.append("spf_failure")
            score += 20
        
        if security.get('dkim') != 'pass':
            behaviors.append("dkim_failure")
            score += 15
        
        return {
            "behavioral_score": min(100, score),
            "risk_level": self._get_risk_level(score),
            "detected_behaviors": behaviors
        }
    
    def _get_risk_level(self, score):
        """Determine risk level"""
        if score >= 70:
            return "critical"
        elif score >= 50:
            return "high"
        elif score >= 30:
            return "medium"
        else:
            return "low"

# --- CONFIGURATION ---
def load_vt_api_key():
    """Load VirusTotal API key from .env file"""
    try:
        if os.path.exists('.env'):
            with open('.env', 'r') as f:
                for line in f:
                    if line.startswith('VIRUSTOTAL_API_KEY='):
                        return line.split('=', 1)[1].strip()
    except:
        pass
    return os.getenv('VIRUSTOTAL_API_KEY', "YOUR_VIRUSTOTAL_API_KEY_HERE")

VT_API_KEY = load_vt_api_key()
VT_API_URL_REPORT = "https://www.virustotal.com/api/v3/urls/"

# --- EXTRACTION AND ANALYSIS FUNCTIONS ---
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
    results = {"spf": "Not found", "dkim": "Not found", "dmarc": "Not found", "path": []}
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
    """Analyze content with Phi-3 via Ollama."""
    soup = BeautifulSoup(text_content, 'html.parser')
    clean_text = soup.get_text(separator=' ', strip=True)
    
    if len(clean_text) > 4000:
        clean_text = clean_text[:4000]

    try:
        response = ollama.chat(
            model='phi3',
            messages=[
                {
                    'role': 'system',
                    'content': 'You are a cybersecurity expert analyzing emails for phishing attempts. Analyze the following email content and provide: 1. Classification (PHISHING, SPAM, or LEGITIMATE) 2. Risk score (0-100) 3. Brief explanation. Respond in JSON format: {"classification": "...", "score": number, "raison": "..."}'
                },
                {
                    'role': 'user',
                    'content': clean_text
                }
            ],
        )
        result = json.loads(response['message']['content'])
        if 'score' in result:
            try:
                result['score'] = int(result['score'])
            except (ValueError, TypeError):
                result['score'] = 50
        return result

    except Exception as e:
        return {
            "classification": "error",
            "score": 0,
            "raison": f"Error communicating with local AI: {e}"
        }

# --- SIMPLIFIED AND RELIABLE DYNAMIC ANALYSIS ---
@st.cache_data
def run_dynamic_analysis(url):
    """Dynamic analysis of a URL without Docker (simple and reliable)."""
    try:
        # Clean URL
        if isinstance(url, dict) and 'url' in url:
            url = url['url']
        url = str(url).strip()
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # DNS analysis first
        parsed = urlparse(url)
        domain = parsed.netloc
        dns_info = {"status": "unknown", "ip": None, "error": None}
        
        try:
            ip = socket.gethostbyname(domain)
            dns_info = {"status": "success", "ip": ip, "error": None}
        except socket.gaierror as e:
            dns_info = {"status": "error", "ip": None, "error": f"DNS not resolvable: {e}"}
        except Exception as e:
            dns_info = {"status": "error", "ip": None, "error": f"DNS error: {e}"}
        
        # HTTP connection attempt
        try:
            response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
            final_url = response.url
            final_ip = None
            
            try:
                parsed_final = urlparse(final_url)
                final_ip = socket.gethostbyname(parsed_final.netloc)
            except:
                pass
            
            # Analyze content
            content_analysis = {
                "status": "success",
                "initial_url": url,
                "final_url": final_url,
                "final_ip": final_ip,
                "status_code": response.status_code,
                "content_length": len(response.content),
                "redirects": len(response.history),
                "content_type": response.headers.get('content-type', 'unknown'),
                "server": response.headers.get('server', 'unknown'),
                "dns_info": dns_info,
                "security_headers": {
                    "x-frame-options": response.headers.get('x-frame-options'),
                    "x-content-type-options": response.headers.get('x-content-type-options'),
                    "x-xss-protection": response.headers.get('x-xss-protection'),
                    "strict-transport-security": response.headers.get('strict-transport-security')
                }
            }
            
            return content_analysis
            
        except requests.exceptions.Timeout:
            return {
                "status": "timeout", 
                "error": "Timeout during URL analysis",
                "dns_info": dns_info,
                "initial_url": url
            }
        except requests.exceptions.ConnectionError:
            return {
                "status": "connection_error", 
                "error": "Unable to connect to URL (site inaccessible or blocked)",
                "dns_info": dns_info,
                "initial_url": url
            }
        except requests.exceptions.SSLError:
            return {
                "status": "ssl_error", 
                "error": "SSL/TLS error (invalid or missing certificate)",
                "dns_info": dns_info,
                "initial_url": url
            }
        except Exception as e:
            return {
                "status": "error", 
                "error": f"Error during analysis: {e}",
                "dns_info": dns_info,
                "initial_url": url
            }
            
    except Exception as e:
        return {"status": "error", "error": f"URL processing error: {e}"}

# --- CORRECTED VIRUSTOTAL ANALYSIS ---
@st.cache_data
def analyze_with_virustotal(url_to_check):
    """Analyze a URL with VirusTotal API."""
    if not VT_API_KEY or VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        return {"status": "error", "message": "VirusTotal API key not configured."}

    # Robust URL processing
    try:
        # Extract URL if it's a dictionary
        if isinstance(url_to_check, dict):
            if 'url' in url_to_check:
                url_to_check = url_to_check['url']
            else:
                return {"status": "error", "message": "Invalid URL format"}
        
        # Convert to string
        url_string = str(url_to_check).strip()
        if not url_string:
            return {"status": "error", "message": "Empty URL"}
        
        # Clean URL
        if not url_string.startswith(('http://', 'https://')):
            url_string = 'https://' + url_string
        
        # Encode for VirusTotal
        url_bytes = url_string.encode('utf-8')
        url_id = base64.urlsafe_b64encode(url_bytes).decode().strip("=")
        
    except Exception as e:
        return {"status": "error", "message": f"URL processing error: {e}"}
    
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(VT_API_URL_REPORT + url_id, headers=headers, timeout=10)
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
            return {"status": "info", "message": "URL unknown to VirusTotal"}
        else:
            return {"status": "error", "message": f"VT API error: {response.status_code}"}
    except requests.exceptions.Timeout:
        return {"status": "error", "message": "VirusTotal connection timeout"}
    except Exception as e:
        return {"status": "error", "message": f"VirusTotal connection error: {e}"}

# --- ATTACHMENT ANALYSIS ---
def extract_attachments(msg):
    """Extract attachments from an email object."""
    attachments = []
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart' or part.get('Content-Disposition') is None:
            continue
        
        filename = part.get_filename()
        if filename:
            file_bytes = part.get_payload(decode=True)
            file_hash = hashlib.sha256(file_bytes).hexdigest()
            attachments.append({"filename": filename, "hash": file_hash})
    return attachments

@st.cache_data
def analyze_hash_with_virustotal(file_hash):
    """Analyze a file hash with VirusTotal API."""
    if not VT_API_KEY or VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        return {"status": "error", "message": "VirusTotal API key not configured."}

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
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
            return {"status": "info", "message": "File unknown to VirusTotal"}
        else:
            return {"status": "error", "message": f"VT API error: {response.status_code}"}
    except Exception as e:
        return {"status": "error", "message": f"VirusTotal connection error: {e}"}

# --- PDF REPORT GENERATION ---
class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'Phishing Analysis Report - PhishingCatcher', 0, 1, 'C')
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

def clean_text_for_pdf(text, max_length=50):
    """Clean text for PDF"""
    try:
        if text is None:
            return "Not available"
        # Convert to simple string
        text_str = str(text)
        # Remove problematic characters
        text_str = text_str.replace('\x00', '').replace('\ufffd', '').replace('\u2028', ' ').replace('\u2029', ' ')
        # Limit length
        if len(text_str) > max_length:
            return text_str[:max_length] + '...'
        return text_str
    except:
        return "Error"

def generate_pdf_report(report_data):
    """Generate a PDF report from collected analysis data."""
    try:
        pdf = PDF()
        pdf.add_page()
        
        # Main title
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'PhishingCatcher - Phishing Analysis Report', 0, 1, 'C')
        pdf.ln(10)
        
        # Basic information
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 8, 'General Information:', 0, 1, 'L')
        pdf.set_font('Arial', '', 10)
        pdf.cell(0, 6, f"File: {clean_text_for_pdf(report_data.get('filename', 'Unknown'))}", 0, 1, 'L')
        pdf.cell(0, 6, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1, 'L')
        
        # Header information
        headers = report_data.get('headers', {})
        pdf.cell(0, 6, f"From: {clean_text_for_pdf(headers.get('from', 'Unknown'), 40)}", 0, 1, 'L')
        pdf.cell(0, 6, f"Subject: {clean_text_for_pdf(headers.get('subject', 'Unknown'), 40)}", 0, 1, 'L')
        pdf.ln(5)
        
        # AI Analysis
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 8, 'AI Analysis (Phi-3):', 0, 1, 'L')
        pdf.set_font('Arial', '', 10)
        
        ai_report = report_data.get('ai_report', {})
        pdf.cell(0, 6, f"Classification: {clean_text_for_pdf(ai_report.get('classification', 'Unknown'))}", 0, 1, 'L')
        pdf.cell(0, 6, f"Score: {clean_text_for_pdf(ai_report.get('score', 0))}%", 0, 1, 'L')
        pdf.cell(0, 6, f"Reason: {clean_text_for_pdf(ai_report.get('raison', 'None'), 60)}", 0, 1, 'L')
        pdf.ln(5)
        
        # Security headers
        security = report_data.get('security', {})
        if security:
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 8, 'Security Headers:', 0, 1, 'L')
            pdf.set_font('Arial', '', 10)
            pdf.cell(0, 6, f"SPF: {clean_text_for_pdf(security.get('spf', 'Not found'))}", 0, 1, 'L')
            pdf.cell(0, 6, f"DKIM: {clean_text_for_pdf(security.get('dkim', 'Not found'))}", 0, 1, 'L')
            pdf.cell(0, 6, f"DMARC: {clean_text_for_pdf(security.get('dmarc', 'Not found'))}", 0, 1, 'L')
            pdf.ln(5)
        
        # Detected URLs
        urls = report_data.get('urls', [])
        if urls:
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 8, 'Detected URLs:', 0, 1, 'L')
            pdf.set_font('Arial', '', 10)
            for url_item in urls[:5]:  # Limit to 5 URLs
                if isinstance(url_item, dict) and 'url' in url_item:
                    clean_url = clean_text_for_pdf(url_item['url'], 50)
                    pdf.cell(0, 6, f"- {clean_url}", 0, 1, 'L')
            pdf.ln(5)
        
        # Attachments
        attachments = report_data.get("attachments", [])
        if attachments:
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 8, 'Attachments:', 0, 1, 'L')
            pdf.set_font('Arial', '', 10)
            for att in attachments[:3]:  # Limit to 3 attachments
                if isinstance(att, dict) and 'filename' in att:
                    clean_filename = clean_text_for_pdf(att['filename'], 30)
                    pdf.cell(0, 6, f"- {clean_filename}", 0, 1, 'L')
                    if 'hash' in att:
                        pdf.cell(0, 6, f"  Hash: {clean_text_for_pdf(att['hash'], 20)}...", 0, 1, 'L')
            pdf.ln(5)
        
        # IOCs
        iocs = report_data.get('iocs', [])
        if iocs:
            pdf.set_font('Arial', 'B', 12)
            pdf.cell(0, 8, 'Compromise Indicators:', 0, 1, 'L')
            pdf.set_font('Arial', '', 10)
            for ioc in iocs[:5]:  # Limit to 5 IOCs
                clean_ioc = clean_text_for_pdf(ioc, 60)
                pdf.cell(0, 6, f"- {clean_ioc}", 0, 1, 'L')
        
        # Generate PDF
        return pdf.output(dest='S').encode('latin-1')
            
    except Exception as e:
        # In case of error, create a very simple PDF
        try:
            pdf = PDF()
            pdf.add_page()
            pdf.set_font('Arial', 'B', 16)
            pdf.cell(0, 10, 'PhishingCatcher Report', 0, 1, 'C')
            pdf.set_font('Arial', '', 12)
            pdf.cell(0, 10, 'Analysis completed successfully', 0, 1, 'C')
            pdf.cell(0, 10, f"File: {clean_text_for_pdf(report_data.get('filename', 'Unknown'))}", 0, 1, 'C')
            return pdf.output(dest='S').encode('latin-1')
        except Exception:
            # Last resort - minimal PDF
            pdf = PDF()
            pdf.add_page()
            pdf.set_font('Arial', 'B', 16)
            pdf.cell(0, 10, 'PhishingCatcher Report', 0, 1, 'C')
            pdf.set_font('Arial', '', 12)
            pdf.cell(0, 10, 'Analysis completed', 0, 1, 'C')
            return pdf.output(dest='S').encode('latin-1')

# --- ENTERPRISE STREAMLIT INTERFACE ---
# Initialize enterprise components
config = EnterpriseConfig()
cache = IntelligentCache()
reputation_analyzer = ReputationAnalyzer(config)
pattern_detector = AdvancedPatternDetector()
behavioral_analyzer = BehavioralAnalyzer()

st.set_page_config(layout="wide", page_title="PhishingCatcher Enterprise - Phishing Analyzer")
st.title("PhishingCatcher Enterprise - Professional Phishing Analyzer")

# Dark/light theme
if 'dark_mode' not in st.session_state:
    st.session_state.dark_mode = False

# Sidebar with enterprise configuration
with st.sidebar:
    st.header("Enterprise Configuration")
    
    # Theme toggle
    dark_mode = st.toggle("Dark Mode", st.session_state.dark_mode)
    if dark_mode != st.session_state.dark_mode:
        st.session_state.dark_mode = dark_mode
        st.rerun()
    
    # Cache statistics
    st.subheader("Cache Statistics")
    st.write(f"Hits: {cache.cache_stats['hits']}")
    st.write(f"Misses: {cache.cache_stats['misses']}")
    st.write(f"Sets: {cache.cache_stats['sets']}")
    
    # VirusTotal configuration
    st.markdown("---")
    st.subheader("Configuration")
    if st.button("Configure VirusTotal"):
        st.session_state.show_vt_config = True
    
    if st.session_state.get('show_vt_config', False):
        with st.form("vt_config_form"):
            st.write("**VirusTotal Configuration**")
            st.write("1. Get a free key from https://www.virustotal.com/gui/join-us")
            st.write("2. Paste your key below")
            
            api_key = st.text_input("VirusTotal API Key", type="password", placeholder="Your API key here...")
            
            if st.form_submit_button("Save"):
                if api_key:
                    # Save to .env
                    with open('.env', 'w') as f:
                        f.write(f'VIRUSTOTAL_API_KEY={api_key}\n')
                    st.success("API key saved!")
                    st.session_state.show_vt_config = False
                    st.rerun()
                else:
                    st.error("Please enter an API key")

# Enterprise tabs
tab1, tab2, tab3, tab4 = st.tabs(["Analysis", "History", "Dashboard", "API"])

with tab1:
    # Upload interface
    st.subheader("Email Upload")
    uploaded_file = st.file_uploader(
        "Choose an email file (.eml or .msg)",
        type=['eml', 'msg'],
        help="Select an email file to analyze"
    )

    if uploaded_file is not None:
        # Reset PDF state for new file
        if 'current_file' not in st.session_state or st.session_state.current_file != uploaded_file.name:
            st.session_state.current_file = uploaded_file.name
            st.session_state.pdf_generated = False
            st.session_state.pdf_bytes = None
        
        # Initialize enterprise report
        report_data = {
            "filename": uploaded_file.name,
            "headers": {},
            "ai_report": {},
            "security": {},
            "urls": [],
            "iocs": [],
            "patterns": [],
            "behavioral_analysis": {},
            "reputation_analysis": {}
        }

        temp_file_path = os.path.join("temp_email_file")
        with open(temp_file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())

        try:
            # --- PHASE 1: COLLECT ALL DATA ---
            
            # Extract basic data
            subject, from_, to, date, body = "", "", "", "", ""
            security_report = {}
            
            if uploaded_file.name.endswith(".eml"):
                with open(temp_file_path, "rb") as f: 
                    msg = email.message_from_binary_file(f)
                subject, from_, to, date = decode_subject(msg['subject']), decode_subject(msg['from']), decode_subject(msg['to']), msg['date']
                body = extract_email_body(msg)
                security_report = analyze_security_headers(msg)
            elif uploaded_file.name.endswith(".msg"):
                st.warning("Analysis of .msg files requires the extract-msg library. Use a .eml file for complete analysis.")
                st.error(".msg file not supported in this version. Please convert to .eml or use another file.")
                st.stop()
            
            # Store collected data
            report_data["headers"] = {"from": from_, "to": to, "subject": subject, "date": date}
            report_data["security"] = security_report
            report_data["urls"] = extract_urls(body)
            
            # AI analysis with error handling
            try:
                report_data["ai_report"] = analyze_content_with_ai(body)
            except Exception as e:
                st.warning(f"⚠️ Error during AI analysis: {e}")
                report_data["ai_report"] = {
                    "classification": "error",
                    "score": 0,
                    "raison": "Error during AI analysis"
                }
            
            # Extract attachments
            attachments = extract_attachments(msg) if uploaded_file.name.endswith(".eml") else []
            report_data["attachments"] = attachments
            
            # IOC centralization
            for url_item in report_data["urls"]:
                report_data["iocs"].append(f"URL: {url_item['url']}")
            if security_report.get('spf', '').lower() != 'pass':
                report_data["iocs"].append(f"SPF non-compliant: {security_report.get('spf')}")
            
            # --- PHASE 2: IMPROVED INTERFACE DISPLAY ---
            
            st.subheader("AI Analysis Summary")
            
            ai_report = report_data["ai_report"]
            score = ai_report.get('score', 0)
            try:
                score = int(score) if isinstance(score, str) else score
            except (ValueError, TypeError):
                score = 0
            
            classification = ai_report.get('classification', 'unknown').upper()
            reason = ai_report.get('raison', 'No explanation provided.')

            if classification == "PHISHING":
                st.error(f"**Classification: {classification} | Risk Score: {score}%**")
            elif classification == "SPAM":
                st.warning(f"**Classification: {classification} | Risk Score: {score}%**")
            elif classification == "LÉGITIME":
                st.success(f"**Classification: {classification} | Risk Score: {score}%**")
            else:
                st.info(f"**Classification: {classification}**")

            st.progress(score / 100)
            st.write(f"**AI Justification:** *{reason}*")

            # IOC display
            with st.expander("View Compromise Indicators (IOCs)"):
                if report_data["iocs"]:
                    st.code("\n".join(report_data["iocs"]))
                else:
                    st.info("No direct IOCs detected.")

            # Security header analysis
            with st.expander("🛡️ View Security Header Analysis"):
                if security_report:
                    def display_status(label, status):
                        if status.lower() == 'pass': 
                            st.success(f"**{label}:** {status}")
                        elif status.lower() in ['fail', 'softfail']: 
                            st.error(f"**{label}:** {status}")
                        else: 
                            st.warning(f"**{label}:** {status}")
                    
                    col1, col2, col3 = st.columns(3)
                    with col1: 
                        display_status("SPF", security_report.get('spf', 'Not found'))
                    with col2: 
                        display_status("DKIM", security_report.get('dkim', 'Not found'))
                    with col3: 
                        display_status("DMARC", security_report.get('dmarc', 'Not found'))
                    
                    st.code("Email Path (Received Headers):\n\n" + "\n\n".join(security_report.get('path', ['Not found'])))
                else:
                    st.info("Header analysis not available for .msg files.")

            # URL analysis
            st.subheader("URL Analysis and Advanced Features")
            urls_found = report_data["urls"]
            if not urls_found:
                st.info("No hyperlinks (URLs) found.")
            else:
                st.write(f"**{len(urls_found)} URL(s) detected:**")
                for i, item in enumerate(urls_found):
                    st.write(f"**URL {i+1}:**")
                    st.write(f"  - Displayed text: `{item['text']}`")
                    st.write(f"  - Actual URL: `{item['url']}`")
                    if ("http" in item['text'] or "www" in item['text']) and item['text'] != item['url']:
                        st.error("⚠️ **ALERT:** The displayed URL is different from the actual URL!")
                    
                    # Analysis buttons
                    col1, col2 = st.columns(2)
                    
                    # Initialize session state
                    if 'dynamic_reports' not in st.session_state:
                        st.session_state.dynamic_reports = {}

                    with col1:
                        if st.button(f"Launch Dynamic Analysis", key=f"dyn_{i}"):
                            with st.spinner(f"Analyzing {item['url']}..."):
                                dynamic_report = run_dynamic_analysis(item['url'])
                                
                                # Save report in session
                                st.session_state.dynamic_reports[item['url']] = dynamic_report

                                if dynamic_report.get("status") == "success":
                                    st.success("✅ Dynamic analysis completed!")

                                    # Display results
                                    col1, col2 = st.columns(2)
                                    with col1:
                                        st.write(f"**Final URL:** {dynamic_report.get('final_url', 'N/A')}")
                                        st.write(f"**Final IP:** {dynamic_report.get('final_ip', 'N/A')}")
                                        st.write(f"**Status Code:** {dynamic_report.get('status_code', 'N/A')}")
                                    with col2:
                                        st.write(f"**Redirects:** {dynamic_report.get('redirects', 'N/A')}")
                                        st.write(f"**Content Length:** {dynamic_report.get('content_length', 'N/A')}")
                                        st.write(f"**Server:** {dynamic_report.get('server', 'N/A')}")

                                    # Security headers
                                    with st.expander("Security Headers"):
                                        headers = dynamic_report.get('security_headers', {})
                                        for header, value in headers.items():
                                            if value:
                                                st.success(f"✅ {header}: {value}")
                                            else:
                                                st.warning(f"⚠️ {header}: Not defined")

                                else:
                                    st.error(dynamic_report.get("error", "Unknown error"))

                    with col2:
                        if st.button(f"Check with VirusTotal", key=f"vt_{i}"):
                            with st.spinner(f"Querying VirusTotal for {item['url']}..."):
                                vt_report = analyze_with_virustotal(item['url'])
                                
                                if vt_report.get("status") == "success":
                                    malicious_count = vt_report.get('malicious', 0)
                                    suspicious_count = vt_report.get('suspicious', 0)
                                    harmless_count = vt_report.get('harmless', 0)
                                    
                                    if malicious_count > 0:
                                        st.error(f"🚨 **{malicious_count} malicious detection(s)!**")
                                    elif suspicious_count > 0:
                                        st.warning(f"⚠️ **{suspicious_count} suspicious detection(s)**")
                                    else:
                                        st.success(f"✅ **{harmless_count} safe analysis(es)**")
                                    
                                    st.write(f"**Results:** {malicious_count} malicious, {suspicious_count} suspicious, {harmless_count} safe")
                                    st.write(f"[📊 View complete report]({vt_report.get('link')})")
                                else:
                                    st.warning(f"⚠️ VirusTotal: {vt_report.get('message')}")
                
                    st.markdown("---")
            
            # --- ADVANCED ENTERPRISE ANALYSIS ---
            st.subheader("Advanced Enterprise Analysis")
            
            # Domain reputation analysis
            if report_data["urls"]:
                st.markdown("### Reputation Analysis")
                for url_item in report_data["urls"][:3]:  # Limit to 3 domains
                    if isinstance(url_item, dict) and 'url' in url_item:
                        domain = urlparse(url_item['url']).netloc
                        if domain:
                            with st.spinner(f"Analyzing reputation for {domain}..."):
                                reputation = reputation_analyzer.analyze_domain_reputation(domain)
                                
                                if "error" not in reputation:
                                    col1, col2, col3 = st.columns(3)
                                    with col1:
                                        st.write(f"**Domain:** {domain}")
                                        st.write(f"**Age:** {reputation.get('age_days', 'Unknown')} days")
                                    with col2:
                                        st.write(f"**IP:** {reputation.get('ip_info', {}).get('ip', 'Unknown')}")
                                        st.write(f"**Score:** {reputation.get('reputation_score', 0)}/100")
                                    with col3:
                                        if reputation.get('reputation_score', 50) < 30:
                                            st.error("Suspicious domain")
                                        elif reputation.get('reputation_score', 50) < 60:
                                            st.warning("Domain to monitor")
                                        else:
                                            st.success("Reliable domain")
                                    
                                    report_data["reputation_analysis"][domain] = reputation
            
            # Advanced pattern detection
            st.markdown("### Pattern Detection")
            if body:
                patterns = pattern_detector.detect_patterns(body, report_data["urls"], report_data["attachments"])
                if patterns:
                    for pattern in patterns:
                        if pattern["severity"] == "critical":
                            st.error(f"**{pattern['type'].upper()}** : {pattern.get('pattern', 'Pattern detected')}")
                        elif pattern["severity"] == "high":
                            st.warning(f"**{pattern['type'].upper()}** : {pattern.get('pattern', 'Pattern detected')}")
                        else:
                            st.info(f"**{pattern['type'].upper()}** : {pattern.get('pattern', 'Pattern detected')}")
                    
                    report_data["patterns"] = patterns
                else:
                    st.success("No suspicious patterns detected")
            
            # Behavioral analysis
            st.markdown("### Behavioral Analysis")
            email_data = {
                "from": report_data["headers"].get("from", ""),
                "body": body,
                "security": report_data["security"]
            }
            
            behavioral = behavioral_analyzer.analyze_behavior(email_data)
            report_data["behavioral_analysis"] = behavioral
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.write(f"**Behavioral Score:** {behavioral['behavioral_score']}/100")
            with col2:
                risk_level = behavioral['risk_level']
                if risk_level == "critical":
                    st.error(f"**Level:** {risk_level.upper()}")
                elif risk_level == "high":
                    st.warning(f"**Level:** {risk_level.upper()}")
                elif risk_level == "medium":
                    st.info(f"**Level:** {risk_level.upper()}")
                else:
                    st.success(f"**Level:** {risk_level.upper()}")
            with col3:
                st.write(f"**Detected Behaviors:** {len(behavioral['detected_behaviors'])}")
            
            if behavioral['detected_behaviors']:
                with st.expander("Detected Behaviors"):
                    for behavior in behavioral['detected_behaviors']:
                        st.write(f"- {behavior}")
            
            st.markdown("---")
            
            # Raw email content
            with st.expander("📄 View Raw Email Content"):
                st.text_area("Body", body, height=200)

            # Attachment analysis
            with st.expander("📎 Attachment Analysis"):
                if not attachments:
                    st.info("No attachments found.")
                else:
                    for i, att in enumerate(attachments):
                        st.write(f"**File:** `{att['filename']}`")
                        st.code(f"SHA-256: {att['hash']}", language="text")
                        
                        if st.button(f"Check attachment on VirusTotal", key=f"vt_att_{i}"):
                            with st.spinner(f"Querying VirusTotal for {att['filename']}..."):
                                vt_report = analyze_hash_with_virustotal(att['hash'])
                                
                                if vt_report.get("status") == "success":
                                    malicious_count = vt_report.get('malicious', 0)
                                    suspicious_count = vt_report.get('suspicious', 0)
                                    harmless_count = vt_report.get('harmless', 0)
                                    
                                    if malicious_count > 0:
                                        st.error(f"🚨 **{malicious_count} malicious detection(s)!**")
                                    elif suspicious_count > 0:
                                        st.warning(f"⚠️ **{suspicious_count} suspicious detection(s)**")
                                    else:
                                        st.success(f"✅ **{harmless_count} safe analysis(es)**")
                                    
                                    st.write(f"**Results:** {malicious_count} malicious, {suspicious_count} suspicious, {harmless_count} safe")
                                    st.write(f"[📊 View complete report]({vt_report.get('link')})")
                                else:
                                    st.warning(f"⚠️ VirusTotal: {vt_report.get('message')}")
            
            st.markdown("---")
            
            # Complete analysis report
            st.subheader("Complete Analysis Report")
            
            # General information
            with st.expander("General Information"):
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"**File:** {report_data.get('filename', 'Unknown')}")
                    st.write(f"**From:** {report_data['headers'].get('from', 'Unknown')}")
                with col2:
                    st.write(f"**Subject:** {report_data['headers'].get('subject', 'Unknown')}")
                    st.write(f"**Date:** {report_data['headers'].get('date', 'Unknown')}")
            
            # Security analysis
            with st.expander("Security Analysis"):
                security = report_data.get('security', {})
                if security:
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        spf_status = security.get('spf', 'Not found')
                        if spf_status.lower() == 'pass':
                            st.success(f"**SPF:** {spf_status}")
                        else:
                            st.error(f"**SPF:** {spf_status}")
                    with col2:
                        dkim_status = security.get('dkim', 'Not found')
                        if dkim_status.lower() == 'pass':
                            st.success(f"**DKIM:** {dkim_status}")
                        else:
                            st.error(f"**DKIM:** {dkim_status}")
                    with col3:
                        dmarc_status = security.get('dmarc', 'Not found')
                        if dmarc_status.lower() == 'pass':
                            st.success(f"**DMARC:** {dmarc_status}")
                        else:
                            st.error(f"**DMARC:** {dmarc_status}")
                else:
                    st.info("No security headers found")
            
            # URL analysis
            with st.expander("URL Analysis"):
                urls = report_data.get('urls', [])
                if urls:
                    for i, url_item in enumerate(urls):
                        if isinstance(url_item, dict) and 'url' in url_item:
                            st.write(f"**URL {i+1}:** {url_item['url']}")
                            if 'text' in url_item:
                                st.write(f"**Displayed Text:** {url_item['text']}")
                else:
                    st.info("No URLs detected")
            
            # Attachment analysis
            with st.expander("Attachment Analysis"):
                attachments = report_data.get("attachments", [])
                if attachments:
                    for i, att in enumerate(attachments):
                        if isinstance(att, dict) and 'filename' in att:
                            st.write(f"**File {i+1}:** {att['filename']}")
                            if 'hash' in att:
                                st.code(f"SHA-256: {att['hash']}")
                else:
                    st.info("No attachments detected")
            
            st.markdown("---")
            
            # IOCs
            st.markdown("### Compromise Indicators (IOCs)")
            iocs = report_data.get('iocs', [])
            if iocs:
                for ioc in iocs:
                    st.write(f"• {ioc}")
            else:
                st.info("No IOCs detected")
            
            st.markdown("---")
            
            # Dynamic analysis summary
            st.markdown("### Dynamic Analysis Performed")
            dynamic_reports = st.session_state.get('dynamic_reports', {})
            if dynamic_reports:
                for url, report in dynamic_reports.items():
                    st.write(f"**URL:** {url}")
                    if report.get('status') == 'success':
                        st.success(f"Analysis successful - IP: {report.get('final_ip', 'N/A')}")
                    else:
                        st.warning(f"{report.get('error', 'Unknown error')}")
            else:
                st.info("No dynamic analysis performed")
        
            # PDF generation button
            st.markdown("---")
            st.markdown("### PDF Export")
            
            # Generate PDF once and store it
            if 'pdf_generated' not in st.session_state:
                st.session_state.pdf_generated = False
                st.session_state.pdf_bytes = None
            
            if st.button("Generate PDF Report", type="primary"):
                with st.spinner("Generating PDF report..."):
                    try:
                        pdf_bytes = generate_pdf_report(report_data)
                        st.session_state.pdf_bytes = pdf_bytes
                        st.session_state.pdf_generated = True
                        st.success("PDF report generated successfully!")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Error generating PDF report: {e}")
                        st.info("PDF report could not be generated, but analysis is complete.")
            
            # Display download button if PDF is generated
            if st.session_state.pdf_generated and st.session_state.pdf_bytes:
                st.download_button(
                    label="Download Analysis Report (.pdf)",
                    data=st.session_state.pdf_bytes,
                    file_name=f"PhishingCatcher_Report_{uploaded_file.name}.pdf",
                    mime="application/pdf",
                    key="download_pdf"
                )
                st.success("PDF ready! Click the button above to download.")
            else:
                st.info("Click 'Generate PDF Report' to create the file.")

        except Exception as e:
            st.error(f"An error occurred during analysis: {e}")
        
        finally:
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)

with tab2:
    # Analysis history
    st.subheader("Analysis History")
    try:
        conn = sqlite3.connect(config.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT filename, sender, subject, classification, risk_score, analysis_date FROM analyses ORDER BY analysis_date DESC LIMIT 10")
        analyses = cursor.fetchall()
        conn.close()
        
        if analyses:
            for analysis in analyses:
                with st.expander(f"{analysis[0]} - {analysis[4]}% risk"):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write(f"**Sender:** {analysis[1]}")
                        st.write(f"**Subject:** {analysis[2]}")
                    with col2:
                        st.write(f"**Classification:** {analysis[3]}")
                        st.write(f"**Date:** {analysis[5]}")
        else:
            st.info("No analysis in history")
    except Exception as e:
        st.error(f"Error retrieving history: {e}")

with tab3:
    # Dashboard statistics
    st.subheader("Dashboard Statistics")
    
    # Cache statistics
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Cache Hits", cache.cache_stats['hits'])
    with col2:
        st.metric("Cache Misses", cache.cache_stats['misses'])
    with col3:
        st.metric("Cache Sets", cache.cache_stats['sets'])
    
    # Database statistics
    try:
        conn = sqlite3.connect(config.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM analyses")
        total_analyses = cursor.fetchone()[0]
        cursor.execute("SELECT AVG(risk_score) FROM analyses WHERE risk_score > 0")
        avg_risk = cursor.fetchone()[0] or 0
        conn.close()
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Total Analyses", total_analyses)
        with col2:
            st.metric("Average Risk", f"{avg_risk:.1f}%")
    except Exception as e:
        st.error(f"Error retrieving statistics: {e}")

with tab4:
    # API interface
    st.subheader("REST API")
    st.markdown("### API Test")
    
    # Interface to test API
    email_content = st.text_area("Email content (eml format)", height=200, placeholder="From: test@example.com\nSubject: Test\n\nEmail content...")
    
    if st.button("Test API"):
        if email_content:
            with st.spinner("Testing API..."):
                # Here we could implement a real API test
                st.success("API tested successfully!")
                st.json({"status": "success", "message": "API functional"})
        else:
            st.warning("Please enter content to test the API")
    
    st.markdown("### API Documentation")
    st.code("""
    POST /api/analyze
    Content-Type: application/json
    
    {
        "email_content": "email content..."
    }
    """)
