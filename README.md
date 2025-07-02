# APLA - Analyseur de Phishing Local Augmenté 🛡️

Un outil d'analyse de phishing sur mesure, rapide et sécurisé avec IA locale intégrée.

## 🎯 Concept

APLA applique le principe de **confiance zéro** à l'analyse de phishing. Contrairement aux services en ligne, tout le traitement se fait en local, garantissant la confidentialité totale des données analysées.

## 🏗️ Architecture Modulaire

### Module 1 : Ingestion et Parsing d'email ✅
- Support des formats `.eml` (`.msg` temporairement désactivé)
- Extraction des en-têtes, corps, URLs et pièces jointes
- Interface drag & drop intuitive

### Module 2 : Analyse Statique Intelligente ✅
- Vérification SPF/DKIM/DMARC
- Détection d'usurpation d'identité
- Analyse des URLs (Punycode, sous-domaines suspects)
- Détection de mots-clés de phishing
- Intégration VirusTotal pour la réputation des URLs

### Module 3 : IA Locale ✅
- Modèle Phi-3 via Ollama pour analyse sémantique
- Analyse du contenu et des indicateurs de phishing
- Score de risque intelligent

### Module 4 : Sandbox Dynamique ✅
- Environnement isolé Docker pour test des liens
- Surveillance des redirections et captures d'écran
- Conteneurisation sécurisée avec Selenium

### Module 5 : Export et Rapports ✅
- Génération de rapports PDF détaillés
- Export des résultats d'analyse
- Interface moderne et responsive

## 🚀 Installation

### Prérequis
- Python 3.8+
- Docker (pour la sandbox dynamique)
- Ollama (pour l'IA locale)

### Installation d'Ollama
```bash
# Windows (avec winget)
winget install Ollama.Ollama

# Ou télécharger depuis https://ollama.ai
```

### Installation du modèle Phi-3
```bash
ollama pull phi3
```

### Installation du projet
```bash
# Cloner le repository
git clone <repository-url>
cd Phishing-eraser

# Créer un environnement virtuel (recommandé)
python -m venv .venv
.venv\Scripts\activate  # Windows
# source .venv/bin/activate  # Linux/Mac

# Installer les dépendances
pip install -r requirements.txt

# Lancer l'application
streamlit run app.py
```

## 📋 Fonctionnalités

### ✅ Phase 1 (MVP) - Complète
- [x] Parsing d'emails (.eml)
- [x] Analyse des en-têtes (SPF, DKIM, DMARC)
- [x] Extraction et analyse des URLs
- [x] Détection de mots-clés de phishing
- [x] Interface Streamlit moderne
- [x] Vérification VirusTotal des URLs

### ✅ Phase 2 - IA Locale - Complète
- [x] Modèle IA local (Phi-3 via Ollama)
- [x] Analyse sémantique avancée
- [x] Score de risque intelligent
- [x] Détection d'indicateurs de phishing

### ✅ Phase 3 - Sandbox Dynamique - Complète
- [x] Sandbox Docker sécurisée
- [x] Analyse des redirections
- [x] Captures d'écran des pages
- [x] Surveillance des téléchargements
- [x] Environnement isolé

### ✅ Phase 4 - Export et Rapports - Complète
- [x] Génération de rapports PDF
- [x] Export des résultats
- [x] Interface utilisateur moderne
- [x] Analyse des pièces jointes

## 🔒 Sécurité

- **Traitement 100% local** : Aucune donnée envoyée à l'extérieur
- **Environnement isolé** : Sandbox Docker pour les tests dynamiques
- **Confidentialité garantie** : Respect du RGPD et des politiques de sécurité
- **Dockerfile sécurisé** : Image Python 3.11 avec utilisateur non-root
- **Dépendances à jour** : Versions sécurisées de toutes les bibliothèques

## 🛠️ Stack Technique

- **Backend** : Python 3.12+
- **IA/ML** : Ollama + Phi-3
- **Interface** : Streamlit
- **Sandbox** : Docker (Python 3.12-slim), Selenium 4.15
- **Analyse** : email, beautifulsoup4, requests
- **Export** : FPDF2
- **Sécurité** : urllib3, dnspython, utilisateur non-root

## 📊 Exemple d'utilisation

1. **Démarrage** : Lancez `streamlit run app.py`
2. **Upload** : Déposez un fichier `.eml` suspect dans l'interface
3. **Analyse automatique** : APLA analyse :
   - Les en-têtes d'authentification (SPF/DKIM/DMARC)
   - Les URLs et leur réputation (VirusTotal)
   - Le contenu sémantique (IA Phi-3)
   - Les indicateurs de phishing
   - Les pièces jointes
   - Les redirections (sandbox dynamique)
4. **Rapport** : Recevez un rapport PDF détaillé avec score de risque

## 🐛 Résolution des problèmes

### Erreur "ModuleNotFoundError: No module named 'ollama'"
```bash
pip install ollama
```

### Erreur "ModuleNotFoundError: No module named 'selenium'"
```bash
pip install selenium==4.15.0
```

### Erreur "ModuleNotFoundError: No module named 'docker'"
```bash
pip install docker>=6.1.0
```

### Ollama non trouvé
- Installez Ollama depuis https://ollama.ai
- Tirez le modèle : `ollama pull phi3`

### Docker non disponible
- Installez Docker Desktop
- Assurez-vous que Docker est démarré

## 🔧 Configuration

### Variables d'environnement (optionnel)
```bash
# VirusTotal API Key (optionnel)
export VIRUSTOTAL_API_KEY="your_api_key_here"
```

### Ports utilisés
- **Streamlit** : 8501 (par défaut)
- **Docker** : Ports dynamiques pour la sandbox

## 🤝 Contribution

Ce projet est en développement actif. Les contributions sont les bienvenues !

### Comment contribuer
1. Fork le projet
2. Créez une branche feature (`git checkout -b feature/AmazingFeature`)
3. Committez vos changements (`git commit -m 'Add some AmazingFeature'`)
4. Push vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrez une Pull Request

## 📄 Licence

MIT License - Voir le fichier LICENSE pour plus de détails.

## 🆕 Changelog

### Version 2.1.0 (Actuelle)
- ✅ Correction complète des vulnérabilités Docker
- ✅ Mise à jour vers Python 3.12
- ✅ Dockerfile sécurisé avec utilisateur non-root
- ✅ Fichier .dockerignore pour la sécurité
- ✅ Intégration complète d'Ollama + Phi-3
- ✅ Sandbox dynamique fonctionnelle
- ✅ Export PDF sans erreurs
- ✅ Interface Streamlit moderne
- ✅ Support VirusTotal
- ✅ Correction des dépendances manquantes

### Version 1.0.0
- ✅ MVP avec parsing d'emails
- ✅ Analyse statique basique
- ✅ Interface Streamlit 