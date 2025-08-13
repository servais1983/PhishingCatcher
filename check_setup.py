#!/usr/bin/env python3
"""
Script de vérification de l'installation PhishingCatcher
Vérifie que toutes les dépendances sont correctement installées
"""

import sys
import importlib

def check_python_version():
    """Vérifie la version de Python"""
    print("🐍 Vérification de la version Python...")
    version = sys.version_info
    if version.major == 3 and version.minor >= 12:
        print(f"✅ Python {version.major}.{version.minor}.{version.micro} - OK")
        return True
    else:
        print(f"❌ Python {version.major}.{version.minor}.{version.micro} - Version 3.12+ requise")
        return False

def check_module(module_name, package_name=None):
    """Vérifie qu'un module est installé"""
    try:
        importlib.import_module(module_name)
        print(f"✅ {package_name or module_name} - OK")
        return True
    except ImportError:
        print(f"❌ {package_name or module_name} - Manquant")
        return False

def main():
    """Fonction principale de vérification"""
    print("=" * 50)
    print("🔧 Vérification de l'installation PhishingCatcher")
    print("=" * 50)
    print()
    
    checks = []
    
    # Vérifications de base
    checks.append(check_python_version())
    
    # Vérifications des modules Python
    print("\n📦 Vérification des modules Python...")
    modules = [
        ('streamlit', 'Streamlit'),
        ('email', 'Email (built-in)'),
        ('bs4', 'BeautifulSoup4'),
        ('requests', 'Requests'),
        ('docker', 'Docker SDK'),
        ('fpdf', 'FPDF2'),
        ('base64', 'Base64 (built-in)'),
        ('hashlib', 'Hashlib (built-in)'),
        ('json', 'JSON (built-in)'),
        ('datetime', 'Datetime (built-in)'),
    ]
    
    for module, name in modules:
        checks.append(check_module(module, name))
    
    # Résumé
    print("\n" + "=" * 50)
    print("📊 RÉSUMÉ DE LA VÉRIFICATION")
    print("=" * 50)
    
    passed = sum(checks)
    total = len(checks)
    
    if passed == total:
        print(f"🎉 Toutes les vérifications sont passées ! ({passed}/{total})")
        print("✅ PhishingCatcher est prêt à être utilisé !")
        print("\n🚀 Pour démarrer l'application :")
        print("   - Windows : Double-cliquez sur start.bat")
        print("   - Terminal : streamlit run app.py")
    else:
        print(f"⚠️ {total - passed} vérification(s) ont échoué ({passed}/{total})")
        print("🔧 Veuillez corriger les problèmes ci-dessus avant d'utiliser PhishingCatcher")
    
    print("\n📖 Consultez le README.md pour plus d'informations")

if __name__ == "__main__":
    main()
