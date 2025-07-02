# Dockerfile pour notre sandbox d'analyse - Version sécurisée
FROM python:3.12-slim

# Variables d'environnement pour la sécurité
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive
ENV HOME=/app

# 1. Mise à jour du système et installation des dépendances de sécurité
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    gnupg \
    wget \
    unzip \
    ca-certificates \
    curl \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# 2. Installation sécurisée de Google Chrome
RUN wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor -o /usr/share/keyrings/google-chrome.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list \
    && apt-get update && apt-get install -y \
    google-chrome-stable \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# 3. Création d'un utilisateur non-root pour la sécurité
RUN groupadd -r appuser && useradd -r -g appuser appuser

# 4. Installation des bibliothèques Python nécessaires avec versions sécurisées
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir selenium==4.15.0 webdriver-manager==4.0.2

# 5. Configuration du répertoire de travail
WORKDIR /app

# 6. Copie de notre script d'analyse
COPY sandbox_script.py .

# 7. Changement des permissions et propriétaire
RUN chown -R appuser:appuser /app

# 8. Changement vers l'utilisateur non-root
USER appuser

# 9. Point d'entrée pour exécuter le script
ENTRYPOINT ["python", "sandbox_script.py"] 