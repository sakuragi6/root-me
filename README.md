# 🚩 Writeups & Compte-Rendus Root-Me

Ce dépôt rassemble mes notes, analyses et solutions détaillées (writeups) des différents challenges réalisés sur la plateforme **[Root-Me](https://www.root-me.org/)**.

L'objectif de ce dépôt est de documenter ma progression, formaliser mes méthodologies d'analyse et partager mes apprentissages en sécurité informatique.

---

## 📂 Structure du Dépôt

Les writeups sont organisés par catégories :

- **`App-Systeme/`** : Exploitation de vulnérabilités binaires (Stack Overflow, Format Strings, ROP, etc.)
- **`App-Script/`** : Élévation de privilèges et failles d'environnement en scripts (Bash, Python, etc.)
- **`Web-Client/` & `Web-Server/`** : Web (XSS, SQLi, LFI/RFI, SSRF, etc.)
- **`Cracking/`** : Rétro-ingénierie et reverse engineering de binaires.

---

## 🛠️ Format des Writeups

Chaque rapport suit une structure claire et constante :
1. **Fiche technique & Protections** (analyse `checksec` / environnement)
2. **Analyse du code source & Vulnérabilité** (explications pas à pas)
3. **Stratégie d'exploitation** (payload, endianness, offsets)
4. **Preuve de concept (PoC)** et capture du flag
5. **Remédiation** (comment corriger la faille)

---

## ⚠️ Avertissement (Disclaimer)

Les informations et scripts présentés dans ce dépôt sont rédigés à des fins strictement éducatives et d'apprentissage dans un cadre éthique (CTF / Plateformes d'entraînement).
