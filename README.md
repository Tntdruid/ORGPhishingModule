<p align="center">
  <img src="https://img.shields.io/badge/Rspamd-Brand%20Phishing%20Module-blue?style=for-the-badge&logo=lua&logoColor=white" alt="Rspamd Brand Phishing Module">
</p>

<h1 align="center">ORG Phishing Detection Module</h1>

<p align="center">
  Avanceret brand-baseret phishingdetektion til Rspamd 4.1.5+  
  <br>
  Understøtter danske og internationale brands, DKIM-policy, URL-heuristik og urgency-mønstre.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue?style=flat-square">
  <img src="https://img.shields.io/badge/Rspamd-4.1.5+-green?style=flat-square">
  <img src="https://img.shields.io/badge/Lua-5.1-blueviolet?style=flat-square">
  <img src="https://img.shields.io/badge/status-production_success-success?style=flat-square">
  <img src="https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square">
</p>

# ORG Phishing Detection Module for Rspamd

Et avanceret brand‑baseret phishing‑modul til **Rspamd 4.1.5+**, designet til at opdage mails der udgiver sig for at være kendte danske og internationale tjenester.  
Modulet matcher display‑name, afsenderdomæne, URL‑mønstre, DKIM‑status og brand‑specifikke urgency‑mønstre.

## Features

### ✔ Understøttede brands
- PostNord  
- DHL  
- GLS  
- Bring  
- Posta Norge  
- UPS  
- FedEx  
- EasyPark  
- BroBizz  
- MobilePay  
- e‑Boks  
- MitID  
- NemID  
- Nets  
- TDC  
- Telia  
- YouSee  
- Punktum.dk  
- Sygeforsikring Danmark  

### ✔ DKIM‑policy pr. brand
- Critical: MitID, NemID, MobilePay, e‑Boks, Nets, Sygeforsikring Danmark  
- Medium: PostNord, DHL, GLS, Bring, UPS, FedEx, Punktum.dk  
- Low: TDC, Telia, YouSee, EasyPark, BroBizz  

### ✔ URL‑heuristik
Matcher brand‑relaterede phishing‑URL’er.

### ✔ Rspamd 4.1.5 kompatibel
Ingen brug af `task:get_symbols()` eller `task:get_results()`.

---

## Installation

### 1. Lua‑fil
/etc/rspamd/lua.local.d/org_phishing.lua

### 2. groups.conf
/etc/rspamd/local.d/groups.conf

### 3. Test
rspamadm configtest

### 4. Genstart
systemctl restart rspamd

---

## Licens

MIT License.

---

## Bidrag

Pull requests er velkomne.

MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
# Changelog – Netflix Brand Detection
Alle væsentlige ændringer relateret til Netflix‑brandet i ORG_PHISHING‑modulet.

