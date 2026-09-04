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

# Changelog – EasyPark Brand Detection
Alle væsentlige ændringer relateret til EasyPark‑brandet i ORG_PHISHING‑modulet.

## [1.0.3] – 2026‑09‑04
### Added
- Udvidet brand‑match til at understøtte alle variationer af EasyPark:
  - `easy[%s%-]*park` matcher nu:
    - EasyPark  
    - EASY PARK  
    - Easy‑Park  
    - Easy Park Support  
    - EasyPark Billing  
- Tilføjet nye URL‑patterns for EasyPark‑phishing:
  - `easypark-secure`
  - `easypark-payment`
  - `easypark-verify`
  - `easypark-login`
  - `easypark-billing`
- Tilføjet SES‑relaterede phishing‑patterns:
  - `miportal-ggs`
  - `amazonses`

### Improved
- Display‑name heuristik er nu case‑insensitive og tolerant over for mellemrum og bindestreger.
- EasyPark urgency‑mønstre er bevaret og udvidet for bedre match på betalingssvindel.
- DKIM‑policy for EasyPark er nu kategoriseret som **low‑risk**, men stadig aktiv ved fail/none.

### Fixed
- EasyPark‑phishing sendt via Amazon SES blev ikke fanget korrekt.
  - Problem: legitime SES‑hosts + falske domæner som `miportal-ggs.com`.
  - Løsning: nye URL‑patterns + tolerant brand‑match.
- Display‑name “EasyPark” blev kun matchet i én strengform.
- Phishing‑mails med obfuskeret subject (fx “P=?UTF‑8?...”) blev nu korrekt matchet via urgency‑mønstre.

---

## [1.0.2] – 2026‑09‑03
### Added
- Første version af EasyPark‑brandet:
  - Display‑name match: `easypark`
  - Domæne‑whitelist for legitime EasyPark‑domæner
  - Grundlæggende urgency‑mønstre for parkeringsbetaling

---

## [1.0.1] – 2026‑09‑02
### Added
- Initial brand‑struktur for modul
- DKIM‑policy framework
- URL‑heuristik framework

