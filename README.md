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

# ORG Phishing Detection Module
### Advanced brand‑based phishing detection for Rspamd 4.1.5+

Dette modul identificerer phishing‑mails, der udgiver sig for at være kendte brands.  
Det matcher display‑navne, domæner, URL‑mønstre, DKIM‑status, urgency‑fraser og brand‑specifikke heuristikker.

Modulet er designet til produktion og understøtter både danske og internationale brands, inkl. PostNord, YouSee, Brobizz, Hetzner, Elgiganten, Netflix, One.com, EasyPark og mange flere.

---

## Features

- Brand‑baseret phishingdetektion  
- Display‑name mismatch detection  
- Domæne‑whitelist med wildcard‑patterns  
- URL‑heuristik for brand‑spoofing  
- DKIM‑policy pr. brand (critical / medium / low)  
- Brand‑specifikke urgency‑mønstre  
- Understøtter SendGrid, Responsys, marketing‑domæner og relay‑subdomæner  
- Ingen deprecated Rspamd API  
- Kompatibel med Rspamd 4.1.5+

---

## Understøttede brands

### Danske og nordiske tjenester
- SKAT  
- MitID  
- NemID  
- MobilePay  
- e‑Boks  
- Nets  
- Sygeforsikring Danmark  
- Punktum.dk  
- TDC  
- Telia  
- YouSee  
- One.com  

### Hosting & Cloud
- Hetzner (robot, abuse, cloud, support)

### E‑commerce & retail
- Elgiganten

### Transport & levering
- PostNord  
- DHL  
- GLS  
- Bring  
- Posta  
- UPS  
- FedEx  

### Betaling & parkering
- EasyPark  
- Brobizz  

### Streaming
- Netflix  

---

## Whitelist‑logik

Modulet indeholder en avanceret domæne‑whitelist med wildcard‑patterns:

- `em%d+%.postnord.com`  
- `em%d+%.yousee.dk`  
- `em%d+%.brobizz.com`  
- `o%d%.email%.brobizz.dk`  
- `em%d+%.elgiganten.dk`  
- `robot%.hetzner%.com`  
- `abuse%.hetzner%.de`  
- `support%.hetzner%.com`  

Dette sikrer at legitime mails fra SendGrid, Responsys, marketing‑platforme og relay‑systemer **ikke** bliver tagget som phishing.

---

## URL‑heuristik

Modulet matcher brand‑relaterede phishing‑URL’er, fx:

- `easypark-secure`, `easypark-payment`, `easypark-login`  
- `netflix-billing`, `netflix-update`, `netflix-verify`  
- `onecom-secure`, `onecom-billing`, `onecom-login`  
- `hetzner-robot`, `hetzner-cloud`, `hetzner-billing`  
- `elgiganten-order`, `elgiganten-tracking`  
- SES‑phishing: `miportal-ggs`, `amazonses`  
- Obfuskerede navne: `one-com`, `nflx`, `easy%park`

---

## DKIM‑policy

### Critical brands
- SKAT  
- MitID  
- NemID  
- MobilePay  
- e‑Boks  
- Nets  
- Sygeforsikring Danmark  

### Medium brands
- PostNord  
- DHL  
- GLS  
- Bring  
- UPS  
- FedEx  
- Posta  
- Punktum.dk  
- Netflix  
- One.com  
- YouSee  
- Brobizz  
- Hetzner  
- Elgiganten  

### Low brands
- TDC  
- Telia  
- EasyPark  

---

## Urgency‑mønstre

Modulet indeholder brand‑specifikke urgency‑fraser, fx:

- “din Netflix betaling er afvist”  
- “one.com domain expires”  
- “verify your Hetzner account”  
- “din Elgiganten ordre er på vej”  
- “brobizz betaling mangler”  
- “din pakke er tilbageholdt”  
- “verify your account”  

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

