# Phishing Email Analysis

## Project Overview
This project shows the analysis of a suspected phishing email using various tools:
- EML Analyzer
- URLVoid
- VirusTotal

The goal is to find common signs of phishing and check for malicious domains or attachments.

## Tools Used
- **[EML Analyzer](https://eml-analyzer.herokuapp.com/)**– for inspecting email headers and body.
- **[URLVoid](https://www.urlvoid.com/)** – to check domain reputation and blacklist status.
- **[VirusTotal](https://www.virustotal.com/)** – for analyzing attachments and domains.

---

## Key Findings
1. **Email Header Red Flags**
   - SPF, DKIM, DMARC: Fail
   - Sender spoofing: claimed `@bradesco.com.br, real IP from VPS.
   - Malformed To: address.

2. **Email Body Red Flags**  
   - Urgency message: *"Seu cartão tem 92.990 pontos expirando hoje!"*  
   - HTML-only format with external resources.  

3. **Suspicious URL**  
   - `https://blog1seguimentmydomaine2bra.me`  
   - Newly registered, no reputation history.  

4. **VirusTotal Insights**  
   - EML file confirmed as phishing.  
   - Related **phishing ZIP archives** detected in past scans.  

---

## Phishing Traits Summary  
- Urgent call to action (expiring points).  
- Spoofed sender domain.  
- Authentication failures.  
- Hidden or mismatched URLs.  
- External resources embedded.  

---

## Repository Structure  
phishing-analysis/  
├── emailheadanalyzer.pdf # Email header and body analysis  
├── urlscan.pdf # Domain reputation check  
├── virustool.pdf # VirusTotal file analysis  
├── virustool2.pdf # Additional VirusTotal relations  
└── README.md # Project documentation  
# I did not found any presence of spelling or grammar errors in this email but some of the examples are given below.
1.Check Display Name vs. Email Address

Example: support@paypai.com instead of support@paypal.com.

Attackers often replace letters with similar-looking numbers or characters, for example, o becomes 0 and l becomes 1.

2.Look for Misspelled Domains

Common tricks include:

micr0soft.com (zero instead of "o")

faceb00k.com (two zeros instead of "oo")

goggle.com instead of google.com.

3.Check Grammar and Spelling in Body

Phishing emails often contain awkward phrasing, such as:

"Your account has been suspended due to security reasons."

"Click here to verify immediately."

4.Check for URL Encoding or Extra Words

Example: paypal-secure-login.com (looks legit but is fake).

Hover over links to see the actual URL.

5.Automated Tools

Use scripts to detect homograph attacks with similar-looking characters.

Use natural language processing to flag grammar issues.

## Conclusion  
Always verify suspicious emails by:  
- Checking SPF, DKIM, and DMARC.  
- Inspecting links before clicking.  
- Using multi-engine scanners for attachments and domains.
