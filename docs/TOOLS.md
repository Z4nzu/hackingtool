# Tool catalog

Every tool hackingtool can install, launch, or point you at — **219 active tools
across 21 categories**, plus 44 archived entries kept out of this list (they are
unmaintained or dead upstream and are hidden in the app unless you set
`show_archived true` via `/config`).

Tags under each entry come from the fixed taxonomy in `src/hackingtool/tags.py`
(63 tags in use). Inside the app you can filter by any of them with
`@tag:<name>`, or search names/descriptions/tags with `/search <keyword>`.

Entries marked as a link point at the upstream project; a few are curated
reference resources (labs, cheat sheets, online services) rather than installable
binaries — hackingtool opens those instead of installing them.

> **Authorized targets only.** Every tool here is for systems you own or have
> written permission to test.

Back to the [README](../README.md) · [How to use hackingtool](HOW-TO-USE.md)

---

## 🛡 Anonymously Hiding Tools

- [Anonymously Surf](https://github.com/Und3rf10w/kali-anonsurf) — <sub>anonymity, tunneling, network</sub>
- [Multitor](https://github.com/trimstray/multitor) — <sub>anonymity, tunneling, network</sub>
- [Tor + torsocks (SOCKS anonymity proxy)](https://gitlab.torproject.org/tpo/core/torsocks) — <sub>anonymity, tunneling, network</sub>
- [proxychains-ng (chain traffic through proxies/Tor)](https://github.com/rofl0r/proxychains-ng) — <sub>anonymity, tunneling, network</sub>
- [Whonix — Anonymity & Tor OpSec (docs)](https://www.whonix.org/wiki/Documentation) — <sub>anonymity, reference, learning</sub>

<br>
<div align="center">
  <sub>Sponsored by</sub><br>
  <a href="https://webvetted.com/hacking-tools?utm_source=github&utm_medium=sponsor&utm_campaign=tools-catalogue">
    <img width="600" alt="WebVetted Intelligence - OSINT & Recon Platform" src="https://github.com/user-attachments/assets/20cb2526-c3b4-4217-a41f-42cb7e7d568e" />
  </a>
  <br><br>
  <i><b>Go beyond manual recon.</b> WebVetted turns an email, phone or username into a complete identity investigation with deep OSINT enrichment, breach intel, AI analysis, and an interactive identity graph.</i><br>
  <br>
  <a href="https://webvetted.com/hacking-tools?utm_source=github&utm_medium=sponsor&utm_campaign=tools-catalogue"><b>Start an Investigation →</b></a>
</div>

## 🔍 Information gathering tools

- [Network Map (nmap)](https://github.com/nmap/nmap) — <sub>scanner, port-scan, recon, network</sub>
- Port scanning — <sub>port-scan, scanner, network</sub>
- Host to IP  — <sub>recon, dns, lookup</sub>
- [RED HAWK (All In One Scanning)](https://github.com/Tuhinshubhra/RED_HAWK) — <sub>web, recon, scanner, fingerprint</sub>
- [ReconSpider(For All Scanning)](https://github.com/bhavsec/reconspider) — <sub>osint, recon, crawler</sub>
- IsItDown (Check Website Down/Up) — <sub>recon, online-service, web</sub>
- [SecretFinder (like API & etc)](https://github.com/m4ll0k/SecretFinder) — <sub>web, recon, credentials, git-secrets</sub>
- [Port Scanner - rang3r](https://github.com/floriankunushevci/rang3r) — <sub>port-scan, scanner, network</sub>
- [Breacher](https://github.com/s0md3v/Breacher) — <sub>web, recon, enumeration</sub>
- [theHarvester (OSINT)](https://github.com/laramies/theHarvester) — <sub>osint, email, subdomain-enum, recon</sub>
- [Amass (Attack Surface Mapping)](https://github.com/owasp-amass/amass) — <sub>subdomain-enum, recon, osint, dns</sub>
- [Masscan (Fast Port Scanner)](https://github.com/robertdavidgraham/masscan) — <sub>port-scan, scanner, network</sub>
- [RustScan (Modern Port Scanner)](https://github.com/RustScan/RustScan) — <sub>port-scan, scanner, network</sub>
- [Holehe (Email → Social Accounts)](https://github.com/megadose/holehe) — <sub>osint, email, recon, lookup</sub>
- [Maigret (Username OSINT)](https://github.com/soxoj/maigret) — <sub>osint, recon, lookup</sub>
- [httpx (HTTP Toolkit)](https://github.com/projectdiscovery/httpx) — <sub>web, recon, scanner, fingerprint</sub>
- [SpiderFoot (OSINT Automation)](https://github.com/smicallef/spiderfoot) — <sub>osint, recon, subdomain-enum</sub>
- [Subfinder (Subdomain Enumeration)](https://github.com/projectdiscovery/subfinder) — <sub>subdomain-enum, recon, osint, dns</sub>
- [TruffleHog (Secret Scanner)](https://github.com/trufflesecurity/trufflehog) — <sub>git-secrets, credentials, recon</sub>
- [Gitleaks (Git Secret Scanner)](https://github.com/gitleaks/gitleaks) — <sub>git-secrets, credentials, reporting</sub>
- [naabu (fast port scanner)](https://github.com/projectdiscovery/naabu) — <sub>port-scan, recon, network</sub>
- [dnsx (DNS toolkit)](https://github.com/projectdiscovery/dnsx) — <sub>dns, recon, enumeration</sub>
- [reconFTW (Automated Recon)](https://github.com/six2dez/reconftw) — <sub>recon, osint, subdomain-enum, scanner, dns</sub>
- [gowitness (Web Screenshots)](https://github.com/sensepost/gowitness) — <sub>web, recon, fingerprint, reporting</sub>
- [EyeWitness (Web Screenshots + Headers)](https://github.com/RedSiege/EyeWitness) — <sub>web, recon, fingerprint, reporting</sub>
- [Sn1per (Attack Surface Scanner)](https://github.com/1N3/Sn1per) — <sub>scanner, recon, vuln-scan, enumeration, web</sub>

## 📚 Wordlist Generator

- [Cupp](https://github.com/Mebus/cupp) — <sub>wordlist, password-attack, credentials, osint</sub>
- [Hashcat (Password Cracker)](https://github.com/hashcat/hashcat) — <sub>hash-crack, password-attack, credentials</sub>
- [John the Ripper](https://github.com/openwall/john) — <sub>hash-crack, password-attack, credentials</sub>
- [haiti (Hash Type Identifier)](https://github.com/noraj/haiti) — <sub>hash-crack, lookup, reference</sub>
- [crunch (Wordlist Generator)](https://sourceforge.net/projects/crunch-wordlist/) — <sub>wordlist, bruteforce, password-attack</sub>
- [CeWL (Custom Word List)](https://github.com/digininja/CeWL) — <sub>wordlist, osint, recon, credentials</sub>
- [SecLists (Wordlist Collection)](https://github.com/danielmiessler/SecLists) — <sub>wordlist, reference, bruteforce</sub>
- [Kali wordlists package (rockyou etc.)](https://gitlab.com/kalilinux/packages/wordlists) — <sub>wordlist, reference, password-attack</sub>

## 📡 Wireless attack tools

- [WiFi-Pumpkin](https://github.com/P0cL4bs/wifipumpkin3) — <sub>wireless, mitm, phishing, credentials</sub>
- [pixiewps](https://github.com/wiire/pixiewps) — <sub>wireless, bruteforce, password-attack</sub>
- [Bluetooth Honeypot GUI Framework](https://github.com/andrewmichaelsmith/bluepot) — <sub>wireless, sniffing</sub>
- [Fluxion](https://github.com/FluxionNetwork/fluxion) — <sub>wireless, phishing, social-engineering, credentials</sub>
- [Wifiphisher](https://github.com/wifiphisher/wifiphisher) — <sub>wireless, phishing, social-engineering, mitm</sub>
- [Wifite](https://github.com/derv82/wifite2) — <sub>wireless, password-attack, bruteforce, credentials</sub>
- Howmanypeople — <sub>wireless, sniffing, recon</sub>
- [Airgeddon (Wireless Attack Suite)](https://github.com/v1s1t0r1sh3r3/airgeddon) — <sub>wireless, password-attack, mitm, credentials</sub>
- [hcxdumptool (PMKID Capture)](https://github.com/ZerBea/hcxdumptool) — <sub>wireless, sniffing, pcap, credentials</sub>
- [hcxtools (PMKID/Hash Conversion)](https://github.com/ZerBea/hcxtools) — <sub>wireless, hash-crack, pcap, credentials</sub>
- [Bettercap (Network/WiFi/BLE MITM)](https://github.com/bettercap/bettercap) — <sub>wireless, mitm, sniffing, network</sub>
- [aircrack-ng (WiFi security suite)](https://github.com/aircrack-ng/aircrack-ng) — <sub>wireless, password-attack, bruteforce, sniffing</sub>
- [Kismet (wireless detector / WIDS)](https://github.com/kismetwireless/kismet) — <sub>wireless, sniffing, recon, network</sub>
- [Reaver (WPS PIN attack)](https://github.com/t6x/reaver-wps-fork-t6x) — <sub>wireless, bruteforce, password-attack, credentials</sub>
- [WiGLE (wardriving map & API)](https://wigle.net/) — <sub>wireless, osint, online-service, lookup</sub>
- [hashcat example hashes (WPA mode 22000)](https://hashcat.net/wiki/doku.php?id=example_hashes) — <sub>wireless, hash-crack, reference</sub>
- [Aircrack-ng: cracking WPA (tutorial)](https://www.aircrack-ng.org/doku.php?id=cracking_wpa) — <sub>wireless, learning, reference</sub>

## 💉 SQL Injection Tools

- [Sqlmap tool](https://github.com/sqlmapproject/sqlmap) — <sub>web, sql-injection, exploitation, scanner</sub>
- [NoSqlMap](https://github.com/codingo/NoSQLMap) — <sub>web, sql-injection, exploitation</sub>
- [Damn Small SQLi Scanner](https://github.com/stamparm/DSSS) — <sub>web, sql-injection, scanner</sub>
- [SQLScan](https://github.com/Cvar1984/sqlscan) — <sub>web, sql-injection, scanner</sub>
- [Ghauri (Modern SQLi Tool)](https://github.com/r0oth3x49/ghauri) — <sub>web, sql-injection, exploitation, scanner</sub>
- [PortSwigger — SQL Injection Labs](https://portswigger.net/web-security/sql-injection) — <sub>learning, web, sql-injection, reference</sub>
- [PayloadsAllTheThings — SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection) — <sub>cheatsheet, reference, sql-injection, web</sub>

## 🎣 Phishing attack tools

- [AdvPhishing](https://github.com/Ignitetch/AdvPhishing) — <sub>phishing, social-engineering, credentials</sub>
- [Setoolkit](https://github.com/trustedsec/social-engineer-toolkit) — <sub>social-engineering, phishing, credentials</sub>
- [SocialFish](https://github.com/UndeadSec/SocialFish) — <sub>phishing, credentials, web</sub>
- [HiddenEye](https://github.com/Morsmalleo/HiddenEye) — <sub>phishing, credentials, social-engineering</sub>
- [Evilginx3](https://github.com/kgretzky/evilginx2) — <sub>phishing, mitm, credentials, web</sub>
- [SayCheese](https://github.com/hangetzzu/saycheese) — <sub>social-engineering, phishing</sub>
- [QR Code Jacking](https://github.com/cryptedwolf/ohmyqr) — <sub>phishing, social-engineering</sub>
- [QRLJacking](https://github.com/OWASP/QRLJacking) — <sub>phishing, social-engineering, credentials</sub>
- [Maskphish](https://github.com/jaykali/maskphish) — <sub>phishing, social-engineering</sub>
- [dnstwist](https://github.com/elceef/dnstwist) — <sub>osint, dns, phishing</sub>
- [GoPhish (Phishing Simulation)](https://getgophish.com/) — <sub>phishing, social-engineering, email, credentials, web</sub>
- [GoPhish Documentation](https://docs.getgophish.com/) — <sub>phishing, reference, learning</sub>
- [MITRE ATT&CK — Phishing (T1566)](https://attack.mitre.org/techniques/T1566/) — <sub>phishing, social-engineering, reference</sub>

## 🌐 Web Attack tools

- Skipfish — <sub>web, vuln-scan, scanner, crawler</sub>
- [SubDomain Finder](https://github.com/aboul3la/Sublist3r) — <sub>subdomain-enum, recon, osint, dns</sub>
- [Sub-Domain TakeOver](https://github.com/edoardottt/takeover) — <sub>subdomain-enum, web, vuln-scan</sub>
- [Dirb](https://gitlab.com/kalilinux/packages/dirb) — <sub>web, enumeration, bruteforce, wordlist</sub>
- [Nuclei (Vulnerability Scanner)](https://github.com/projectdiscovery/nuclei) — <sub>web, vuln-scan, scanner</sub>
- [ffuf (Web Fuzzer)](https://github.com/ffuf/ffuf) — <sub>web, fuzzing, enumeration, wordlist</sub>
- [Feroxbuster (Directory Brute Force)](https://github.com/epi052/feroxbuster) — <sub>web, enumeration, bruteforce, wordlist</sub>
- [Nikto (Web Server Scanner)](https://github.com/sullo/nikto) — <sub>web, vuln-scan, scanner</sub>
- [wafw00f (WAF Detector)](https://github.com/EnableSecurity/wafw00f) — <sub>web, fingerprint, recon</sub>
- [Katana (Web Crawler)](https://github.com/projectdiscovery/katana) — <sub>web, crawler, recon, enumeration</sub>
- [Gobuster (Dir/DNS/Vhost Brute Force)](https://github.com/OJ/gobuster) — <sub>web, enumeration, bruteforce, dns, wordlist</sub>
- [Dirsearch (Web Path Discovery)](https://github.com/maurosoria/dirsearch) — <sub>web, enumeration, bruteforce, wordlist</sub>
- [OWASP ZAP (Web App Scanner)](https://github.com/zaproxy/zaproxy) — <sub>web, vuln-scan, scanner, fuzzing</sub>
- [testssl.sh (TLS/SSL Checker)](https://github.com/drwetter/testssl.sh) — <sub>web, scanner, fingerprint</sub>
- [Arjun (HTTP Parameter Discovery)](https://github.com/s0md3v/Arjun) — <sub>web, fuzzing, enumeration</sub>
- [Caido (Web Security Auditing)](https://github.com/caido/caido) — <sub>web, scanner, crawler</sub>
- [mitmproxy (Intercepting Proxy)](https://github.com/mitmproxy/mitmproxy) — <sub>web, mitm, sniffing</sub>
- [WhatWeb (Web Fingerprinter)](https://github.com/urbanadventurer/WhatWeb) — <sub>web, fingerprint, recon, scanner</sub>
- [WPScan (WordPress Scanner)](https://github.com/wpscanteam/wpscan) — <sub>web, vuln-scan, scanner, enumeration</sub>
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — <sub>learning, web, reference</sub>
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — <sub>cheatsheet, reference, payload, web</sub>
- [HackTricks](https://book.hacktricks.xyz/) — <sub>cheatsheet, reference, web, privesc</sub>
- [revshells.com (Reverse Shell Generator)](https://www.revshells.com/) — <sub>reverse-shell, cheatsheet, online-service, web</sub>

## 🔧 Post exploitation tools

- [pwncat-cs (Reverse Shell Handler)](https://github.com/calebstewart/pwncat) — <sub>post-exploitation, reverse-shell, persistence, privesc</sub>
- [Sliver (C2 Framework)](https://github.com/BishopFox/sliver) — <sub>c2, post-exploitation, payload</sub>
- [PEASS-ng — LinPEAS/WinPEAS (Priv Esc)](https://github.com/peass-ng/PEASS-ng) — <sub>privesc, post-exploitation, enumeration</sub>
- [Ligolo-ng (Tunneling/Pivoting)](https://github.com/nicocha30/ligolo-ng) — <sub>tunneling, lateral-movement, post-exploitation, network</sub>
- [Chisel (HTTP Tunnel)](https://github.com/jpillora/chisel) — <sub>tunneling, lateral-movement, post-exploitation, network</sub>
- [Evil-WinRM (Windows Remote Shell)](https://github.com/Hackplayers/evil-winrm) — <sub>lateral-movement, credentials, post-exploitation, active-directory</sub>
- [Mythic (C2 Platform)](https://github.com/its-a-feature/Mythic) — <sub>c2, post-exploitation, lateral-movement</sub>
- [pspy (unprivileged process snooping)](https://github.com/DominicBreuker/pspy) — <sub>post-exploitation, privesc, enumeration</sub>
- [linux-smart-enumeration (lse.sh)](https://github.com/diego-treitos/linux-smart-enumeration) — <sub>privesc, post-exploitation, enumeration</sub>
- [LaZagne (Local Credential Recovery)](https://github.com/AlessandroZ/LaZagne) — <sub>credentials, post-exploitation, password-attack</sub>
- [HackTricks (post-ex / privesc playbook)](https://book.hacktricks.xyz/) — <sub>post-exploitation, privesc, reference, cheatsheet</sub>
- [LOLBAS (Windows living-off-the-land binaries)](https://lolbas-project.github.io/) — <sub>privesc, post-exploitation, reference, cheatsheet</sub>
- [revshells.com (reverse shell generator)](https://www.revshells.com/) — <sub>reverse-shell, post-exploitation, online-service, reference</sub>
- [PayloadsAllTheThings (payload + technique cheatsheets)](https://github.com/swisskyrepo/PayloadsAllTheThings) — <sub>payload, post-exploitation, reference, cheatsheet</sub>
- [mimikatz (Windows credential dumping — reference)](https://github.com/gentilkiwi/mimikatz) — <sub>credentials, post-exploitation, active-directory, reference</sub>

## 🕵 Forensic tools

- Autopsy — <sub>forensics, metadata</sub>
- Wireshark — <sub>network, forensics, sniffing, pcap</sub>
- [Bulk extractor](https://github.com/simsong/bulk_extractor) — <sub>forensics, memory-dump, metadata</sub>
- [Disk Clone and ISO Image Acquire](https://guymager.sourceforge.io/) — <sub>forensics, binary</sub>
- [Toolsley](https://www.toolsley.com/) — <sub>reference, online-service, forensics</sub>
- [Volatility 3 (Memory Forensics)](https://github.com/volatilityfoundation/volatility3) — <sub>forensics, memory-dump, malware-analysis</sub>
- [Binwalk (Firmware Analysis)](https://github.com/ReFirmLabs/binwalk) — <sub>forensics, binary, reversing</sub>
- [pspy (Process Monitor — No Root)](https://github.com/DominicBreuker/pspy) — <sub>forensics, post-exploitation, enumeration</sub>
- [ExifTool (Metadata)](https://exiftool.org/) — <sub>forensics, metadata, image, document</sub>
- [Foremost (File Carving)](http://foremost.sourceforge.net/) — <sub>forensics, binary</sub>
- [Eric Zimmerman's Tools](https://ericzimmerman.github.io/) — <sub>reference, forensics, online-service</sub>
- [MalwareBazaar (Sample Database)](https://bazaar.abuse.ch/) — <sub>online-service, reference, malware-analysis</sub>

## 📦 Payload creation tools

- [The FatRat](https://github.com/Screetsec/TheFatRat) — <sub>payload, reverse-shell, apk, c2</sub>
- [Stitch](https://nathanlopez.github.io/Stitch) — <sub>payload, c2, reverse-shell, persistence</sub>
- [Venom Shellcode Generator](https://github.com/r00t-3xp10it/venom) — <sub>payload, reverse-shell, c2</sub>
- [Mob-Droid](https://github.com/kinghacker0/Mob-Droid) — <sub>payload, mobile, apk, reverse-shell</sub>
- [msfvenom (Payload Generator)](https://github.com/rapid7/metasploit-framework) — <sub>payload, reverse-shell, c2, apk</sub>
- [LOLBAS (Living Off The Land Binaries)](https://lolbas-project.github.io/) — <sub>reference, payload, post-exploitation</sub>

## 🧰 Exploit framework

- [RouterSploit](https://github.com/threat9/routersploit) — <sub>network, iot, exploitation, scanner</sub>
- [Commix](https://github.com/commixproject/commix) — <sub>web, exploitation, payload</sub>
- [Metasploit Framework](https://github.com/rapid7/metasploit-framework) — <sub>exploitation, post-exploitation, payload, c2, scanner</sub>
- [SearchSploit (Exploit-DB CLI)](https://gitlab.com/exploit-database/exploitdb) — <sub>exploitation, recon, reference</sub>
- [Exploit-DB (Online Archive)](https://www.exploit-db.com/) — <sub>online-service, reference, exploitation</sub>
- [Metasploit Unleashed (Free Course)](https://www.offsec.com/metasploit-unleashed/) — <sub>learning, reference, exploitation</sub>

## 🔁 Reverse engineering tools

- [Androguard](https://github.com/androguard/androguard) — <sub>reversing, apk, mobile, malware-analysis</sub>
- [Apk2Gold](https://github.com/lxdvs/apk2gold) — <sub>reversing, apk, mobile</sub>
- [JadX](https://github.com/skylot/jadx) — <sub>reversing, apk, mobile</sub>
- [Ghidra (NSA Reverse Engineering)](https://github.com/NationalSecurityAgency/ghidra) — <sub>reversing, binary, malware-analysis</sub>
- [Radare2 (RE Framework)](https://github.com/radareorg/radare2) — <sub>reversing, binary</sub>
- [apktool (APK Decode/Rebuild)](https://apktool.org/) — <sub>reversing, apk, mobile</sub>
- [GDB (GNU Debugger)](https://www.sourceware.org/gdb/) — <sub>reversing, binary</sub>
- [binutils (strings / objdump / readelf)](https://www.gnu.org/software/binutils/) — <sub>reversing, binary</sub>
- [crackmes.one (RE Practice)](https://crackmes.one/) — <sub>reference, learning, reversing</sub>
- [Malware Unicorn RE101 (Workshop)](https://malwareunicorn.org/workshops/re101.html) — <sub>reference, learning, reversing, malware-analysis</sub>

## ⚡ DDOS Attack Tools

- [DDoS](https://github.com/the-deepnet/ddos) — <sub>ddos, network, web</sub>
- SlowLoris — <sub>ddos, web</sub>
- [UFOnet](https://github.com/epsylon/ufonet) — <sub>ddos, web, network</sub>
- [SaphyraDDoS](https://github.com/anonymous24x7/Saphyra-DDoS) — <sub>ddos, web</sub>
- [hping3 (Packet Crafter / Flooder)](https://github.com/antirez/hping) — <sub>ddos, network</sub>
- [slowhttptest (Slow-HTTP DoS Tester)](https://github.com/shekyan/slowhttptest) — <sub>ddos, web</sub>
- [OWASP Denial of Service Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html) — <sub>ddos, web, reference</sub>

## 🖥 Remote Administrator Tools (RAT)

- [Villain (Reverse Shell / C2 Manager)](https://github.com/t3l3machus/Villain) — <sub>c2, reverse-shell, post-exploitation, payload</sub>
- [hoaxshell (HTTP(S) PowerShell Reverse Shell)](https://github.com/t3l3machus/hoaxshell) — <sub>reverse-shell, c2, payload, post-exploitation</sub>
- [Merlin (cross-platform C2)](https://github.com/Ne0nd0g/merlin) — <sub>c2, post-exploitation, reference</sub>
- [Covenant (.NET C2)](https://github.com/cobbr/Covenant) — <sub>c2, post-exploitation, reference</sub>

## 🧪 XSS Attack Tools

- [DalFox (Finder of XSS)](https://github.com/hahwul/dalfox) — <sub>web, xss, scanner, fuzzing</sub>
- [XSS Payload Generator](https://github.com/capture0x/XSS-LOADER.git) — <sub>web, xss, payload</sub>
- [Advanced XSS Detection Suite](https://github.com/UltimateHackers/XSStrike) — <sub>web, xss, scanner, fuzzing</sub>
- [kxss (Reflection Finder)](https://github.com/Emoe/kxss) — <sub>web, xss, scanner, recon</sub>
- [PortSwigger — XSS Labs](https://portswigger.net/web-security/cross-site-scripting) — <sub>learning, web, xss, reference</sub>
- [PayloadsAllTheThings — XSS Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection) — <sub>cheatsheet, reference, xss, web</sub>

## 🖼 Steganography Tools

- SteganoHide — <sub>steganography, image, forensics</sub>
- [Stegseek (fast steganography cracker)](https://github.com/RickdeJager/stegseek) — <sub>steganography, hash-crack, bruteforce</sub>
- [stegseek (fast steghide cracker)](https://github.com/RickdeJager/stegseek) — <sub>steganography, bruteforce, password-attack, image</sub>
- [zsteg (PNG/BMP LSB detector)](https://github.com/zed-0xff/zsteg) — <sub>steganography, image, forensics</sub>
- [outguess (JPEG stego)](https://github.com/resurrecting-open-source-projects/outguess) — <sub>steganography, image, forensics</sub>
- [ExifTool (metadata reader)](https://exiftool.org/) — <sub>steganography, metadata, image, forensics</sub>
- [Aperi'Solve (all-in-one image stego)](https://www.aperisolve.com/) — <sub>steganography, image, online-service, reference</sub>
- [StegOnline (in-browser LSB explorer)](https://georgeom.net/StegOnline/upload) — <sub>steganography, image, online-service</sub>
- [Futureboy Stegano decoder](https://futureboy.us/stegano/decinput.html) — <sub>steganography, online-service, reference</sub>
- [stego-toolkit (Docker kit + checklist)](https://github.com/DominicBreuker/stego-toolkit) — <sub>steganography, reference, cheatsheet</sub>

## 🏢 Active Directory Tools

- [BloodHound (AD Attack Paths)](https://github.com/BloodHoundAD/BloodHound) — <sub>active-directory, enumeration, lateral-movement, credentials</sub>
- [NetExec — nxc (Network Pentesting)](https://github.com/Pennyw0rth/NetExec) — <sub>active-directory, network, enumeration, credentials, password-attack</sub>
- [Impacket (Network Protocol Tools)](https://github.com/fortra/impacket) — <sub>active-directory, credentials, network, lateral-movement, kerberos</sub>
- [Responder (LLMNR/NBT-NS Poisoner)](https://github.com/lgandx/Responder) — <sub>active-directory, credentials, mitm, sniffing, network, poisoning, relay</sub>
- [Certipy (AD Certificate Abuse)](https://github.com/ly4k/Certipy) — <sub>active-directory, credentials, privesc, enumeration, adcs</sub>
- [Kerbrute (Kerberos Brute Force)](https://github.com/ropnop/kerbrute) — <sub>active-directory, bruteforce, password-attack, enumeration, credentials, kerberos</sub>
- [ldapdomaindump (AD LDAP Dumper)](https://github.com/dirkjanm/ldapdomaindump) — <sub>active-directory, enumeration, credentials</sub>
- [Coercer (Authentication Coercion)](https://github.com/p0dalirius/Coercer) — <sub>active-directory, relay, privesc, credentials</sub>
- [PCredz (Credential Extractor)](https://github.com/lgandx/PCredz) — <sub>active-directory, credentials, sniffing, pcap, kerberos</sub>
- [The Hacker Recipes (AD)](https://www.thehacker.recipes/) — <sub>reference, active-directory, learning</sub>

## ☁ Cloud Security Tools

- [Prowler (Cloud Security Scanner)](https://github.com/prowler-cloud/prowler) — <sub>cloud, scanner, vuln-scan</sub>
- [ScoutSuite (Multi-Cloud Auditing)](https://github.com/nccgroup/ScoutSuite) — <sub>cloud, scanner, enumeration</sub>
- [Pacu (AWS Exploitation Framework)](https://github.com/RhinoSecurityLabs/pacu) — <sub>cloud, exploitation, post-exploitation</sub>
- [Trivy (Container/K8s Scanner)](https://github.com/aquasecurity/trivy) — <sub>scanner, vuln-scan, cloud</sub>
- [Checkov (IaC Misconfig Scanner)](https://github.com/bridgecrewio/checkov) — <sub>cloud, scanner, vuln-scan</sub>
- [HackTricks Cloud (cloud pentest playbook)](https://cloud.hacktricks.xyz/) — <sub>reference, cloud, learning</sub>
- [flaws.cloud (AWS Security Challenge)](http://flaws.cloud/) — <sub>learning, cloud, online-service</sub>

## 📱 Mobile Security Tools

- [MobSF (Mobile Security Framework)](https://github.com/MobSF/Mobile-Security-Framework-MobSF) — <sub>mobile, apk, vuln-scan, scanner, malware-analysis</sub>
- [Frida (Dynamic Instrumentation)](https://github.com/frida/frida) — <sub>mobile, reversing, malware-analysis</sub>
- [Objection (Mobile Runtime Exploration)](https://github.com/sensepost/objection) — <sub>mobile, reversing</sub>
- [adb (Android Debug Bridge)](https://developer.android.com/tools/adb) — <sub>mobile, apk</sub>
- [OWASP MAS (Mobile App Security)](https://mas.owasp.org/) — <sub>mobile, reference, learning</sub>
- [Frida CodeShare](https://codeshare.frida.re/) — <sub>mobile, reversing, online-service, reference</sub>

## ✨ Other tools

- [MySMS](https://github.com/papusingh2sms/mysms) — <sub>payload, mobile, apk</sub>
- [HatCloud(Bypass CloudFlare for IP)](https://github.com/HatBashBR/HatCloud) — <sub>recon, network, dns</sub>
- [Hash Buster](https://github.com/s0md3v/Hash-Buster) — <sub>hash-crack, lookup, online-service, credentials</sub>
- [Sherlock](https://github.com/sherlock-project/sherlock) — <sub>osint, recon, enumeration</sub>
- [SocialScan | Username or Email](https://github.com/iojw/socialscan) — <sub>osint, recon, email, enumeration</sub>
- [Pixload](https://github.com/chinarulezzz/pixload) — <sub>payload, steganography, image</sub>
- [Gospider](https://github.com/jaeles-project/gospider) — <sub>web, crawler, recon</sub>
- Terminal Multiplexer — <sub>cheatsheet, reference</sub>
- [Crivo](https://github.com/GMDSantana/crivo) — <sub>network, recon</sub>
- [CyberChef (Cyber Swiss-Army Knife)](https://gchq.github.io/CyberChef/) — <sub>reference, online-service</sub>

## 🔑 Password / Hash Cracking

- [hashcat (GPU hash cracker)](https://github.com/hashcat/hashcat) — <sub>hash-crack, password-attack, bruteforce</sub>
- [John the Ripper (jumbo)](https://github.com/openwall/john) — <sub>hash-crack, password-attack</sub>
- [hydra (Network Login Cracker)](https://github.com/vanhauser-thc/thc-hydra) — <sub>bruteforce, password-attack, credentials, network</sub>
- [CrackStation (online lookup)](https://crackstation.net/) — <sub>hash-crack, online-service, lookup</sub>
- [hashes.com (hash identifier + lookup)](https://hashes.com/en/tools/hash_identifier) — <sub>hash-crack, online-service, lookup</sub>
- [CyberChef (the cyber swiss-army knife)](https://gchq.github.io/CyberChef/) — <sub>online-service, reference</sub>
- [GTFOBins (unix binary abuse)](https://gtfobins.github.io/) — <sub>privesc, reference, cheatsheet</sub>

---

## Adding a tool

Most tools are **one YAML entry** in `src/hackingtool/catalog/` — no Python. See
[CONTRIBUTING.md](../CONTRIBUTING.md) for the entry format, the tag taxonomy, and
the checks your PR has to pass (`make check`).

Can't find what you need? Ask the console: `/find <what you're trying to do>`
searches the catalog first, then GitHub, and shows real maintained repos with the
reason each was ranked. See [HOW-TO-USE.md](HOW-TO-USE.md#4-find-a-tool-that-isnt-in-the-catalog-find).
