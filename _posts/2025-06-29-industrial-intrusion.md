---
title: Industrial Intrusion (2025) - OSINT Challenge Write-up
date: 2025-06-30 08:00:00 +0800
categories: [ctf, osint]
tags: [ctf, tryhackme, osint]    # TAG names should always be lowercase
description: "Challenge: OSINT 1 - 3"
---


## Introduction
This write-up details the solutions and methodologies employed to solve the OSINT challenges (Tasks 5, 6, and 7) from the "Industrial Intrusion" CTF, which took place from June 27th to June 29th, 2025.

---


## Task 5: OSINT 1 - Subdomain Discovery

### Challenge Description

The first challenge required the discovery of subdomains for the `virelia-water.it.com` website.

![OSINT 1 Image](/dzif8ltvg/image/upload/v1751273434/CTF/industrial-intrusion/OSINT/tegppxuhyepskwgcjbhd.png){: width="400" height="400"}

### Solution Methodology

Our primary approach involved using subdomain enumeration tools and leveraging public data sources.

1.  **Sublist3r for Subdomain Enumeration:**
    We utilized `Sublist3r` to identify potential subdomains for `virelia-water.it.com`. The command and its output are shown below:

    ```bash
    python3 sublist3r.py -d virelia-water.it.com
    # ... (redacted Sublist3r verbose output for brevity) ...

    [-] Total Unique Subdomains Found: 2
    54484d7b5375357373737d.virelia-water.it.com
    stage0.virelia-water.it.com
    ```

    One of the found subdomains, `54484d7b5375357373737d.virelia-water.it.com`, appeared to be an encoded string. Recognizing it as a hexadecimal string, we decoded it to reveal the flag:

    ```bash
    echo 54484d7b5375357373737d | xxd -p -r
    THM{Su5sss}
    ```

### Alternative Approaches

Several other OSINT techniques could have been used to achieve the same result:

1.  **GitHub Search:**
    A targeted search on GitHub for `virelia-water.it.com` yielded relevant repositories:
    * `https://github.com/solstice-tech1/ot-auth-mirror`
        Within the `index.html` file of this repository, a redirect to `https://54484d7b5375357373737d.virelia-water.it.com/reset` was discovered, confirming the hexadecimal subdomain.
    * `https://github.com/solstice-tech1/staging-panel/blob/main/CNAME`
        This file explicitly listed `stage0.virelia-water.it.com`, confirming the second subdomain.

2.  **crt.sh Certificate Transparency Logs:**
    Checking `crt.sh` for `virelia-water.it.com` would also reveal registered subdomains. The entry for `54484d7b5375357373737d.virelia-water.it.com` on `crt.sh` would further reinforce the hexadecimal nature of the subdomain, leading to its decoding.

---


## Task 6: OSINT 2 - Hidden C2 Information

### Challenge Description

The second challenge involved further enumeration of the previously found subdomains to uncover hidden information.

![OSINT 2 Image](/dzif8ltvg/image/upload/v1751273433/CTF/industrial-intrusion/OSINT/mv9nvfpve0npfiu4xfje.png){: width="400" height="400"}

### Solution Methodology

Our investigation started with the two identified subdomains. While direct web browse of `54484d7b5375357373737d.virelia-water.it.com` did not reveal any immediate leads, we continued our analysis with `stage0.virelia-water.it.com`.

1.  **Source Code Analysis of `stage0.virelia-water.it.com`:**
    Upon inspecting the HTML source code of `stage0.virelia-water.it.com`, we identified a link to an external JavaScript file:
    
    [https://raw.githubusercontent.com/SanTzu/uplink-config/refs/heads/main/init.js](https://raw.githubusercontent.com/SanTzu/uplink-config/refs/heads/main/init.js)
    
    This JavaScript file (`init.js`) contained the following object:

    ```javascript
    var beacon = {
      session_id: "O-TX-11-403",
      fallback_dns: "uplink-fallback.virelia-water.it.com",
      token: "JBSWY3DPEBLW64TMMQQQ=="
    };
    ```

## Investigation of `uplink-fallback.virelia-water.it.com`

The `fallback_dns` value, `uplink-fallback.virelia-water.it.com`, immediately suggested a potential Command & Control (C2) infrastructure subdomain. 
Although direct DNS resolution attempts (e.g., `dig ANY uplink-fallback.virelia-water.it.com`) did not yield immediate results, we pivoted to investigating DNS `TXT` records, which are often used to store arbitrary data, including configuration or hidden messages.

    ```bash
    # Initial attempt that didn't yield useful results
    dig ANY uplink-fallback.virelia-water.it.com
    # ... (Output omitted) ...
    ```

1.  **Querying TXT Records:**

    A `dig` query for `TXT` records on `uplink-fallback.virelia-water.it.com` revealed a promising result:

    ```bash
    dig TXT uplink-fallback.virelia-water.it.com

    ; <<>> DiG 9.20.4-3ubuntu1.1-Ubuntu <<>> TXT uplink-fallback.virelia-water.it.com
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 58891
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

    ;; OPT PSEUDOSECTION:
    ; EDNS: version: 0, flags:; udp: 65494
    ;; QUESTION SECTION:
    ;uplink-fallback.virelia-water.it.com. IN TXT

    ;; ANSWER SECTION:
    uplink-fallback.virelia-water.it.com. 1799 IN TXT "eyJzZXNzaW9uIjoiVC1DTjEtMTcyIiwiZmxhZyI6IlRITXt1cGxpbmtfY2hhbm5lbF9jb25maXJtZWR9In0="

    ;; Query time: 72 msec
    ;; SERVER: 127.0.0.53#53(127.0.0.53) (UDP)
    ;; WHEN: Sat Jun 28 09:54:55 EAT 2025
    ;; MSG SIZE  rcvd: 162
    ```

2.  **Decoding the Base64 String:**

    The `TXT` record contained a Base64 encoded string: `eyJzZXNzaW9uIjoiVC1DTjEtMTcyIiwiZmxhZyI6IlRITXt1cGxpbmtfY2hhbm5lbF9jb25maXJtZWR9In0=`
    Decoding this string revealed a JSON object containing the flag:

    ```bash
    echo eyJzZXNzaW9uIjoiVC1DTjEtMTcyIiwiZmxhZyI6IlRITXt1cGxpbmtfY2hhbm5lbF9jb25maXJtZWR9In0 | base64 -d
    {"session":"T-CN1-172","flag":"THM{uplink_channel_confirmed}"}
    ```

    This Base64 string could also be decoded using online tools that support JWT or generic Base64 decoding, such as [jwt.lannysport.net](https://jwt.lannysport.net/) (though this wasn't strictly a JWT, it shared the same encoding principles).

---


## Task 7: OSINT 3 - PGP Signature Verification

### Challenge Description

The final OSINT challenge involved investigating a mysterious PGP-signed message related to `virelia-water.it.com`.

![OSINT 3 Image](/dzif8ltvg/image/upload/v1751273434/CTF/industrial-intrusion/OSINT/fbibossnavxkyn2kohtx.png){: width="400" height="400"}

### Contextual Analysis

Initial investigation through GitHub searches for `virelia-water.it.com` led to the `virelia-water/compliance` repository. A specific commit, `bf80b28d73cdbbccaa37c34633de98cd00e7b236` titled "Removing during investigation", raised suspicion. This commit indicated the removal of the "June 2025 OT Alerts Exception report" from the public website.

![Removing during investigation](/dzif8ltvg/image/upload/v1751274565/CTF/industrial-intrusion/OSINT/ponnysodghjuizlmmol7.png){: width="400" height="400"}

Key details gathered about the PGP message:
* The removed report was a routine maintenance notice, signed with PGP, which is unusual and raised suspicion.
* Corporate auditors quietly removed it due to potential malicious intent.
* The message was signed by "DarkPulse" from `alerts@virelia-water.it.com`.
* The message requested confirmation of system integrity at 03:00 UTC.

### Solution Methodology

The core of this challenge was to verify the PGP signature and retrieve the associated public key, which was expected to contain the flag.


1.  **Saving the Signed Message:**
    The provided signed message was saved to a file named `signed_message.asc`. For brevity, the full content is not shown here, but it followed the standard PGP signed message format:

    ```text
    -----BEGIN PGP SIGNED MESSAGE-----
    ...
    -----BEGIN PGP SIGNATURE-----
    ...
    -----END PGP SIGNATURE-----
    ```

2.  **Attempting Signature Verification:**
    We attempted to verify the signature using `gpg`:

    ```bash
    gpg --verify signed_message.asc
    gpg: Signature made Mon 23 Jun 2025 15:44:52 EAT
    gpg:                using RSA key 88DEDE7B730513BD5EDD6D9FA4F0FEB084A311E5
    gpg:                issuer "alerts@virelia-water.it.com"
    gpg: Can't check signature: No public key
    ```
    As expected, `gpg` indicated that it could not check the signature because the public key (`88DEDE7B730513BD5EDD6D9FA4F0FEB084A311E5`) was not available locally.

3.  **Retrieving the Public Key:**
    To retrieve the public key, we used a public key server (Ubuntu's keyserver in this case), specifying the key ID found in the previous step:

    ```bash
    gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys 88DEDE7B730513BD5EDD6D9FA4F0FEB084A311E5
    gpg: key F8ED5BC28874364F: public key "Ghost (THM{h0pe_th1s_k3y_doesnt_le4d_t0_m3}) <solstice.tech.ops@gmail.com>" imported
    gpg: Total number processed: 1
    gpg:               imported: 1
    ```

    The output of the `recv-keys` command revealed the public key details, including the user ID (Ghost (THM{h0pe_th1s_k3y_doesnt_le4d_t0_m3}) <solstice.tech.ops@gmail.com>), which contained the flag:

    **THM{h0pe_th1s_k3y_doesnt_le4d_t0_m3}**

---


## 📌 Takeaway

These OSINT challenges highlighted the importance of:
* **Thorough Subdomain Enumeration:** Using multiple tools and sources (e.g., Sublist3r, GitHub, crt.sh) for comprehensive discovery.
* **Source Code Review:** Always checking HTML and linked external files (like JavaScript) for hidden clues.
* **DNS Record Investigation:** Beyond A/AAAA records, `TXT` records are a common place to store arbitrary data, including C2 information or flags.
* **PGP Key Analysis:** Understanding how to verify PGP signatures and retrieve public keys from keyservers, as flags can often be embedded within key metadata (like the User ID).
* **Commit History Scrutiny:** Git repositories often contain valuable historical data, even for "removed" information.

This CTF provided excellent practice in applying various OSINT techniques to uncover layered information.

---
