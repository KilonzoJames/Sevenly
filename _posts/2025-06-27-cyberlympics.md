---
title: Cyberlympics (2025)
date: 2025-06-27 08:00:00 +0800
categories: [ctf, crypto]
tags: [ctf, cyberlympics, cyberchef, crypto ]    # TAG names should always be lowercase
description: "Challenge: Lorenzo 150"
---

## Challenge
My name is Lorenzo the great and I love doing fun stuff, nice to meet y'all.

**`O8P59TJIBOGZY9MJPV`**

Flag Format: **`acdfCTF{UPPERCASE}`**

---


## 🛠️ Solution 
The challenge's description — particularly the name **"Lorenzo the Great"** and the seemingly random string `O8P59TJIBOGZY9MJPV` — strongly hinted at a cryptographic puzzle. 

After reading the prompt multiple times and conducting some external research, I identified the **Lorenz cipher** as the likely encryption method.

To solve it, I turned to [CyberChef](https://gchq.github.io/CyberChef/), a powerful web-based tool for decoding, encoding, and analyzing data. Through experimentation, I discovered that the key was to configure the **Lorenz Cipher** operation correctly.

> 🔑 **Key Insight**: Change the input type from *Plaintext* to *ITA2 (International Telegraph Alphabet)* — this is essential to how the Lorenz cipher operates.

Once applied, the hidden message was revealed: LORENZOTHETRICSTER.

---


## ✅ Final Flag
Adhering to the specified flag format`acdfCTF{UPPERCASE}`, the final flag is:

**acdfCTF{LORENZOTHETRICSTER}**

---


## 🧩 Summary:
This challenge was a fun, wordplay-based cryptography puzzle that required recognizing the specific **Lorenz cipher** and understanding the importance of the **ITA2 encoding**  in the decryption process. 

It served as a great reminder that seemingly random strings can hold meaningful data — when the right tools and context are applied.

---