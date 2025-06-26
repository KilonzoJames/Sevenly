---
title: Season V, US Cyber Open (2025)
date: 2025-06-26 08:00:00 +0800
categories: [ctf, forensics]
tags: [ctf, uscybergames, binwalk, cyberchef, exif, forensics, base64]    # TAG names should always be lowercase
description: "Challenge: Charlie (Forensics) – 100 pts"
group: "BGR - SIV Pipeline Forensics Group 5"
---


![Desktop View](/dzif8ltvg/image/upload/v1750932948/CTF/hn98wa3mg7oking6uxiy.jpg){: width="400" height="400"}

The challenge presents an image of a dog, hinting at a digital forensics task. Our goal: uncover hidden data buried within the image.

---


## 🧪 Initial Analysis: EXIF Data

Our first step is to examine the image's metadata using `exiftool`. Online options like [exif.tools](https://exif.tools/) are also available, and both macOS and Windows offer built-in tools for viewing photo metadata.

For this challenge, I used `exiftool` on Linux. However, this initial inspection did not reveal any useful information:

```bash
exiftool charlie.jpg 
```

![EXIF Data Screenshot](/dzif8ltvg/image/upload/v1750936834/CTF/kz3dre3yy6tmk4hdlzqm.png){: width="400" height="400" }

---


## 🕵️ Deep Dive: Binwalk Analysis

Next, I employed **binwalk** to detect and extract any embedded files within the image. The command `binwalk -e filename` is used for this purpose, analyzing a binary file and automatically extracting any detected embedded data.

The binwalk scan successfully identified a zip archive containing a file named flag.txt. Binwalk creates a dedicated directory for extracted data, and we located flag.txt within it.

```bash
# Extract embedded data from the image
binwalk -e charlie.jpg
```
### Output:

![Binwalk Output](/dzif8ltvg/image/upload/v1750936834/CTF/f4fhlkgp2hvj3odgckzy.png){: width="972" height="589" }

---


## 🔍 Decoding and Revelation: CyberChef
Upon opening flag.txt, we found a string of seemingly random text. This immediately suggested a Base64 encoding.

Recognizing the Base64 pattern, I used CyberChef, a powerful online tool, for decoding. While a simple online or command-line Base64 decoder could also work, CyberChef offers a versatile environment for such tasks.

The initial Base64 decoding resulted in what still appeared to be gibberish. However, the presence of "JFIF" at the beginning of the decoded output strongly indicated that the data was a JPEG image. Fortunately, CyberChef has the capability to render images directly from raw data.

![CyberChef Recipe](/dzif8ltvg/image/upload/v1750939417/CTF/svgalxmlyslmlrwshvzk.png){: width="400" height="400" }

And there we had it – the flag!

![Decoded Flag Image](/dzif8ltvg/image/upload/v1750935536/CTF/v7vnkgmy3iwy8flbpqgi.jpg){: width="400" height="400" }

The flag text can then be extracted from the image using an [Optical Character Recognition (OCR) tool](https://www.i2ocr.com/free-online-english-ocr).

🏁 Flag: SVBGR{B1NW4LK_F7N}

## 🧩 Summary:

This challenge highlighted the power of Binwalk and CyberChef in uncovering hidden files and decoding embedded images. A reminder that sometimes, images hold more than meets the eye.
