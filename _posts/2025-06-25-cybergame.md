---
title: CyberGame 2025
date: 2025-06-26 10:00:00 +0800
categories: [CTF, cryptography]
tags: [ctf, cybergame, cryptography]     # TAG names should always be lowercase
description: "Short Crypto Tales - SecretFunction^2 – Points: 18"
---


## Description

**EN:**  
Legend has it that Gregory the Great—retired barista turned mad quaternion tinkerer—built a four-dimensional safe guarded by hyper-caffeinated squirrels and locked his secret croissant recipe inside a swirling mashup of a, b, c, and d raised to the 65537th power; now it’s up to you to brave his bamboozling “SecretFunction” arithmetic (u, v, and w included at no extra charge) and decrypt his espresso-fueled masterpiece.

The challenge provides two files:  
- [`message.txt`](/assets/files/message.txt)  
- [`main.py`](/assets/files/main.py)

---

## Solution

After researching the underlying math, I discovered a helpful write-up from another solver: [RSA 4.0](https://7rocky.github.io/en/ctf/other/seccon-ctf/rsa-4.0/). By following their process step-by-step, I was able to understand the mechanics and successfully recover the flag.

---


Afterward, I wrote a script to automate the steps I took:


```python
import os
import re
from math import gcd

# --- Step 1: Read the encrypted data from message.txt ---
data = {}
with open('message.txt', 'r') as f:
    for line in f:
        # Remove leading/trailing whitespace and split by '='
        parts = line.strip().split(' = ')
        if len(parts) == 2:
            key = parts[0]
            # Handle the 'enc' value which is a string representation of a Quaternion
            if key == 'enc':
                data[key] = parts[1]
            else:
                try:
                    data[key] = int(parts[1])
                except ValueError:
                    data[key] = parts[1] # Keep as string if not an integer

n = data.get('n')
e = data.get('e')
enc_str = data.get('enc') # This will be the string representation of the quaternion

if n is None or e is None or enc_str is None:
    print("Error: Could not find 'n', 'e', or 'enc' in message.txt. Please check the file format.")
    exit()


# --- Step 2: Parse the 'enc' string into its coefficients ---
# enc = "327 + 644i -289j +101k"
# Split by ' + ' or ' - ' carefully to keep signs
parts = enc_str.split(' + ')

# Initialize variables
a_n = b_n = c_n = d_n = 0

for part in parts:
    if '*i' in part:
        clean_part = part.replace('*i', '').strip()
        if clean_part.startswith('+'):
            clean_part = clean_part[1:].strip()
        b_n = int(clean_part)
    elif '*j' in part:
        clean_part = part.replace('*j', '').strip()
        if clean_part.startswith('+'):
            clean_part = clean_part[1:].strip()
        c_n = int(clean_part)
    elif '*k' in part:
        clean_part = part.replace('*k', '').strip()
        if clean_part.startswith('+'):
            clean_part = clean_part[1:].strip()
        d_n = int(clean_part)
    else:
        clean_part = part.strip()
        if clean_part.startswith('+'):
            clean_part = clean_part[1:].strip()
        a_n = int(clean_part)

# print(a_n, b_n, c_n, d_n)


# --- Step 3: Factor n (using your derived relationships) ---
qX_val = pow(22386, -1, n) * (9 * d_n + 77 * b_n - 98 * c_n)
qX_val %= n # Ensure it's within the modulus

q = gcd(n, qX_val)
p = n // q

# print(f"\nFactoring n:")
# print(f"p = {p}")
# print(f"q = {q}")


# --- Step 4: Validate p and q (optional but good for debugging) ---
if p * q == n:
    print("p * q == n: True (Factorization successful!)")
else:
    print("p * q == n: False (Something went wrong with factorization)")


# --- Step 5: Solve for X and then b (based on your derivation) ---
X = pow(12 * p - 300 * q, -1, n) * (c_n - b_n) % n
b_val = b_n * pow(X, -1, n) % n

# print(f"\nX = {X}")
print(f"b_val (which should be enc_i) = {b_val}")


# --- Step 6: Extract m from the derived relationship ---
m = (b_val - p - 337 * q) // 3

print(f"\nCalculated m = {m}")


# --- Step 7: Convert m back to bytes ---
if m < 0:
    print("Warning: Calculated m is negative. This might indicate an issue.")
    m = abs(m) # Or handle appropriately based on expected flag format

flag_bytes = bytes.fromhex(hex(m)[2:])

print(f"\nDecrypted Flag: {flag_bytes.decode('utf-8', errors='ignore')}")

```

---

## Final Result
After successfully reconstructing the mathematical steps and automating the process, I was able to decrypt the final flag:

```text
Decrypted Flag: SK-CERT{RSA_w17h_u54g3_0f_qu473rn10n5}
```
---


## 🧩 Summary:
This challenge was a fun twist on classical RSA encryption, incorporating quaternion-based operations to obfuscate the message. With a bit of research, external insight, and scripting, the espresso-fueled encryption was cracked!