---
title: Microsoft ADC Capture the Flag
date: 2025-06-25 08:00:00 +0800
categories: [ctf, forensics]
tags: [ctf, microsoftadcctf]     # TAG names should always be lowercase
description: "We are 2 days away from the event: Kindly go through the teaser to see what we have instore for you on the day!"
---

## 🧨 Teaser Challenge

```text
I have got a teaser challenge for you to get into the CTF mood 🏴

📎See attached file. (This is a ZipBomb attack- your mission is to extract it)

* The teaser is harder than the challenges in the CTF because you have more time to work on it 😁

 ```
---


The challenge provides a single zip file:
- [`ExtractMe.zip`](/assets/files/ExtractMe.zip)  

---

## 🛠️ Solution & Script Explanation

The core of this challenge lies in a recursive zip bomb. A series of zip files nested within each other, each protected by a password. The twist: the password for each level is the name of the inner zip file (without the .zip extension). 

For example, if you unzip ExtractMe.zip and find 44008.zip inside, you'll use 44008 as the password to extract 44008.zip. This process repeats for hundreds or even thousands of levels, creating a recursive maze!

To automate this tedious process, I wrote the following Python script:

```python
import zipfile
import os

current_zip = "ExtractMe.zip"  # starting point
extract_dir = "extracted_dir"  # output directory
os.makedirs(extract_dir, exist_ok=True)    # Ensure the extraction directory exists

#This starts from the zip file called ExtractMe.zip
#Each zip file contains another zip file, and:
#The password for each level is the name of the inner zip file (without .zip).
#For example:
#You unzip ExtractMe.zip
#Inside is 83832.zip
#To unzip 83832.zip, you use the password: 83832
#This repeats hundreds or thousands of times — a recursive maze!

while True:
    try:
        with zipfile.ZipFile(current_zip) as z:
            # get the name of the next zip file
            inner_file = z.namelist()[0]
            password = os.path.splitext(inner_file)[0]
            print(f"[+] Extracting {inner_file} using password: {password}")

            # extract to the target directory
            z.extract(inner_file, path=extract_dir, pwd=bytes(password, 'utf-8'))

        # Update current_zip to the next level (full path inside extracted_dir)
        current_zip = os.path.join(extract_dir, inner_file)

    except RuntimeError as e:
        print(f"[!] Failed to extract {current_zip} - {e}")
        break
    except FileNotFoundError:
        print(f"[✓] Extraction complete. No more archives.")
        break
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        break

```
---

## 🔍 How the Script Works

```text
1. Initialization: It sets up the starting zip file (ExtractMe.zip) and a designated output directory (extracted_dir).

2. Recursive Extraction Loop: The while True loop continuously attempts to extract files.

3. Password Discovery: For each zip file, it identifies the name of the single inner file. This inner file's name (without the .zip extension) is then used as the password for its extraction.

4. Extraction: The zipfile module extracts the inner zip file into the extracted_dir, using the discovered password.

5. Iteration: The current_zip variable is updated to point to the newly extracted zip file, allowing the loop to continue to the next level of the zip bomb.

6. Exit Conditions / Termination: The loop breaks if 
- it encounters a RuntimeError (often due to an incorrect password or corrupted zip, which in this case signals the end of the chain)
- a FileNotFoundError (meaning no more zip files were found to extract)
- any other unexpected/unhandled Exception.
```


## ✅ Final Result

After running the script to completion, I found a file named FoundIt.txt inside the final extraction folder. (extracted_dir)

Reading its contents revealed the following message:

```text
cat FoundIt.txt 

Congratulations!
You have managed to solve the teaser!
Please send email to **redacted** with the following body:

'I g07 7h3 P455W012d F0R Th3 73az3r!'

We will see you in Microsoft CTF!
```

✅ The crucial piece of information to send via email was:

```text
I g07 7h3 P455W012d F0R Th3 73az3r!
```
---


## 🧩 Summary:

This teaser was a great warm-up exercise, introducing the concept of recursive zip bombs and the value of automation in forensic workflows. It demonstrated how scripting can transform an overwhelming manual task into a smooth, hands-off operation — just what you'd want before diving into the real challenges at Microsoft ADC CTF!
