---
title: Industrial Intrusion (2025) - Reverse Engineering Challenge Write-up
date: 2025-06-30 08:00:00 +0800
categories: [ctf, reverse engineering]
tags: [ctf, tryhackme, reverse engineering]    # TAG names should always be lowercase
description: "Challenge: Reverse Engineering Tasks 24-27"
---


## Introduction

This write-up details the solutions and methodologies employed to solve the reverse engineering challenges (Tasks 24-27) from the "Industrial Intrusion" CTF, which took place from June 27th to June 29th, 2025. This post will provide a comprehensive breakdown of the tasks and their solutions.


## Task 24  Reversing Auth

### The Challenge

![Reverse Engineering Image 1](/dzif8ltvg/image/upload/v1698409460/samples/cup-on-a-table.jpg){: width="400" height="400"}

The scenario for this task was: "ZeroTrace intercepts a stripped-down authentication module running on a remote industrial gateway. Assembly scrolls across glowing monitors as she unpacks the logic behind the plant’s digital checkpoint."

We were provided with a virtual machine that accepted `netcat` connections on port `9005` (e.g., `nc 10.10.10.10 9005`). Interacting with it initially showed:

```
[?] Enter unlock code: [!] Access Denied!
```

Additionally, an ELF binary named `auth` was provided for download via: 
`wget http://<ip>/auth/auth.zip`.

---


## Solution Methodology

### Initial Analysis
First, I examined the downloaded `auth` binary to understand its basic properties using the `file` command:

```bash
file auth
auth: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=06ef6e45afa25c9ef8a775bde8bfabe48cdc0251, for GNU/Linux 3.2.0, not stripped
```

This confirmed it was a 64-bit ELF executable, not stripped, which is ideal for static analysis.

---


### Ghidra Disassembly and Code Analysis

I then loaded the binary into Ghidra for static analysis. The key functions identified were `main` and `transform`.

#### 🔍 Breakdown of main()

The `main` function's decompiled code revealed the core authentication logic:

![Main Function in Ghidra](/dzif8ltvg/image/upload/v1751302707/CTF/industrial-intrusion/Reverse%20Engineering/hwvvpzrqmrqj3hfadp4p.png){: width="400" height="400"}

**The code reads an 8-byte user input and passes it through a `transform()` function before comparing it against a hardcoded 8-byte target. If it matches, it prints the flag from `flag.txt`. Let's walk through it and identify how to break it.**

**Key Observations from `main()`:**

* `local_160 = 0xefcdab8967452301;`: This is the hardcoded target value that the transformed user input must match for successful authentication.

* `fgets((char *)local_158,0x40,stdin);`: User input is read into a buffer local_158 (buffer of 8 undefined8s = 64 bytes).

* `sVar4 = strnlen((char *)local_158,0x40); if (sVar4 == 8)`: The program only proceeds if the user's input is exactly 8 characters long.

* `local_168 = local_158[0]; transform(&local_168, 8);`: Only the first 8 bytes of the input (local_158[0]) are copied to local_168, and then the transform function is applied to local_168.

* `memcmp(&local_168,&local_160,8);`: This is the final comparison. The transformed input (local_168) is compared byte-for-byte with the hardcoded target value (local_160). If they match, the flag is printed from flag.txt.

Our goal was clear: reverse the `transform()` function to find the 8-character string which, after transformation, becomes `0xefcdab8967452301`.


#### 🔍 Breakdown of tranform()

Next, I investigated the `transform` function's implementation:

![Transform Function in Ghidra](/dzif8ltvg/image/upload/v1751302706/CTF/industrial-intrusion/Reverse%20Engineering/qtnay2vned6pk4qzwmhr.png){: width="400" height="400"}

The function iterates through the input buffer (of length `param_2`, which is 8 in our case) and performs a simple operation: it XORs each byte with the value 0x55.

This means the `transform` function is a straightforward **XOR cipher** using a single-byte key `**0x55**`.

---


### Reversing the Transformation (Decryption)

**Goal Recap: We want to find an 8-character string, such that after XORing each byte with `0x55`, the result is: `0xefcdab8967452301`.**

Since XOR is a symmetric operation:

**X ^ 0x55 = Y  ⇒  X = Y ^ 0x55** 

, we can reverse the transformation by simply XORing the target value with 0x55.

The target value from `main()` is `0xefcdab8967452301`. To perform the byte-by-byte XOR, we consider its little-endian representation:

`01 23 45 67 89 ab cd ef`

Now, we XOR each byte with `0x55`:

```text
XOR each byte with 0x55:
0x01 ^ 0x55 = 0x54 = 'T'
0x23 ^ 0x55 = 0x76 = 'v'
0x45 ^ 0x55 = 0x10 = '\x10'
0x67 ^ 0x55 = 0x32 = '2'
0x89 ^ 0x55 = 0xdc = 'Ü'
0xab ^ 0x55 = 0xfe = 'þ'
0xcd ^ 0x55 = 0x98 = '˜'
0xef ^ 0x55 = 0xba = 'º'
```

🔢 Byte-by-Byte Decryption ⇒ `Original Byte (Hex) ^ Result (Hex) = ASCII Character`

The resulting 8-byte unlock code is \x54\x76\x10\x32\xdc\xfe\x98\xba. As this sequence contains non-printable and high-ASCII characters, it cannot be directly typed into a standard terminal.

---


### Exploitation

#### Local Testing (Optional)

For testing locally with the downloaded binary (e.g., ./auth), you can pipe the calculated bytes:

```bash
python3 -c 'import sys; sys.stdout.buffer.write(b"\x54\x76\x10\x32\xdc\xfe\x98\xba")' | ./auth
```

Alternatively, if writing an exploit script, the byte array can be directly used:
`unlock_code = bytes([0x54, 0x76, 0x10, 0x32, 0xdc, 0xfe, 0x98, 0xba])`


### Remote Exploitation

To interact with the running challenge on the remote host (let's use 10.10.10.10 as an example, since the exact IP might vary in a CTF), we need to send these specific bytes.

Here's how to do it using Python and netcat:

1. Connect via netcat
Open a terminal and connect using:

```bash
nc 10.10.80.97 9005
```

You should see the prompt: `[?] Enter unlock code:`

2. Prepare the payload 
The correct 8 byte unlock code as a Python byte string: `b"\x54\x76\x10\x32\xdc\xfe\x98\xba"`

3. Send the payload via netcat:
Since direct typing isn't possible, we'll pipe the bytes to netcat using Python's sys.stdout.buffer.write to ensure binary data is handled correctly. Remember to include a newline character (\n) to simulate pressing Enter after the input.

```bash
python3 -c 'import sys; sys.stdout.buffer.write(b"\x54\x76\x10\x32\xdc\xfe\x98\xba\n")' | nc 10.10.10.10 9005
```

⚠️ Note:

- The \n at the end simulates pressing Enter.
- sys.stdout.buffer.write is required to handle non-printable binary data correctly.

4. Expected Output
If successful, you’ll get something like:

```bash
python3 -c 'import sys; sys.stdout.buffer.write(b"\x54\x76\x10\x32\xdc\xfe\x98\xba\n")' | nc 110.10.10.10 9005
[?] Enter unlock code: [+] Access Granted! Flag: THM{Simple_tostart_nice_done_mwww}
```

## 🧾 Final Result

And, there we have it.  

Upon executing the command, the server responded with the reverse engineering beginner flag:

`**THM{Simple_tostart_nice_done_mwww}**`

This successfully completed Task 24, demonstrating a fundamental understanding of reverse engineering binary authentication logic and handling non-printable characters in exploits.

---





## Task 25 Reversing Access Granted

### Challenge Description

![Reverse Engineering Image 2](/dzif8ltvg/image/upload/v1698409460/samples/cup-on-a-table.jpg){: width="400" height="400"}

The scenario for this second challenge was: "ZeroTrace intercepts a suspicious HMI login module on the plant floor. Reverse the binary logic to reveal the access key and slip past digital defenses."

We were provided with: 
- a virtual machine accepting `netcat` connections on port `9009`:
`nc <ip> 9009`

- An ELF binary named `access_granted` was also provided for download:
`wget http://<ip>/access_granted/access_granted.zip`

---


### Solution Methodology

#### Initial Analysis

After unzipping the file, I examined the downloaded `access_granted` binary using the `file` command to determine its properties:

```bash
file access_granted
access_granted: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e9097542628490c31042bb6a07667b49f6d44c39, for GNU/Linux 3.2.0, not stripped
```
This confirmed it was a 64-bit ELF executable, not stripped — function names and symbols are preserved, making reverse engineering easier.

---


### Ghidra Disassembly and Code Analysis

I then loaded the binary into Ghidra for static analysis. The primary functions of interest were `main` and `print_flag`.

### Analyzing main()

The decompiled code for the `main` function revealed the authentication mechanism:

![main Function](/dzif8ltvg/image/upload/v1751303417/CTF/industrial-intrusion/Reverse%20Engineering/qgqaknguusbcqxikq4lm.png){: width="400" height="400"}

Key Observations from main():

- `read(0, local_38, 0x1f);`: This line reads up to 0x1f (31) bytes of user input from standard input (file descriptor 0) into the buffer local_38.

- `strncmp(pass, local_38, 10);`: This is the crucial comparison. It compares the first 10 bytes of a variable named pass with the first 10 bytes of the user's input (local_38).

If the `strncmp` returns `0` (indicating a match), the program calls `print_flag()`.

Our goal was to identify the correct 10-byte string hardcoded in the `pass` variable.


### Analyzing print_flag()

The print_flag() function, as observed in Ghidra, was straightforward:

![print_flag Function](/dzif8ltvg/image/upload/v1751303417/CTF/industrial-intrusion/Reverse%20Engineering/orgnp1gbo9lbphzzic9l.png){: width="400" height="400"}

This function simply reads and prints the contents of flag.txt — so our main challenge lies in bypassing the password check.

---


### Strategy: Static vs Dynamic

Given the challenge, two main approaches could be considered:

1.  **Static Analysis (Ghidra/IDA/Radare2):**
    * Search for the global or static variable `pass` in the decompiled or disassembled code.
    * If it's directly initialized in the binary's `.data` or `.rodata` section, it might show as: `char pass[10] = "S3cr3tK3y!";`
    * If it's obfuscated or dynamically loaded, further analysis of surrounding code would be necessary.

2.  **Dynamic Analysis (GDB):**
    * Execute the binary in a debugger and inspect its memory and registers during runtime, particularly around the `strncmp` call, to find the value of `pass`.

I opted for dynamic analysis using GDB, which proved to be an efficient method for this challenge.

---


### Dynamic Analysis with GDB

Given the clear comparison in main(), dynamic analysis using GDB was an efficient approach to extract the hardcoded password. The strategy involved setting a breakpoint at the specific strncmp function and inspecting its arguments. In x86-64 Linux, the first two arguments to a function are typically passed in the rdi and rsi registers, respectively.

Here's a transcript of the GDB session:

1.  **Prepare dummy input:** Create a file with 10 characters (e.g., 'A's) to provide input to the program's `read()` function.

    ```bash
    ❯ echo -n "AAAAAAAAAA" > input.txt
    ```

2.  **Launch GDB and load the binary:**

    ```bash
    ❯ gdb ./access_granted
    GNU gdb (GDB) 12.1
    ... (GDB license and info messages) ...
    Reading symbols from ./access_granted...
    # ... (redacted verbose output for brevity) ...
    (gdb) break main
    Breakpoint 1 at 0x1319
    (gdb) run < input.txt
    Starting program: /path to binary file/access_granted < input.txt
    [Thread debugging using libthread_db enabled]
    Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

    Breakpoint 1, 0x0000555555555319 in main ()
    ```

3.  **Break at `strncmp` and Continue:**

    ```bash
    (gdb) break strncmp
    Breakpoint 2 at 0x7ffff7d99660: strncmp. (2 locations)
    (gdb) continue
    Continuing.
    Enter the password :
    processing...
    # ... (redacted) ...
    ```

4.  **Inspect `strncmp` arguments:** Once execution hits the `strncmp` breakpoint, the program will pause. We can then inspect the contents of the `rdi` and `rsi` registers to find the values being compared.

    * The first argument (`rdi`) holds the correct password (`pass`).
    * The second argument (`rsi`) holds our dummy input.

    ```bash
    (gdb) x/s $rdi
    0x555555558010 <pass>:  "industrial"
    (gdb) x/s $rsi
    0x7fffffffd9c0: "AAAAAAAAAA"
    ```

5.  **Exit GDB:**

    ```bash
    (gdb) quit
    A debugging session is active.

        Inferior 1 [process 234320] will be killed.

    Quit anyway? (y or n) y
    ```

---


### Verification and Remote Exploitation

With the password "industrial" in hand, the next step was to verify it locally and then use it against the remote challenge.

#### Local Verification
Running the access_granted binary locally with the correct password:

```bash
❯ ./access_granted 
Enter the password : industrial

processing...Access Granted!
Flag file not found!
```

Note: The "Flag file not found!" message is expected during local testing if flag.txt does not exist in the current directory.

#### Remote Exploitation
Connecting to the challenge VM via netcat and providing the discovered password:

```bash
❯ nc <ip> 9009
Enter the password : industrial

processing...Access Granted!
THM{s0meth1ng_inthe_str1ng_she_knows}
```
This successfully retrieved the flag from the remote server.

---


## 🧾 Final Result

And once more, there we have it. 

The reverse engineering easy flag: 

`**THM{s0meth1ng_inthe_str1ng_she_knows}**`

This challenge reinforced the effectiveness of dynamic analysis using GDB for quickly identifying hardcoded values in a binary.

---





## Task 26 Reversing Simple Protocol


### Challenge Description

![Reverse Engineering Image 3](/dzif8ltvg/image/upload/v1698409460/samples/cup-on-a-table.jpg){: width="400" height="400"}

The scenario for this challenge was: "Amid whirring routers and blinking panel lights, ZeroTrace dissects a custom network protocol linking industrial subsystems. Patterns in the packet flow hint at secrets embedded deep within machine chatter."

We were provided with:
* A virtual machine accepting `netcat` connections on port `4444`:
    ```bash
    nc <ip> 4444
    ```
* An ELF binary named `prot` was also provided for download:
    ```bash
    wget http://<ip>/small-protocol/prot.zip
    ```
---

### 🎯 Objective

The objective was to identify how to inject a crafted packet into the target protocol that bypasses or abuses internal command routing logic to extract sensitive data (e.g. the flag).

---


### Solution Methodology

#### Initial Analysis

I began by examining the downloaded `prot` binary using the `file` command to determine its properties:

```bash
❯ file prot
prot: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3c8e02fb6a10bb5831066c5f85da6cbbdf53b172, for GNU/Linux 3.2.0, stripped
```

This output confirms that the binary is `64-bit, position-independent (PIE), and stripped`, meaning most function names and debug symbols are removed. This implies a greater reliance on static analysis tools like Ghidra to understand the program's logic.

---


### Ghidra Disassembly and Code Analysis

I loaded the `prot` binary into Ghidra for static analysis. Several functions were identified as key to understanding the custom protocol:

✅ Key Functions Identified

- FUN_00101575: This is the main server logic, responsible for socket setup, receiving client data, and handling the core protocol.
- FUN_00101421 – This function handles the flag retrieval and dispatch logic.
- FUN_001013c9 and FUN_001013e2 – These functions appeared to be custom handlers for other, less relevant, command types.

### Analyzing FUN_00101575(): Protocol Dissection

This function is the heart of the custom server. Its decompiled view revealed the network communication and protocol parsing logic.

| ![Server A](/dzif8ltvg/image/upload/v1751353856/CTF/industrial-intrusion/Reverse%20Engineering/v9ffjfybz68d5lviyzuj.png) | ![Server B](/dzif8ltvg/image/upload/v1751353856/CTF/industrial-intrusion/Reverse%20Engineering/cdnc71qxrsgz7bammjo0.png) |
|:--:|:--:|
| FUN_00101575 Function Part A | FUN_00101575 Function Part B |

Function Overview:

FUN_00101575() implements a custom TCP server that:

- Listens on TCP port 4444 (0x115c).
- Accepts an incoming client connection.
- Expects a specific 20-byte custom protocol packet: a 12-byte header followed by 8 bytes of body metadata.
- Validates critical fields, including a checksum and payload size.
- Dispatches to a command handler (FUN_00101421) based on a command_id if all validations pass. The FUN_00101421 function is responsible for sending the flag.txt content.

---

### 📦 Packet Structure

Through detailed analysis of `FUN_00101575`, the custom protocol's structure and validation logic were reverse-engineered as follows:

#### 🔐 Header (12 bytes)

| Field        | Value        | Size | Endianness | Notes               |
|--------------|--------------|------|------------|---------------------|
| `field1`     | `0xaaaa`     | 2 B  | Big-Endian | Arbitrary field     |
| `command_id` | `0x0100`     | 2 B  | Big-Endian | Triggers flag logic |
| `checksum`   | `0xabab5678` | 4 B  | Big-Endian | Must be computed correctly |
| `payload_id` | `0x12345678` | 4 B  | Big-Endian | Matches body section |


#### 🧩 Body Metadata (8 bytes)

This section immediately follows the 12-byte header.

| Field            | Value        | Size | Endianness | Notes                    |
|------------------|--------------|------|------------|--------------------------|
| `payload_id`     | `0x12345678` | 4 B  | Big-Endian | Must match header value  |
| `payload_length` | `0x00000000` | 4 B  | Big-Endian | Valid length (≤ 64 bytes) |

---


### Checksum Validation Logic
The checksum is a critical field that the server verifies before processing a packet. The binary calculates an expected checksum (local_64) and compares it to the received checksum (local_6c). If they do not match, the connection is terminated.

The formula for the expected checksum (derived from the C-style logic in Ghidra) is:

`expected_checksum = (payload_id & 0xffff) | ((command_id ^ field1) << 16);`

```
payload_id = 0x12345678
command_id = 0x0100
field1 = 0xaaaa

checksum = (payload_id & 0xffff) | ((command_id ^ field1) << 16)
checksum = (0x12345678 & 0xffff) | ((0x0100 ^ 0xaaaa) << 16) # Substitute values
checksum = 0x5678 | (0xabab << 16)                         # Intermediate XOR and mask
checksum = 0x5678 | 0xabab0000                             # Left shift
checksum = 0xabab5678                                      # Final result
```

---

### 🔎 Analyzing FUN_00101421(): Flag Dispatch Logic

![FUN_00101421 Function](/dzif8ltvg/image/upload/v1751353856/CTF/industrial-intrusion/Reverse%20Engineering/ne1ityu5jdbvmkss9ib1.png)

This function is responsible for serving the contents of flag.txt to the connected client. It accepts one parameter: the client socket file descriptor (param_1).

Behavior Summary:

1. Open Flag File

    ```c
    __stream = fopen("flag.txt", "rb");
    ```

    The function attempts to open flag.txt in binary read mode ("rb"). If the file doesn't exist, it sends "flag not found\n" to the client.

2. Read and Send Contents

    ```c
    sVar1 = fread(local_118, 1, 0xff, __stream);
    ```

    It attempts to read up to 0xff (255) bytes into the local_118 buffer. If nothing is read (e.g., the file is empty), it sends "flag empty\n".

    Otherwise:

    ```
    local_118[sVar1] = 0; // Null-terminate the buffer
    send(param_1, local_118, sVar1, 0); // Sends the content to the client
    ```

    The read content is null-terminated and then sent to the client via send().

**Key Takeaway**: This function is the final stage of the protocol logic for flag retrieval. If a client sends a valid packet with command_id = 0x0100, execution reaches this function, which attempts to read flag.txt and return its content over the socket.

---


### Packet Crafting and Exploitation

We assemble the 20-byte payload by choosing:

* `field1 = 0xaaaa` (arbitrary, 2 bytes)
* `command_id = 0x0100` (required for flag, 2 bytes)
* `payload_id = 0x12345678` (arbitrary, 4 bytes)
* `payload_length = 0x00000000` (valid, ≤ 64 bytes)
* `checksum = 0xabab5678` (calculated from formula above)

The final packet, incorporating these values and adhering to the big-endian requirements for all fields, is then constructed. (Refer to the "Packet Structure" section above for a detailed breakdown of the header and body metadata fields).

---

### Python Script to Send Packet
The following Python script crafts and sends this specific 20-byte packet to the remote server to retrieve the flag:

```python
import socket
import struct

field1 = 0xaaaa
cmd_id = 0x0100
payload_id = 0x12345678
checksum = (payload_id & 0xffff) | ((cmd_id ^ field1) << 16)

host = "<ip>"
port = 4444

with socket.create_connection((host, port)) as s:
    header = struct.pack(">HHII", field1, cmd_id, checksum, payload_id)
    body_meta = struct.pack(">II", payload_id, 0)  # 0-length payload
    s.sendall(header + body_meta)

    print(s.recv(4096).decode())
```

---

## 🧾 Final Result

Executing the Python script against the remote target successfully retrieved the flag:

```python
❯ python3 prot.py
THM{what-a-prot0c0l}
```

This challenge provided valuable experience in reverse engineering custom network protocols and crafting packets to trigger specific functionalities.

---





## Task 27 Reversing Jump Procedure


![Reverse Engineering Image 4](/dzif8ltvg/image/upload/v1698409460/samples/cup-on-a-table.jpg){: width="400" height="400"}

### The Challenge

The "Reversing Jump Procedure" challenge involved:
* A remote VM accepting `netcat` connections: `nc <ip> 9100`
* An ELF binary (`jmpproc.zip`) for local analysis: `wget http://<ip>/jmpproc/jmpproc.zip`

---

Our mission: Find three specific integer inputs ("Process ID," "Skip bytes proc," "Process bound") that would make `jmpproc` print a hidden flag instead of an error "Procedure Error" or crash "Illegal instruction". The program's unusual "jump patterns" complicated analysis.

---


### Initial Investigation

Running `jmpproc` locally revealed its input-dependent behavior:

```bash
❯ ./jmpproc
Process ID: 0
Skip bytes proc: 0
Process bound: 0
Procedure Error
❯ ./jmpproc
Process ID: 1
Skip bytes proc: 1
Process bound: 1
1
Illegal instruction (core dumped) # Crashed! Inputs matter!
```

This program (jmpproc) takes 3 inputs:
* Process ID → affects how many machine instructions the program skips
* Skip bytes proc → also controls how far we jump ahead in the code
* Process bound → likely passed to a function that adds to a value

Providing zeros resulted in a benign error, while ones caused a crash. This indicated inputs directly controlled program execution flow, likely by dictating jump offsets in machine code.

The core logic involved starting with val = 1, undergoing three transformations based on our inputs, and aiming for val == 1337 to get the flag.

![next_label1 Function](/dzif8ltvg/image/upload/v1751357348/CTF/industrial-intrusion/Reverse%20Engineering/m5luzl2kptgrlcd9xoud.png)

![next_label2 Function](/dzif8ltvg/image/upload/v1751357349/CTF/industrial-intrusion/Reverse%20Engineering/noz5awzyw5fd1ptwxswg.png)

![next_label3 Function](/dzif8ltvg/image/upload/v1751357349/CTF/industrial-intrusion/Reverse%20Engineering/e0g2by6l6oooamydachy.png)

### Reverse Engineering the Logic

We analyzed the program's transformations and modeled them in Python:

* **Function 1 (input `a`):** Multiplied `val` by $2^{(7-a)}$ if $a \le 6$.
* **Function 2 (input `b`):** Iteratively applied $val = (val + 2) \times 4$ for $(15-b)$ times if $b < 15$.
* **Function 3 (input `c`):** Added `c` to `val`.

Our Python simulation to find the correct logical inputs:

```python
def final_value(a, b, c):
    """Simulate jmpproc's transformations to find when final value hits 1337."""
    d = 1
    if a <= 6:
        d *= 2 ** (7 - a)         # Function 1: shift left
    if b < 15:
        for _ in range(15 - b):  # Function 2: iterative (d + 2) * 4
            d = (d + 2) * 4
    return d + c                 # Function 3: add c

TARGET = 1337
print("🔍 Searching for (a, b, c) that yield 1337...")

for a in range(7):   # Iterate through possible 'a' values
    for b in range(15):  # Iterate through possible 'b' values
        for c in range(150): # Iterate through possible 'c' values
            if final_value(a, b, c) == TARGET:
                # 'c_effective' accounts for a specific internal transformation (150 - c)
                print(f"✅ a={a}, b={b}, c_raw={c}, c_effective={150 - c}")
```

Running the script yielded:

```
❯ python3 jmpproc.py 
🔍 Searching for (a, b, c) that yield 1337...
✅ a=3, b=12, c_raw=145, c_effective=5
✅ a=6, b=11, c_raw=145, c_effective=5
```
We chose the solution a=3, b=12, and c_effective=5.

---


### Translating to Program Inputs (Byte Offsets)
The jmpproc program didn't use the logical values (a, b, c_effective) directly. Instead, these were multipliers for byte offsets that told the program where to jump in its code. We then translated these value into byte offsets for the program's actual inputs ("Process ID", "Skip bytes proc", "Process bound"). This translation was derived by analyzing the assembly instruction sizes:
  
- Function 1: Each step was 3 bytes. So, Process ID = a * 3.
- Function 2: Each iteration was 8 bytes. So, Skip bytes proc = b * 8.
- Function 3: Each step was 4 bytes. So, Process bound = c_effective * 4.

Using our chosen solution (a=3, b=12, c_effective=5):

 - Process ID: 3
times3=9
- Skip bytes proc: 12
times8=96
- Process bound: 5
times4=20

---


## 🧾 Final Solution

First, we tried it on our local machine (where we downloaded the jmpproc binary):

```
❯ ./jmpproc
Process ID: 9
Skip bytes proc: 96
Process bound: 20
cat: flag.txt: No such file or directory
```

It didn't crash, and it didn't say "Procedure Error"! Instead, it tried to cat flag.txt. This meant our calculations were correct, and the program would have printed the flag if the flag.txt file existed locally (which it wouldn't, as the flag was likely only on the remote VM).

Finally, we connected to the actual challenge VM using netcat and provided our calculated inputs:

```
nc 10.10.10.10 9100
Process ID: 9
Skip bytes proc: 96
Process bound: 20
THM{jmpjmp+little_r4bb1t}
```

Success! The VM gave us the flag: THM{jmpjmp+little_r4bb1t}.

---