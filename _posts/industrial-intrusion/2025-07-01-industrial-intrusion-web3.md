---
title: Industrial Intrusion (2025) - Web3 Challenge Write-up
date: 2025-07-01 08:00:00 +0800
categories: [ctf, web3]
tags: [ctf, tryhackme, web3]    # TAG names should always be lowercase
description: "Challenge: Web Task 33 - 34"
---

## Introduction

This write-up covers the solutions to `Web3 IndustrialChain` and `Web3 Obscurity`, two smart contract challenges from the `Industrial Intrusion (2025)` CTF. Both tasks required interacting with Ethereum smart contracts using `ethers.js`, demonstrating key concepts in contract state control and private variable retrieval.

---

## Task 33 Web3 IndustrialChain

### The Challenge

Flicker has ghosted through your decentralised control logic quietly, reversing override conditions in your smart contract. The main switch appears engaged, but safety locks remain enforced at the contract level.

Your mission: Reclaim manual control. Could you review the smart contract logic and execute the correct sequence to override the sabotage?

---


### Solution

The core of this challenge lies in interacting with a provided Solidity smart contract. The objective is to activate the system and then press an override button, which requires the system to be activated first. This suggests a two-step interaction with the contract functions.

We used `ethers.js` to interact with the smart contract deployed on the given RPC endpoint.

**Steps taken:**

1.  **Initialize Project:**
    ```bash
    npm init -y
    npm install ethers
    ```
2.  **Create `solve.js`:** A JavaScript file was created to house the interaction logic.
3.  **Interact with Contract:**
    * An `ethers.JsonRpcProvider` was set up to connect to the provided RPC endpoint (`http://<ip>:8545`).
    * A wallet was initialized with a private key to sign transactions.
    * The contract address (`0xE8B291589C19d39199EB01d5e6f5D2a22b3F868d`) and its Application Binary Interface (ABI) were defined to allow `ethers.js` to understand the contract's functions.
    * The `engageMainSwitch()` function was called first to activate the system.
    * Subsequently, the `pressOverrideButton()` function was called to complete the override.
    * Finally, `checkSystem()` and `isSolved()` functions were called to verify the status and confirm the challenge was solved.

**Execution:**

```bash
node solve.js
✅ Using wallet: 0xB20A0621C0CA5dee86EE7410D54FCfDeB249d059
[*] Engaging Main Switch...
[*] Pressing Override Button...
📟 System Status: System Online  Mission Accomplished!
🎉 Challenge Solved! Go get your flag!

THM{Industrial_Override_Activated}
```
---


## 🧾 Final Solution

The flag obtained upon successful execution was:

**THM{Industrial_Override_Activated}**

---


## 🧩 Summary 

The challenge involved a simple smart contract with a logical flow that required two sequential transactions. The `Challenge` contract had an `emergencyShutdown` variable (which was not directly relevant to the solution path), a `systemActivated` boolean, and a `you_solved_it` boolean. The `engageMainSwitch` function sets `systemActivated` to `true`. The `pressOverrideButton` function, which sets `you_solved_it` to `true`, has a `require` statement ensuring `systemActivated` is `true` before it can be executed.

The `solve.js` script correctly identified this dependency and executed the functions in the necessary order, leading to the `you_solved_it` state being `true` and thus revealing the flag.

The challenge tests understanding of logical sequencing in contract functions. The override can only succeed if the system is first activated—a simple yet effective access control mechanism.

---


### Smart Contract Code (Challenge.sol)

---

### Solution Script (solve.js)

```javascript
const { ethers } = require("ethers");

const provider = new ethers.JsonRpcProvider("http://<ip>:8545");

const wallet = new ethers.Wallet(
  "0x14e9b2c9fcfa23ad5a15ca21e3153813a4dfbb0bbc9f0a6dd7fc05e286960428",
  provider
);

const address = "0xE8B291589C19d39199EB01d5e6f5D2a22b3F868d";

const abi = [
  "function engageMainSwitch() external returns (bool)",
  "function pressOverrideButton() external returns (bool)",
  "function isSolved() external view returns (bool)",
  "function checkSystem() external view returns (string)"
];

(async () => {
  try {
    const signerAddress = await wallet.getAddress();
    console.log("✅ Using wallet:", signerAddress);

    const contract = new ethers.Contract(address, abi, wallet);

    console.log("[*] Engaging Main Switch...");
    await (await contract.engageMainSwitch()).wait();

    console.log("[*] Pressing Override Button...");
    await (await contract.pressOverrideButton()).wait();

    const status = await contract.checkSystem();
    const solved = await contract.isSolved();

    console.log("📟 System Status:", status);
    console.log(solved ? "🎉 Challenge Solved! Go get your flag!" : "❌ Still not solved.");
  } catch (err) {
    console.error("❌ Error:", err.message || err);
  }
})();

```
---


## Task 34 Web3 Obscurity

## Introduction

This write-up details the solution and methodologies employed to solve **Task 34: Web3 Obscurity**  from the "Industrial Intrusion (2025)" CTF. This challenge focuses on interacting with a smart contract where a critical piece of information, a secret code, is stored in a private storage slot. To restore control, this private code must be retrieved directly from the blockchain's storage, demonstrating that even private contract state is accessible via direct blockchain storage inspection.

---


### The Challenge

The plant’s override relay was blockchain-governed. That is until Flicker embedded a sabotage handshake inside the contract’s state logic. Now, the machinery won’t respond unless the hidden sequence is re-executed.

Sensors are reading “Main switch: ON”, but nothing moves. Flicker’s smart contract ghost fork rewired state verification, hiding the real override behind two calls in just the right order.

---


### Solution

This challenge required a deeper understanding of how Solidity smart contracts store data. The `unlock` function required a `uint256` input that matched a private `code` variable. Since `code` is `private`, it cannot be directly accessed via a public getter function. However, private variables in Solidity are still stored on the blockchain's state and can be read directly from specific storage slots.

We leveraged `ethers.js`'s `provider.getStorage()` method to read the value of the `code` variable from its storage slot.

**Steps taken:**

1.  **Initialize Project:**
    ```bash
    npm init -y
    npm install ethers
    ```
2.  **Create `solve.js`:** A JavaScript file was created to house the interaction logic.
3.  **Identify Storage Slot:**
    * In Solidity, state variables are stored sequentially starting from slot 0.
    * `string private secret` is at slot 0.
    * `bool private unlock_flag` is at slot 1.
    * `uint256 private code` is at slot 2.
    * Therefore, we needed to read storage slot 2 to get the `code`.
4.  **Retrieve `code` from Storage:**
    * `provider.getStorage(contractAddr, 2)` was used to fetch the raw hexadecimal value from storage slot 2.
    * `ethers.toBigInt(raw)` converted this raw value into a `BigInt`, representing the `code`.
5.  **Interact with Contract:**
    * An `ethers.JsonRpcProvider` was set up to connect to the provided RPC endpoint (`http://<ip>:8545`).
    * A wallet was initialized with a private key to sign transactions.
    * The contract address (`0x74dae0A0e456C8556525c7f16fB07CD9c25b2127`) and its ABI were defined.
    * The `unlock()` function was called with the recovered `code` as the input.
    * Finally, `isSolved()` and `getFlag()` functions were called to verify the status and retrieve the flag.

---

**Execution:**

```bash
node solve.js
[*] Recovered code: 6778
[*] Calling unlock()...
[+] Unlock transaction mined!
[*] isSolved(): true
[🎉] FLAG: The flag is not here!
THM{web3_obscurity}
```

---


## 🧾 Final Solution

The flag obtained upon successful execution was:

**THM{web3_obscurity}**

---


## 🧩 Summary 
The challenge `Web3 Obscurity` tested the understanding of Solidity's storage layout. Even though a variable (`code`) was declared `private`, its value was still retrievable directly from the blockchain's storage. By identifying the correct storage slot (`slot 2` for `code`), we could read its value using `ethers.js`'s `getStorage` method. This `code` was then used as an argument to the `unlock` function, which in turn set `unlock_flag` to `true`, allowing the `getFlag` function to be called and the flag to be retrieved.

---


## Smart Contract Code (Challenge.sol)

---

## Solution Script (solve.js)

```javascript
const { ethers } = require("ethers");

const RPC_URL = "http://<ip>:8545";  // Your provided RPC
const provider = new ethers.JsonRpcProvider(RPC_URL);

// Your wallet details
const privateKey = "0xad7791c6c55e81789fbadabeef3b2584546cd2b30d727fb1bb0b017706792af2";
const wallet = new ethers.Wallet(privateKey, provider);

// Challenge contract address
const contractAddr = "0x74dae0A0e456C8556525c7f16fB07CD9c25b2127";

// ABI of relevant functions
const abi = [
  "function unlock(uint256 input) public returns (bool)",
  "function isSolved() public view returns (bool)",
  "function getFlag() public view returns (string)"
];

async function main() {
  try {
    // Step 1: Read storage slot 2 (uint256 private code)
    const raw = await provider.getStorage(contractAddr, 2);
    const code = ethers.toBigInt(raw);
    console.log("[*] Recovered code:", code.toString());

    // Step 2: Connect to contract
    const contract = new ethers.Contract(contractAddr, abi, wallet);

    // Step 3: Call unlock(code)
    console.log("[*] Calling unlock()...");
    const tx = await contract.unlock(code);
    await tx.wait();
    console.log("[+] Unlock transaction mined!");

    // Step 4: Verify and get flag
    const solved = await contract.isSolved();
    console.log("[*] isSolved():", solved);

    if (solved) {
      const flag = await contract.getFlag();
      console.log("[🎉] FLAG:", flag);
    } else {
      console.log("[-] Unlock failed.");
    }
  } catch (err) {
    console.error("Error:", err);
  }
}

main();

```
---