# Shellcode Loader Bypass Techniques

This repository contains examples of advanced shellcode loader bypass techniques implemented in `test.cpp` and `bypass1.cpp`. These techniques are designed to evade detection and bypass modern security mechanisms, such as EDR (Endpoint Detection and Response) and AV (Antivirus) solutions.

---

## Techniques in `test.cpp`

The following bypass techniques are implemented in `test.cpp`:

1. **API Resolution and Dynamic Invocation**  
   Resolves and invokes APIs dynamically at runtime to avoid static detection.

2. **API Hammering**  
   Repeatedly calls benign APIs to confuse behavior-based detection mechanisms.

3. **String Obfuscation and Decryption**  
   Obfuscates sensitive strings (e.g., API names, shellcode) and decrypts them at runtime to evade static analysis.

4. **NTDLL Restoration and Anti-Hooking**  
   Restores the original, unhooked version of `ntdll.dll` to bypass user-mode hooks placed by EDRs.

5. **Thread Pool Execution of Shellcode**  
   Executes shellcode using thread pools to blend in with legitimate application behavior.

6. **Remote Thread Injection**  
   Injects shellcode into a remote process to execute payloads stealthily.

7. **Encrypted Shellcode File Loading (`shellcode.bin`)**  
   Loads and decrypts an encrypted shellcode file (`shellcode.bin`) at runtime to avoid detection.

---

## Techniques in `bypass1.cpp`

The following bypass techniques are implemented in `bypass1.cpp`:

1. **API Hashing for Function Resolution**  
   Resolves API functions using hashed names instead of plaintext strings to evade static analysis.

2. **API Hammering**  
   Similar to `test.cpp`, repeatedly calls benign APIs to confuse behavior-based detection mechanisms.

3. **Dynamic API Resolution**  
   Dynamically resolves API functions at runtime to avoid static detection.

4. **Unhooking `ntdll.dll`**  
   Restores the original, unhooked version of `ntdll.dll` to bypass user-mode hooks.

5. **Encrypted Shellcode File Loading (`shellcode.bin`)**  
   Loads and decrypts an encrypted shellcode file (`shellcode.bin`) at runtime to avoid detection.

6. **Thread Pool Execution**  
   Executes shellcode using thread pools to mimic legitimate application behavior.

7. **Stealthy Memory Allocation**  
   Allocates memory for shellcode in a stealthy manner, avoiding suspicious patterns that could trigger detection.

---
## Shellcode Loader Bypass Images  

### 1. 360 Bypass  
![360 Bypass](https://github.com/Answerr/shellcode_loader_bypass/blob/main/images/360_bypass1.png)  

### 2. Defender Test  
![Defender Test](https://github.com/Answerr/shellcode_loader_bypass/blob/main/images/Defender_test.png)  

### 3. Huorong Bypass  
![Huorong Bypass](https://github.com/Answerr/shellcode_loader_bypass/blob/main/images/huorong_bypass1.png)  

### 4. Tencent Bypass  
![Tencent Bypass](https://github.com/Answerr/shellcode_loader_bypass/blob/main/images/tencent_bypass1.png)

## Summary
test.cpp can bypass tencent,huorong,defender but not 360 because I added an remote injection fucntion on RunTimeBroker.exe
bypass1.cpp can bypass tencent,huorong,360 but not defender

> **Disclaimer:**  
> This repository is for educational and research purposes only. The techniques demonstrated here should not be used for malicious purposes. Always ensure compliance with applicable laws and regulations.

---
