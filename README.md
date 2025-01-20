# Shellcode Loader Bypass Techniques  

This repository contains examples of advanced Shellcode Loader bypass techniques implemented in `test.cpp` and `bypass1.cpp`. These techniques are designed to evade detection and bypass modern security mechanisms such as EDR (Endpoint Detection and Response) and AV (Antivirus) solutions.   

**Note:** Using binary files smaller than 100kb tends to be more stable due to memory allocation limits imposed by thread pool execution; otherwise, you may need to sacrifice stealth.  

## Techniques in `test.cpp`  

The following bypass techniques are implemented in `test.cpp`:  

1. **API Resolution and Dynamic Invocation**  
   Dynamically resolve and call APIs at runtime to avoid static detection.  

2. **API Hammering**  
   Repeatedly call benign APIs to obfuscate behavior-based detection mechanisms.  

3. **String Obfuscation and Decryption**  
   Obfuscate sensitive strings (such as API names and Shellcode) and decrypt them at runtime to evade static analysis.  

4. **NTDLL Recovery and Unhooking**  
   Restore the original, unhooked `ntdll.dll` to bypass user-mode hooks placed by EDR.  

5. **Thread Pool Execution of Shellcode**  
   Use a thread pool to execute Shellcode, mimicking legitimate application behavior.  

6. **Remote Thread Injection**  
   Inject Shellcode into a remote process to execute the payload stealthily.  

7. **Encrypted Shellcode File Loading (`shellcode.bin`)**  
   Load and decrypt an encrypted Shellcode file (`shellcode.bin`) at runtime to avoid detection.  

## Techniques in `bypass1.cpp`  

The following bypass techniques are implemented in `bypass1.cpp`:  

1. **API Hash Resolution Function**  
   Use hashed names instead of plaintext strings to resolve API functions, circumventing static analysis.  

2. **API Hammering**  
   Similar to `test.cpp`, repeatedly call benign APIs to obfuscate behavior-based detection mechanisms.  

3. **Dynamic API Resolution**  
   Dynamically resolve API functions at runtime to avoid static detection.  

4. **Unhooking `ntdll.dll`**  
   Restore the original, unhooked `ntdll.dll` to bypass user-mode hooks.  

5. **Encrypted Shellcode File Loading (`shellcode.bin`)**  
   Load and decrypt an encrypted Shellcode file (`shellcode.bin`) at runtime to avoid detection.  

6. **Thread Pool Execution**  
   Use a thread pool to execute Shellcode, mimicking legitimate application behavior.  

7. **Stealthy Memory Allocation**  
   Allocate memory for Shellcode in a stealthy manner to avoid triggering detection caused by suspicious patterns.  

## Usage Instructions  

1. Use your preferred method to generate a `.bin` file of the raw Shellcode.  
2. Rename the file to `input.bin` and run `xor.py`. This will generate an encrypted file named `output.bin`.  
3. Rename `output.bin` to `shellcode.bin` and place it in the same directory as the executable.  
4. Execute the payload.  


Shellcode Loader Bypass Screenshots  

### 1. 360 Bypass  
![360 Bypass](https://github.com/Answerr/shellcode_loader_bypass/blob/main/images/360_bypass1.png)  

### 2. Defender Test  
![Defender Test](https://github.com/Answerr/shellcode_loader_bypass/blob/main/images/Defender_test.png)  

### 3. Huorong Bypass  
![Huorong Bypass](https://github.com/Answerr/shellcode_loader_bypass/blob/main/images/huorong_bypass1.png)  

### 4. Tencent Bypass  
![Tencent Bypass](https://github.com/Answerr/shellcode_loader_bypass/blob/main/images/tencent_bypass1.png)

# Summary  

- **`test.cpp`:** Can bypass Tencent, Huorong, and Defender, but fails to bypass 360 due to the addition of remote injection targeting `RuntimeBroker.exe`.  

- **`bypass1.cpp`:** Can bypass Tencent, Huorong, and 360, but fails to bypass Defender.  

## Disclaimer  

This repository is for educational and research purposes only. The techniques demonstrated here should not be used for malicious purposes. Always ensure compliance with applicable laws and regulations.
