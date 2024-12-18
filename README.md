# Shellcode Loader 绕过技术  

此仓库包含在 `test.cpp` 和 `bypass1.cpp` 中实现的高级 Shellcode Loader 绕过技术示例。这些技术旨在规避检测并绕过现代安全机制，如 EDR（端点检测与响应）和 AV（杀毒软件）解决方案。  
PS:用小于100kb以下的bin较稳定，因为线程池执行的内存分配限制，不然就得牺牲隐蔽性。

---  

## `test.cpp` 中的技术  

以下绕过技术在 `test.cpp` 中实现：  

1. **API 解析与动态调用**  
   在运行时动态解析并调用 API，以避免静态检测。  

2. **API Hammering（API 锤击）**  
   重复调用无害的 API 以混淆基于行为的检测机制。  

3. **字符串混淆与解密**  
   对敏感字符串（如 API 名称、Shellcode）进行混淆，并在运行时解密以规避静态分析。  

4. **NTDLL 恢复与反 Hook**  
   恢复原始、未 Hook 的 `ntdll.dll`，以绕过 EDR 放置的用户模式 Hook。  

5. **线程池执行 Shellcode**  
   使用线程池执行 Shellcode，以模仿合法的应用程序行为。  

6. **远程线程注入**  
   将 Shellcode 注入到远程进程中，以隐秘地执行负载。  

7. **加密 Shellcode 文件加载（`shellcode.bin`）**  
   在运行时加载并解密加密的 Shellcode 文件（`shellcode.bin`），以避免检测。  

---  

## `bypass1.cpp` 中的技术  

以下绕过技术在 `bypass1.cpp` 中实现：  

1. **API 哈希解析函数**  
   使用哈希名称而非明文字符串解析 API 函数，以规避静态分析。  

2. **API Hammering（API 锤击）**  
   与 `test.cpp` 类似，重复调用无害的 API 以混淆基于行为的检测机制。  

3. **动态 API 解析**  
   在运行时动态解析 API 函数，以避免静态检测。  

4. **解除 `ntdll.dll` Hook**  
   恢复原始、未 Hook 的 `ntdll.dll`，以绕过用户模式 Hook。  

5. **加密 Shellcode 文件加载（`shellcode.bin`）**  
   在运行时加载并解密加密的 Shellcode 文件（`shellcode.bin`），以避免检测。  

6. **线程池执行**  
   使用线程池执行 Shellcode，以模仿合法的应用程序行为。  

7. **隐秘的内存分配**  
   以隐秘的方式为 Shellcode 分配内存，避免触发可疑模式导致的检测。  

---  

## 使用方法  

1. 使用您首选的方法生成原始 Shellcode 的 `.bin` 文件。  

2. 将文件重命名为 `input.bin`，然后运行 `xor.py`。这将生成一个名为 `output.bin` 的加密文件。  

3. 将 `output.bin` 重命名为 `shellcode.bin`，并将其放置在与可执行文件相同的目录中。  

4. 执行负载。  

## Shellcode Loader 绕过截图  

### 1. 360 Bypass  
![360 Bypass](https://github.com/Answerr/shellcode_loader_bypass/blob/main/images/360_bypass1.png)  

### 2. Defender Test  
![Defender Test](https://github.com/Answerr/shellcode_loader_bypass/blob/main/images/Defender_test.png)  

### 3. Huorong Bypass  
![Huorong Bypass](https://github.com/Answerr/shellcode_loader_bypass/blob/main/images/huorong_bypass1.png)  

### 4. Tencent Bypass  
![Tencent Bypass](https://github.com/Answerr/shellcode_loader_bypass/blob/main/images/tencent_bypass1.png)

**总结**  
`test.cpp`：可以绕过腾讯、火绒和 Defender，但由于添加了针对 RuntimeBroker.exe 的远程注入功能，无法绕过 360。  

`bypass1.cpp`：可以绕过腾讯、火绒和 360，但无法绕过 Defender。  

> **免责声明：**  
> 此仓库仅供教育和研究用途。此处展示的技术不应用于恶意目的。请始终确保遵守适用的法律法规。  

---  

> **Disclaimer:**  
> This repository is for educational and research purposes only. The techniques demonstrated here should not be used for malicious purposes. Always ensure compliance with applicable laws and regulations.

---
