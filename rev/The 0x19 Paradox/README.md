# 🕰️ The 0x19 Paradox — Reverse Engineering CTF Write-up
<img width="624" height="567" alt="image" src="https://github.com/user-attachments/assets/4ca6f4a7-c0ba-4fc8-9ea3-e3f442b569c6" />

## Challenge Overview
**Category:** Reverse Engineering  
**Goal:** Recover the hidden flag from a Linux ELF binary.

When the binary is executed, it prints different messages depending on the current date. Most of the time, nothing interesting happens. The challenge is to figure out **when** and **how** the flag is revealed, and then recover it without waiting.

---

## Step 1: Initial Binary Analysis

After loading the binary into **Ghidra** and letting it auto-analyze, we inspect the `main()` function.
<img width="1919" height="1021" alt="image" src="https://github.com/user-attachments/assets/dc6d9947-0dd5-49d3-8179-3c4bc6404c4c" />

# Decompiled `main()`
<img width="606" height="775" alt="image" src="https://github.com/user-attachments/assets/1b3fb14d-8db6-435b-8b42-bd5853f17cb5" />

# Key Observation:
`0x11`(hex) = 17
`0x19`(hex) = 25

The flag is only decrypted and printed when the value returned `byget_day()` equals **25**.
This is the core idea behind the challenge name: **The 0x19 Paradox**.

## Step 2: Understanding `get_day()`
<img width="608" height="457" alt="image" src="https://github.com/user-attachments/assets/488a26ec-ba4a-4ed0-bb85-7c34aa5c7cf3" />

# What this means:
`time()` get the current system time
`localtime()` converts it into atmstructure
`tm_mday` is the **day o**

So:
The program checks today's date
The flag is revealed only on th
Waiting is unnecessary. We can extract the flag.

## Step 3: Analyzing `decrypt_flag()`
<img width="702" height="314" alt="image" src="https://github.com/user-attachments/assets/d367c660-4072-4fbe-a0e4-3753db7c1d58" />
Interprate:
'enc_flag' i_16-byte encrypted array
Each byte is XORed with '0x49'
The result is a null terminology.

## Step 4: Extracting the
From Ghidra, the `enc_flag` bytes ar_
<img width="1107" height="223" alt="image" src="https://github.com/user-attachments/assets/e5076f1c-a13b-4f23-b65f-31ffb84224f8" />
We XOR each byte with `0x49`.
```
enc = [
    0x19, 0x05, 0x08, 0x02,
    0x32, 0x2e, 0x3f, 0x3b,
    0x16, 0x3f, 0x16, 0x3a,
    0x27, 0x31, 0x3b, 0x34
]

stage1 = ''.join(chr(b ^ 0x49) for b in enc)
print(stage1)
```
## Output: 
```PLAK{gvr_v_snxr}```
This looks like a flag format, b
We apply ROT13 to the entire string.

### Flag
```CYNX{tie_i_fake}```

## Summary of Techniques Used:
- Static analysis with Ghidra
- Identifying time-based logic
- XOR decryption
- ROT13 decoding
- Avoiding time-locked execution by reversing logic
