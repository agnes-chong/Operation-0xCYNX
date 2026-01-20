# m1r4g3 - The Silent Watcher (CTF Write-up)

**Category:** Reverse Engineering    
<img width="622" height="891" alt="image" src="https://github.com/user-attachments/assets/2faafcef-ec18-4f90-93eb-acfcc5c758a5" />

## Challenge Description
> After the CYNX breach, a susy PID was found running for an unusually long time, no persistence, no outbound traffic, nothing...
> What was it doing?
> maybe the OnyX operator was just dumb enough to leave it running... or maybe it’s playing us.

**Provided Files:**
* `m1r4g3_logger.exe`: The malware sample.
* `captured_logs.txt`: An encrypted log file containing a long hex string.
<img width="1185" height="308" alt="image" src="https://github.com/user-attachments/assets/2b190351-8a4a-4208-b0c9-f0679f154173" />

---

## 1. Initial Reconnaissance
We started by inspecting the files. Running `file` on the executable confirmed it is a PE32+ executable (Windows 64-bit).

Checking the `captured_logs.txt` file revealed unreadable hexadecimal data:
<img width="1919" height="472" alt="image" src="https://github.com/user-attachments/assets/5eff4629-f103-4b5c-ad0a-45382ceb335d" />
This confirms the malware captures data (likely keystrokes) and encrypts it locally rather than sending it out. Our goal is to reverse the encryption logic to decrypt this file.

---

## 2. Static Analysis (Ghidra)

We opened `m1r4g3_logger.exe` in **Ghidra** to analyze the control flow.
<img width="1919" height="1015" alt="image" src="https://github.com/user-attachments/assets/bffcec77-0a50-4d43-9caf-13caf0ec8a6f" />

### Locating the Encryption Routine
Searching for the string `"captured_logs.txt"` led us to a function named `encrypt_and_save_file`. Inside, there is a call to `process_buffer`, which handles the encryption logic.

The encryption process relies on two custom functions:
1.  **`init_cipher`**: Initializes the state using a key and some constants (`0xdeadbeef`, `0xcafebabe`, `0x13371337`, `0xbadf00d`). It mixes the state using a loop reminiscent of the **ChaCha20** stream cipher.
2.  **`process_byte` / `gen_stream`**: Generates a keystream using XOR, Addition, and Bitwise Rotation (`rol32`), then XORs it with the input data.

### Finding the Key
The most critical part was identifying the key passed to `init_cipher`. In `WinMain`, the malware calls a function `extract_device_fp` before starting the logger.

```c
// Decompiled logic of extract_device_fp
void extract_device_fp(longlong param_1) {
    byte local_28[] = { 
        0x62, 0x37, 0x3c, 0x38, 0x6e, 0x5d, 0x3b, 0x34, 
        0x39, 0x2d, 0x35, 0x36, 0x27, 0x36, 0x2b, 0x3b, 
        0x3c, 0x6e, 0x62, 0x67 
    };

    // The key is generated dynamically
    for (int i = 0; i < 20; i++) {
        final_key[i] = local_28[i] ^ 0x6b;
    }
}

```
The key is not hardcoded as a string. Instead, it is generated at runtime by XORing a specific byte array with 0x6b. This generates a "Device Fingerprint" that serves as the encryption key.

### 3. Solution Script
We wrote a Python script to replicate the malware's key generation and stream cipher logic.

```
import struct

def rol32(val, r_bits):
    return ((val << r_bits) & 0xFFFFFFFF) | ((val & 0xFFFFFFFF) >> (32 - r_bits))

def get_malware_key():
    # Raw bytes from extract_device_fp
    raw = [0x62, 0x37, 0x3c, 0x38, 0x6e, 0x5d, 0x3b, 0x34, 
           0x39, 0x2d, 0x35, 0x36, 0x27, 0x36, 0x2b, 0x3b, 
           0x3c, 0x6e, 0x62, 0x67]
    return bytearray([b ^ 0x6b for b in raw])

def solve():
    key = get_malware_key()
    
    # Initialize Cipher State (Replicating init_cipher)
    state = [0] * 10
    state[0] = 0xdeadbeef; state[1] = 0xcafebabe
    state[2] = 0x13371337; state[3] = 0xbadf00d
    
    # Key Injection
    for i in range(len(key)):
        idx = i & 3
        state[idx] = (state[idx] ^ (key[i] << ((i & 3) * 8))) & 0xFFFFFFFF
        state[idx] = rol32(state[idx], 7)

    # Mixing Loop
    MAGIC = 0x9e3779b9
    for _ in range(8):
        for i in range(4):
            state[i] = state[i] ^ state[(i + 1) & 3]
            state[i] = (state[i] + MAGIC) & 0xFFFFFFFF
            state[i] = rol32(state[i], 13)

    state[4] = 0; state[9] = 0x10; # Counter & Index

    # Decrypt
    hex_data = "2B9A406A3F369648..." # (Truncated for readability)
    encrypted_bytes = bytes.fromhex(hex_data)
    output = []
    
    # Stream Gen & XOR
    for b in encrypted_bytes:
        if state[9] > 15:
            # Generate new block (gen_stream logic)
            temp = [state[i] ^ state[4] for i in range(4)]
            for _ in range(20):
                temp[0] = (temp[0] + temp[1]) & 0xFFFFFFFF
                temp[3] = rol32(temp[3] ^ temp[0], 16)
                temp[2] = (temp[2] + temp[3]) & 0xFFFFFFFF
                temp[1] = rol32(temp[1] ^ temp[2], 12)
                temp[0] = (temp[0] + temp[1]) & 0xFFFFFFFF
                temp[3] = rol32(temp[3] ^ temp[0], 8)
                temp[2] = (temp[2] + temp[3]) & 0xFFFFFFFF
                temp[1] = rol32(temp[1] ^ temp[2], 7)
            
            stream_buf = bytearray()
            for i in range(4):
                stream_buf.extend(struct.pack("<I", (temp[i] + state[i]) & 0xFFFFFFFF))
            
            state[4] = (state[4] + 1) & 0xFFFFFFFF
            state[9] = 0
            
        k = stream_buf[state[9]]
        output.append(chr(b ^ k))
        state[9] += 1

    print("".join(output))

if __name__ == "__main__":
    solve()
```
### 4. Flag
Running the solver decrypted the PowerShell history log within the same directory as the .exe file:
<img width="1323" height="949" alt="image" src="https://github.com/user-attachments/assets/41ad4443-38e0-45f3-8bda-6ad0007971d4" />
Flag: ```CYNX{w45_0nyx_m1r4g3_0p3r470r_h3r3_?_$ur3_HE_WASSSS}```
