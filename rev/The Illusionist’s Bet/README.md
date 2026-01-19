# 🎰 GambleCTF – The Illusionist’s Bet (Reverse Engineering)
<img width="621" height="800" alt="image" src="https://github.com/user-attachments/assets/ba2ce157-fc19-4dbb-accf-72723e0b5b86" />

---

## 🧩 Challenge Story

> Between the grey smoke and brown liquor lies a casino, the perfect place for a mirage to blend in.  
> He floats between the smoke and flashes along the bright lights.  
> Just as you arrive, you realize he has disappeared.  
> Not without a trace, however, as you have his winning records.  
> With this, you may be able to track his next location.

You are given:
- A Linux ELF binary (`GambleCTF`)
- A text file: **`M1r4g3_winnings_summary.txt`**

The goal is to recover the illusionist’s destination — the flag.

---

## 📂 Provided File: `M1r4g3_winnings_summary.txt`

This file looks like harmless casino output… but it is **the core clue**.
<img width="1009" height="941" alt="image" src="https://github.com/user-attachments/assets/8fe02696-eba1-4d1c-a024-f97361bfc2f6" />

Key observations:

- Total spins: **200**
- Final credits: **3480**
- Complete spin-by-spin history
- At the very bottom:

That last line is **not random**.  
It is **derived from the player name after cryptographic transformations**.

---

## 🔍 Binary Recon Overview

Static analysis (Ghidra / IDA) reveals:
<img width="1919" height="1018" alt="image" src="https://github.com/user-attachments/assets/b8f3a943-30ec-432b-883e-aa60692a1464" />

Important functions:
- `main()`
- `get_player_name()`
- `evaluate()`
- `apply_crypto_operation()`
- `xor_with_key()`
- `rol_bits()`, `ror_bits()`
- `encrypted_name_to_string()`

Important globals:
- `char encrypted_name[50]`
- `char jackpot_key[?]`
- `CRYPTO_MAPPINGS[token][symbol]`

---

## 🧠 Critical Logic Discovery

### 1. Player Name Is the Seed

At startup:
- Your **player name** is copied into `encrypted_name`.
- This buffer is mutated during early spins.

### 2. Only the **First 10 Spins Matter**

Inside `evaluate()`:

```c
if (total_spins < 0xb) {
    apply_crypto_operation(result_type, winning_symbol);
}

```
➡️ While the summary shows **200 spins**, the code tells us that **only the first 10 spins mutate the `encrypted_name` buffer**, which ultimately encodes the flag.

This means the bulk of the spin history is **decoy data** to obscure the real transformation steps.

---

## 🔐 Understanding `apply_crypto_operation`

This function applies one of three transformations to the encrypted buffer depending on the result of each spin.

```c
void apply_crypto_operation(char *result_type, Symbol winning_symbol) {
    if (strcmp(result_type, "NO WIN") == 0) {
        xor_with_key(encrypted_name, jackpot_key);
    } else if (strcmp(result_type, "TWO MATCH") == 0) {
        ror_bits(encrypted_name, CRYPTO_MAPPINGS[active_token][winning_symbol]);
        strncpy(jackpot_key, "Dante", 6);
    } else if (strcmp(result_type, "THREE MATCH") == 0) {
        rol_bits(encrypted_name, CRYPTO_MAPPINGS[active_token][winning_symbol]);
        strncpy(jackpot_key, "Virgil", 7);
    }
}
```
| Outcome Type    | Operation              | Key Set To |
| --------------- | ---------------------- | ---------- |
| `"NO WIN"`      | XOR with `jackpot_key` | unchanged  |
| `"TWO MATCH"`   | ROR with symbol offset | `"Dante"`  |
| `"THREE MATCH"` | ROL with symbol offset | `"Virgil"` |

The rotation shift amount is pulled from:
```CRYPTO_MAPPINGS[active_token][symbol]```
For active_token = 0, the mappin_
```[CHERRY=0x07, LEMON=0x11, ORANGE=0x1B, PLUM=0x25, BELL=0x2F, STAR=0x39, SEVEN=0x30]```

## 🎰 Mapping the First 10 Spins
From the provided M1r4g3_winnings_summary.txt, we extract the first 10 spins:
| Spin | Outcome     | Symbol | Crypto Operation |
| ---- | ----------- | ------ | ---------------- |
| 1    | NO WIN      | -      | XOR with "Dante" |
| 2    | TWO MATCH   | CHERRY | ROR 0x07         |
| 3    | TWO MATCH   | LEMON  | ROR 0x11         |
| 4    | THREE MATCH | PLUM   | ROL 0x25         |
| 5    | TWO MATCH   | LEMON  | ROR 0x11         |
| 6    | NO WIN      | -      | XOR with "Dante" |
| 7    | TWO MATCH   | LEMON  | ROR 0x11         |
| 8    | NO WIN      | -      | XOR with "Dante" |
| 9    | TWO MATCH   | LEMON  | ROR 0x11         |
| 10   | THREE MATCH | LEMON  | ROL 0x11         |
So the final transformation pipeline applied to ```encrypted_name``` is:
```
XOR("Dante") 
→ ROR(0x07)
→ ROR(0x11)
→ ROL(0x25)
→ ROR(0x11)
→ XOR("Dante")
→ ROR(0x11)
→ XOR("Dante")
→ ROR(0x11)
→ ROL(0x11)
```
## 🔄 Final Encoding:encrypted_name_to_string
The transformed encrypted_nameis finally encoded:
```
output[out++] = BASE64[b & 0x3F];
output[out++] = BASE64[b >> 2];
```
This yields the line at the bottom
<img width="1382" height="74" alt="image" src="https://github.com/user-attachments/assets/04ca19c3-34ee-40a6-91cc-be314a6f9efc" />
Each byte becomes 2 printable characters , forming the final encoded version of the play

## 🛠 Solving It
To recover:

1. Decode the final

2. Apply the reverse of the 10 transformations (in reverse order):
  ROL ↔ ROR (invers
  XOR is symmetric

4. You now have the original player name → this is the flag.

Python script:
```
ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

ENCODED = "OjhoIyW1OTvLZWkp2NWlOjhI0d6eCgWVQUhYDAPjiYZmQUGxaGS0V1oqm5m5SkFxAgSkiYW15eg4Skycm5xs0t"

# ------------------ decode encrypted_name ------------------

def decode_custom(enc: str) -> bytearray:
    enc = enc.strip()
    if len(enc) % 2 != 0:
        raise ValueError("Encoded length must be even")

    out = bytearray()
    for i in range(0, len(enc), 2):
        a = ALPH.index(enc[i])       # b & 0x3f
        c = ALPH.index(enc[i + 1])   # b >> 2
        b = (c << 2) | (a & 0x3f)
        out.append(b & 0xff)
    return out

data = decode_custom(ENCODED)
print("[+] decoded encrypted_name bytes:", data.hex())

# ------------------ reverse crypto (first 10 spins) ------------------

# SYMBOL_NAME order from your Ghidra dump
SYMBOL_ORDER = ["CHERRY", "LEMON", "ORANGE", "PLUM", "BELL", "STAR", "SEVEN"]

# First 10 spins only (VERY IMPORTANT)
SPINS = [
    ("NO WIN", None),
    ("TWO MATCH", "CHERRY"),
    ("TWO MATCH", "LEMON"),
    ("THREE MATCH", "PLUM"),
    ("TWO MATCH", "LEMON"),
    ("NO WIN", None),
    ("TWO MATCH", "LEMON"),
    ("NO WIN", None),
    ("TWO MATCH", "LEMON"),
    ("THREE MATCH", "LEMON"),
]

# Convert symbol names to indices
name_to_idx = {n: i for i, n in enumerate(SYMBOL_ORDER)}
SPINS = [(r, None if s is None else name_to_idx[s]) for r, s in SPINS]

# Initial key (confirmed from Ghidra)
key = b"Jackpot"

# CRYPTO_MAPPINGS (you must paste the real table here)
CRYPTO_MAPPINGS = [
    # token 0
    [5, 7, 9, 11, 13, 17, 19],
    # token 1 (example – replace with real values)
    # [...]
]

def xor_with_key(buf, key):
    for i in range(len(buf)):
        buf[i] ^= key[i % len(key)]

def bits(buf):
    out = []
    for b in buf:
        for i in range(8):
            out.append((b >> (7 - i)) & 1)
    return out

def unbits(bits):
    out = bytearray(len(bits) // 8)
    for i in range(len(out)):
        b = 0
        for j in range(8):
            b |= bits[i * 8 + j] << (7 - j)
        out[i] = b
    return out

def rol(buf, n):
    n %= len(buf) * 8
    b = bits(buf)
    b = b[n:] + b[:n]
    buf[:] = unbits(b)

def ror(buf, n):
    n %= len(buf) * 8
    b = bits(buf)
    b = b[-n:] + b[:-n]
    buf[:] = unbits(b)

# brute-force active_token
for token in range(len(CRYPTO_MAPPINGS)):
    test = bytearray(data)
    k = key

    # reverse in reverse order
    for (res, sym) in reversed(SPINS):
        if res == "NO WIN":
            xor_with_key(test, k)
        elif res == "TWO MATCH":
            rol(test, CRYPTO_MAPPINGS[token][sym])
            k = b"Dante"
        elif res == "THREE MATCH":
            ror(test, CRYPTO_MAPPINGS[token][sym])
            k = b"Virgil"

    try:
        s = test.decode()
        if "CYNX{" in s:
            print("\n[+] FLAG FOUND:")
            print(s)
            break
    except:
        pass
```
Execute the Python script within the same directory as the challenge folder.
<img width="1468" height="65" alt="image" src="https://github.com/user-attachments/assets/2134632d-f717-46ed-9f31-0371c948964c" />
After getting te decoded ```encrypted_name``` bytes, reverse the transformations applied during the f, in the reverse order:

## 🏁 Expected Output
```CYNX{r3ad4bl3Ch@r4c7eR5}```
