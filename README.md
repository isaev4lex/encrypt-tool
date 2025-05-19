# 🔐 Encrypt Tool

A powerful cross-platform CLI tool for encrypting and decrypting files and folders using AES-256-CBC (OpenSSL). Supports both Windows and Linux.

---

## 🛠 Features

- 🔒 Encrypt and decrypt single files
- 📁 Recursively process entire folders
- ✅ Check if a file or folder is encrypted
- 📎 Uses secure AES-256-CBC algorithm
- 🧠 Stores IV inside encrypted file (automatically)

---

## 🚀 Quick Start

### 🔧 Compile (Linux)

```bash
sudo apt install g++ libssl-dev
g++ src/main.cpp src/CryptoTool.cpp -o bin/linux_amd64/encrypt-tool -lssl -lcrypto -std=c++17
```

### 🧑‍💻 Build (Windows)

Open `Visual Studio > encrypt-tool.sln`  
Click **Build → Build Solution** or press `Ctrl+Shift+B`

---

## 📦 Usage Examples

### 🔒 Encryption

```bash
./encrypt-tool --encrypt-file secret.txt --key mypassword
./encrypt-tool --encrypt-folder ./data --key mypassword
```

### 🔓 Decryption

```bash
./encrypt-tool --decrypt-file secret.txt --key mypassword
./encrypt-tool --decrypt-folder ./data --key mypassword
```

### 🔍 Check encryption status

```bash
./encrypt-tool --is-encrypted-file secret.txt
./encrypt-tool --is-encrypted-folder ./data
```

---

## ⚠️ Behavior Notes

- When encrypting a folder:
  - If **all files are already encrypted** → throws error
  - If **some files are encrypted** → throws error (you must decrypt all first)
- If `--key` is missing, the tool will refuse to encrypt/decrypt

---

## 🔐 Encryption Details

- **Algorithm:** AES-256-CBC (OpenSSL)
- **IV:** Randomly generated for each encryption
- **Header format:** `CTOOLENC` + IV + encrypted data

---

## 📁 Project Structure

```
encrypt-tool/
├── src/                # Source code
│   ├── main.cpp
│   ├── CryptoTool.cpp/h
│   └── allinclude.h
├── bin/                # Compiled binaries (Linux, Windows)
│   ├── linux_amd64/
│   └── win_x64/
├── Visual Studio/      # Visual Studio solution and project files
├── .gitignore
└── README.md
```

---

## 🧪 Dependencies

- [OpenSSL](https://www.openssl.org/) (libssl, libcrypto)
- C++17
- g++ (Linux) or MSVC (Windows)

