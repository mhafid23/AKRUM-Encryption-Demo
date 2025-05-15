# AKRUM File Encryption Demo (v2)

This is an enhanced prototype demonstrating AKRUM's file encryption system using Cellular Automata-based entropy, now with full **filename preservation** for accurate decryption and restoration.

## Features

- Drag-and-drop any file type (image, text, video, PDF, etc.)
- Encrypts files using AKRUM's entropy engine + Fernet (AES)
- Generates encryption key and downloadable encrypted package
- Automatically restores the original filename on decryption

## How to Run Locally

1. Install required packages:

```bash
pip install -r requirements.txt
```

2. Run the app:

```bash
streamlit run akrum_file_encryption_demo_v2.py
```

## Files

- `akrum_file_encryption_demo_v2.py`: Main demo app
- `requirements.txt`: Dependencies for encryption and UI

---

**AKRUM** is protected under US Patent No. 10,078,492 B2. This demo is for illustrative purposes only.