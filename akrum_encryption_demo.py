
import streamlit as st
import numpy as np
import hashlib
import base64
from cryptography.fernet import Fernet

# Cellular Automata Randomness Generator (Rule 30)
def rule30(prev_row):
    row_len = len(prev_row)
    new_row = np.zeros_like(prev_row)
    for i in range(1, row_len - 1):
        left, center, right = prev_row[i - 1], prev_row[i], prev_row[i + 1]
        new_row[i] = left ^ (center or right)
    return new_row

def generate_ca_entropy(seed_index=30, steps=30, width=61):
    grid = np.zeros((steps, width), dtype=int)
    grid[0, seed_index] = 1
    for i in range(1, steps):
        grid[i] = rule30(grid[i - 1])
    return ''.join(str(bit) for bit in grid[-1])

# Derive Fernet-compatible key from CA entropy
def derive_fernet_key(binary_string):
    hashed = hashlib.sha256(binary_string.encode()).digest()
    return base64.urlsafe_b64encode(hashed)

# Streamlit Interface
st.set_page_config(page_title="AKRUM Encryption Demo", page_icon=":lock:", layout="centered")
st.title("AKRUM Encryption Demo")
st.write("Secure messaging simulation powered by AKRUM's CA-based entropy engine.")

message = st.text_input("Enter your message to encrypt:", "")
if st.button("Encrypt and Simulate Transmission") and message:
    entropy = generate_ca_entropy()
    fernet_key = derive_fernet_key(entropy)
    f = Fernet(fernet_key)
    
    encrypted_msg = f.encrypt(message.encode())
    decrypted_msg = f.decrypt(encrypted_msg).decode()

    st.success("Encryption successful. Here's what happened:")
    st.code(f"Encrypted: {encrypted_msg.decode()}", language="text")
    st.markdown("Message transmitted securely...")

    st.info("At the receiver end:")
    st.code(f"Decrypted: {decrypted_msg}", language="text")
else:
    st.caption("Enter a message above and press the button to see encryption in action.")
