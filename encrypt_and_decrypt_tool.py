import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
import os

KEY_FILE = "secret.key"


def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(key)
    return key


def load_key():
    if not os.path.exists(KEY_FILE):
        return generate_key()
    with open(KEY_FILE, 'rb') as key_file:
        return key_file.read()


# Load or generate the key for encryption and decryption
key = load_key()
cipher_suite = Fernet(key)


def encrypt_text(plain_text):
    encrypted_text = cipher_suite.encrypt(plain_text.encode())
    return encrypted_text.decode()


def decrypt_text(encrypted_text):
    try:
        decrypted_text = cipher_suite.decrypt(encrypted_text.encode())
        return decrypted_text.decode()
    except Exception as e:
        return f"Decryption failed: {str(e)}"


def copy_to_clipboard(text):
    root.clipboard_clear()
    root.clipboard_append(text)
    messagebox.showinfo("Copied", "Text has been copied to clipboard")


def encrypt_action():
    plain_text = text_input.get("1.0", "end").strip()
    if plain_text:
        encrypted_text = encrypt_text(plain_text)
        result_box.config(state='normal')
        result_box.delete("1.0", "end")
        result_box.insert("1.0", encrypted_text)
        result_box.config(state='disabled')
    else:
        messagebox.showerror("Error", "Please enter text to encrypt.")


def decrypt_action():
    encrypted_text = text_input.get("1.0", "end").strip()
    if encrypted_text:
        decrypted_text = decrypt_text(encrypted_text)
        result_box.config(state='normal')
        result_box.delete("1.0", "end")
        result_box.insert("1.0", decrypted_text)
        result_box.config(state='disabled')
    else:
        messagebox.showerror("Error", "Please enter text to decrypt.")


def copy_result():
    result_text = result_box.get("1.0", "end").strip()
    if result_text:
        copy_to_clipboard(result_text)
    else:
        messagebox.showerror("Error", "No text to copy.")


# Main GUI
root = tk.Tk()
root.title("Encrypt and Decrypt Text")

# Input Text
tk.Label(root, text="Enter Text:").pack(pady=5)
text_input = tk.Text(root, wrap='word', width=50, height=5)
text_input.pack(pady=5)

# Action Buttons
button_frame = tk.Frame(root)
button_frame.pack(pady=10)

encrypt_button = tk.Button(button_frame, text="Encrypt", command=encrypt_action, width=10)
encrypt_button.grid(row=0, column=0, padx=5)

decrypt_button = tk.Button(button_frame, text="Decrypt", command=decrypt_action, width=10)
decrypt_button.grid(row=0, column=1, padx=5)

# Result Box
tk.Label(root, text="Result:").pack(pady=5)
result_box = tk.Text(root, wrap='word', width=50, height=5, state='disabled')
result_box.pack(pady=5)

# Copy Button
copy_button = tk.Button(root, text="Copy Result", command=copy_result)
copy_button.pack(pady=10)

root.mainloop()
