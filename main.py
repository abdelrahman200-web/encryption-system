import tkinter as tk
from tkinter import ttk, messagebox
from DES import text_to_bin, split_and_pad_message, des_encrypt, bin_to_hex, hex_to_bin, des_decrypt, bin_to_text
from AES import aes_256_encrypt_ecb, aes_256_decrypt_ecb
from test import encrypt_RC4, decrypt_RC4, encrypt_RSA, decrypt_RSA
import hashlib
    #اضافي بعض لاشكال الي بينه في GUI

BG_COLOR="#0f172a"      # خلفية داكنة
FG_COLOR="#f1f5f9"      # كتابة فاتحة
BTN_COLOR="#2563eb"     # أزرار زرقاء
ENTRY_COLOR="#1e293b"   # لون الحقول
ACCENT_COLOR="#22d3ee"  # لون تزييني

FONT_MAIN=("Segoe UI", 11)
FONT_TITLE=("Segoe UI", 14, "bold")

class CryptoGUI:
    #اضافي بعض لاشكال الي بينه في GUI

    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ Secure Encryption GUI")
        self.root.geometry("850x650")
        self.root.configure(bg=BG_COLOR)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background=BG_COLOR, borderwidth=0)
        style.configure("TNotebook.Tab", background=ENTRY_COLOR, foreground=FG_COLOR, padding=10, font=FONT_MAIN)
        style.map("TNotebook.Tab", background=[("selected", BTN_COLOR)])
    #اضافي بعض لاشكال الي بينه في GUI

        tab_control = ttk.Notebook(root)
        self.rc4_tab = tk.Frame(tab_control, bg=BG_COLOR)
        self.rsa_tab = tk.Frame(tab_control, bg=BG_COLOR)
        self.des_tab = tk.Frame(tab_control, bg=BG_COLOR)
        self.aes_tab = tk.Frame(tab_control, bg=BG_COLOR)
        self.hash_tab = tk.Frame(tab_control, bg=BG_COLOR)

        tab_control.add(self.rc4_tab, text='🔑 RC4')
        tab_control.add(self.rsa_tab, text='🔐 RSA')
        tab_control.add(self.des_tab, text='🧮 DES')
        tab_control.add(self.aes_tab, text='🧊 AES')
        tab_control.add(self.hash_tab, text='🔍 Hashing')
        tab_control.pack(expand=1, fill="both")

        self.setup_rc4()
        self.setup_rsa()
        self.setup_des()
        self.setup_aes()
        self.setup_hash()
    #اضافي بعض لاشكال الي بينه في GUI

    def styled_label(self, parent, text):
        return tk.Label(parent, text=text, bg=BG_COLOR, fg=ACCENT_COLOR, font=FONT_TITLE)

    def styled_entry(self, parent, width=50):
        return tk.Entry(parent, font=FONT_MAIN, bg=ENTRY_COLOR, fg=FG_COLOR, insertbackground=FG_COLOR, width=width, relief="groove", bd=2)

    def styled_button(self, parent, text, command):
        return tk.Button(parent, text=text, command=command, font=FONT_MAIN, bg=BTN_COLOR, fg="white", activebackground=ACCENT_COLOR, relief="flat", padx=10, pady=5, cursor="hand2")

    def styled_text(self, parent):
        return tk.Text(parent, font=FONT_MAIN, bg=ENTRY_COLOR, fg=FG_COLOR, height=8, width=85, relief="flat", wrap="word")

    def setup_rc4(self):
        self.styled_label(self.rc4_tab, "Message:").pack(pady=5)
        self.rc4_msg = self.styled_entry(self.rc4_tab)
        self.rc4_msg.pack()

        self.styled_label(self.rc4_tab, "Seed (digits):").pack(pady=5)
        self.rc4_seed = self.styled_entry(self.rc4_tab)
        self.rc4_seed.pack()

        self.rc4_output = self.styled_text(self.rc4_tab)
        self.rc4_output.pack(pady=10)

        self.styled_button(self.rc4_tab, "Encrypt + Decrypt", self.rc4_process).pack()

    def rc4_process(self):
        try:
            msg = str(self.rc4_msg.get())
            seed = int(self.rc4_seed.get())
            cipher, key = encrypt_RC4(msg, seed)
            decrypted = decrypt_RC4(cipher, key)
            self.rc4_output.delete(1.0, tk.END)
            self.rc4_output.insert(tk.END, f"Cipher: {''.join(hex(i)for i in cipher)}\nDecrypted: {decrypted}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def setup_rsa(self):
        self.styled_label(self.rsa_tab, "Prime p:").pack(pady=5)
        self.rsa_p = self.styled_entry(self.rsa_tab)
        self.rsa_p.pack()

        self.styled_label(self.rsa_tab, "Prime q:").pack(pady=5)
        self.rsa_q = self.styled_entry(self.rsa_tab)
        self.rsa_q.pack()

        self.styled_label(self.rsa_tab, "Message:").pack(pady=5)
        self.rsa_msg = self.styled_entry(self.rsa_tab)
        self.rsa_msg.pack()

        self.rsa_output = self.styled_text(self.rsa_tab)
        self.rsa_output.pack(pady=10)

        self.styled_button(self.rsa_tab, "Encrypt + Decrypt", self.rsa_process).pack()

    def rsa_process(self):
        try:
            p = int(self.rsa_p.get())
            q = int(self.rsa_q.get())
            message = self.rsa_msg.get()
            cipher, pub, priv = encrypt_RSA(p, q, message)
            decrypted = decrypt_RSA(cipher, priv)
            self.rsa_output.delete(1.0, tk.END)
            self.rsa_output.insert(tk.END, f"Cipher: {cipher}\nDecrypted: {decrypted}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def setup_des(self):
        self.styled_label(self.des_tab, "Key (8 ASCII chars):").pack(pady=5)
        self.des_key = self.styled_entry(self.des_tab)
        self.des_key.pack()

        self.styled_label(self.des_tab, "Message:").pack(pady=5)
        self.des_msg = self.styled_entry(self.des_tab, width=60)
        self.des_msg.pack()

        self.des_output = self.styled_text(self.des_tab)
        self.des_output.pack(pady=10)

        self.styled_button(self.des_tab, "Encrypt + Decrypt", self.des_process).pack()

    def des_process(self):
        try:
            key = text_to_bin(self.des_key.get())
            blocks = split_and_pad_message(self.des_msg.get())
            cipher = [bin_to_hex(des_encrypt(text_to_bin(block), key)) for block in blocks]
            decrypted = [bin_to_text(des_decrypt(hex_to_bin(c), key)) for c in cipher]
            plain = ''.join(decrypted).rstrip()
            self.des_output.delete(1.0, tk.END)
            self.des_output.insert(tk.END, f"Cipher: {''.join(cipher)}\nDecrypted: {plain}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def setup_aes(self):
        self.styled_label(self.aes_tab, "Key (32 bytes):").pack(pady=5)
        self.aes_key = self.styled_entry(self.aes_tab, width=60)
        self.aes_key.pack()

        self.styled_label(self.aes_tab, "Message:").pack(pady=5)
        self.aes_msg = self.styled_entry(self.aes_tab, width=60)
        self.aes_msg.pack()

        self.aes_output = self.styled_text(self.aes_tab)
        self.aes_output.pack(pady=10)

        self.styled_button(self.aes_tab, "Encrypt + Decrypt", self.aes_process).pack()

    def aes_process(self):
        try:
            key = self.aes_key.get().encode('ascii')
            msg = self.aes_msg.get().encode('ascii')
            ciphertext = aes_256_encrypt_ecb(msg, key)
            decrypted = aes_256_decrypt_ecb(ciphertext, key)
            self.aes_output.delete(1.0, tk.END)
            self.aes_output.insert(tk.END, f"Cipher (hex): {ciphertext.hex()}\nDecrypted: {decrypted.decode('ascii')}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
     # ===== Hash Tab all edid gado and zide =====
    def setup_hash(self):
        self.styled_label(self.hash_tab,"Enter Text:").pack(pady=5)
        self.hash_entry=self.styled_entry(self.hash_tab,width=60)
        self.hash_entry.pack()
        self.styled_label(self.hash_tab,"Choose Algorithm:").pack(pady=5)
        self.algo_choice = ttk.Combobox(self.hash_tab, values=["md5","sha1","sha256","sha512"],font=FONT_MAIN)
        self.algo_choice.current(0)
        self.algo_choice.pack()
        self.styled_button(self.hash_tab,"Generate Hash",self.generate_hash).pack(pady=5)
        self.result_text = self.styled_text(self.hash_tab)
        self.result_text.pack(pady=10)
    def generate_hash(self):
        text=self.hash_entry.get()
        algo=self.algo_choice.get()
        try:
            h=getattr(hashlib, algo)()
            h.update(text.encode())
            result = h.hexdigest()
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert(tk.END, f"{algo.upper()}:\n{result}")
        except Exception as e:
            self.result_text.insert(tk.END, f"Error: {str(e)}")
            
if __name__ == '__main__':
    root = tk.Tk()
    app = CryptoGUI(root)
    root.mainloop()
