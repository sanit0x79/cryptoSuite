from typing import Tuple
import customtkinter
import tkinter as tk
from features.frequencyAnalysis import frequencyAnalysis
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
import os

class buttonFrame(customtkinter.CTkFrame):
    def __init__(self, master, title):
        super().__init__(master)
        self.title = title

        self.menuOption1 = customtkinter.CTkButton(self, text="Frequency Analysis", command=self.master.openFrequencyAnalysisWindow)
        self.menuOption1.grid(row=1, column=0, padx=5, pady=5)

        self.menuOption2 = customtkinter.CTkButton(self, text="RSA Encryption", command=self.master.openRSAEncryptionWindow)
        self.menuOption2.grid(row=2, column=0, padx=5, pady=5)

        self.menuOption3 = customtkinter.CTkButton(self, text="AES Encryption", command=self.master.openAESEncryptionWindow)
        self.menuOption3.grid(row=3, column=0, padx=5, pady=5)

        self.title = customtkinter.CTkLabel(self, text=self.title, fg_color="gray30", corner_radius=8)
        self.title.grid(row=0, column=0, padx=5, pady=5)

class newTopLevelWindow(customtkinter.CTkToplevel):
    def __init__(self, master, title, content):
        super().__init__(master)
        self.geometry("1000x500")
        self.title(title)
        self.iconbitmap("features/media/logicleap_transparent.ico")
        self.grid_rowconfigure((5,0), weight=1)

        self.content = customtkinter.CTkLabel(self, text=content)
        self.content.grid(row=0, column=0)

class userInterface(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.title("CryptoSuite")
        self.geometry("1000x500")
        self.grid_rowconfigure((1,0), weight=0)
        self.grid_columnconfigure((1, 0), weight=0)
        self.iconbitmap("features/media/logicleap_transparent.ico")

        self.buttonFrame = buttonFrame(self, title="Features")
        self.buttonFrame.grid(row=0, column=0, padx=0, pady=0)

    def openFrequencyAnalysisWindow(self):
        if hasattr(self, "frequencyWindow") and self.frequencyWindow.winfo_exists():
            self.frequencyWindow.focus()
        else:
            self.frequencyWindow = newTopLevelWindow(self, "Frequency Analysis", "Frequency Analysis Content")

            self.cipherTextBox = customtkinter.CTkTextbox(self.frequencyWindow, width=200, height=350)
            self.cipherTextBox.insert("0.0", "Enter Ciphertext Here")
            self.cipherTextBox.grid(row=0, column=0, padx=5, pady=5)

            self.analyzeButton = customtkinter.CTkButton(self.frequencyWindow, text="Analyze", command=self.doFrequencyAnalysis)
            self.analyzeButton.grid(row=1, column=0, padx=5, pady=5)

            self.plainTextBox = customtkinter.CTkTextbox(self.frequencyWindow, width=200, height=350)
            self.plainTextBox.grid(row=0, column=1, padx=5, pady=5)

    def doFrequencyAnalysis(self):
        ciphertext = self.cipherTextBox.get("1.0", "end-1c")
        frequencies = frequencyAnalysis(ciphertext)
        formatted_output = "Frequency Analysis:\n"
        for char, (count, percentage) in frequencies.items():
            formatted_output += f"'{char}': {count} times, {percentage:.2f}%\n"
        self.plainTextBox.delete("1.0", "end")
        self.plainTextBox.insert("1.0", formatted_output)

    def openRSAEncryptionWindow(self):
        if hasattr(self, "rsaWindow") and self.rsaWindow.winfo_exists():
            self.rsaWindow.focus()
        else:
            self.rsaWindow = newTopLevelWindow(self, "RSA Encryption", "RSA Encryption Content")

            self.messageTextBox = customtkinter.CTkTextbox(self.rsaWindow, width=200, height=150)
            self.messageTextBox.insert("0.0", "Enter Message Here")
            self.messageTextBox.grid(row=0, column=0, padx=5, pady=5)

            self.publicKeyTextBox = customtkinter.CTkTextbox(self.rsaWindow, width=200, height=100)
            self.publicKeyTextBox.insert("0.0", "Enter Public Key")
            self.publicKeyTextBox.grid(row=1, column=0, padx=5, pady=5)

            self.privateKeyTextBox = customtkinter.CTkTextbox(self.rsaWindow, width=200, height=100)
            self.privateKeyTextBox.insert("0.0", "Enter Private Key")
            self.privateKeyTextBox.grid(row=2, column=0, padx=5, pady=5)

            self.encryptButton = customtkinter.CTkButton(self.rsaWindow, text="Encrypt", command=self.doRSAEncryption)
            self.encryptButton.grid(row=3, column=0, padx=5, pady=5)

            self.decryptButton = customtkinter.CTkButton(self.rsaWindow, text="Decrypt", command=self.doRSADecryption)
            self.decryptButton.grid(row=4, column=0, padx=5, pady=5)

            self.resultTextBox = customtkinter.CTkTextbox(self.rsaWindow, width=200, height=150)
            self.resultTextBox.grid(row=0, column=1, padx=5, pady=5, rowspan=5)

    def doRSAEncryption(self):
        message = self.messageTextBox.get("1.0", "end-1c")
        public_key_data = self.publicKeyTextBox.get("1.0", "end-1c")
        public_key = RSA.import_key(public_key_data)
        cipher = PKCS1_OAEP.new(public_key)
        encrypted_message = cipher.encrypt(message.encode())
        encoded_message = b64encode(encrypted_message).decode()
        self.resultTextBox.delete("1.0", "end")
        self.resultTextBox.insert("1.0", encoded_message)

    def doRSADecryption(self):
        encrypted_message = self.messageTextBox.get("1.0", "end-1c")
        private_key_data = self.privateKeyTextBox.get("1.0", "end-1c")
        private_key = RSA.import_key(private_key_data)
        cipher = PKCS1_OAEP.new(private_key)
        decrypted_message = cipher.decrypt(b64decode(encrypted_message))
        self.resultTextBox.delete("1.0", "end")
        self.resultTextBox.insert("1.0", decrypted_message.decode())

    def openAESEncryptionWindow(self):
        if hasattr(self, "aesWindow") and self.aesWindow.winfo_exists():
            self.aesWindow.focus()
        else:
            self.aesWindow = newTopLevelWindow(self, "AES Encryption", "AES Encryption Content")

            self.messageTextBox = customtkinter.CTkTextbox(self.aesWindow, width=200, height=150)
            self.messageTextBox.insert("0.0", "Enter Message Here")
            self.messageTextBox.grid(row=0, column=0, padx=5, pady=5)

            self.keyTextBox = customtkinter.CTkTextbox(self.aesWindow, width=200, height=100)
            self.keyTextBox.insert("0.0", "Enter AES Key (16, 24, or 32 bytes)")
            self.keyTextBox.grid(row=1, column=0, padx=5, pady=5)

            self.encryptButton = customtkinter.CTkButton(self.aesWindow, text="Encrypt", command=self.doAESEncryption)
            self.encryptButton.grid(row=2, column=0, padx=5, pady=5)

            self.decryptButton = customtkinter.CTkButton(self.aesWindow, text="Decrypt", command=self.doAESDecryption)
            self.decryptButton.grid(row=3, column=0, padx=5, pady=5)

            self.resultTextBox = customtkinter.CTkTextbox(self.aesWindow, width=200, height=150)
            self.resultTextBox.grid(row=0, column=1, padx=5, pady=5, rowspan=4)

    def doAESEncryption(self):
        message = self.messageTextBox.get("1.0", "end-1c").encode()
        key = self.keyTextBox.get("1.0", "end-1c").encode()
        cipher = AES.new(key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(message, AES.block_size))
        encoded_cipher = b64encode(cipher.iv + ciphertext).decode()
        self.resultTextBox.delete("1.0", "end")
        self.resultTextBox.insert("1.0", encoded_cipher)

    def doAESDecryption(self):
        encrypted_message = self.messageTextBox.get("1.0", "end-1c")
        key = self.keyTextBox.get("1.0", "end-1c").encode()
        encrypted_data = b64decode(encrypted_message)
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        self.resultTextBox.delete("1.0", "end")
        self.resultTextBox.insert("1.0", plaintext.decode())

app = userInterface()
app.mainloop()
