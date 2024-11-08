import customtkinter
import tkinter as tk
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256, SHA512, MD5
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

class buttonFrame(customtkinter.CTkFrame):
    def __init__(self, master, title):
        super().__init__(master)
        self.title = title

        self.menuOption1 = customtkinter.CTkButton(self, text="Frequency Analysis", command=master.openFrequencyAnalysisWindow)
        self.menuOption1.grid(row=1, column=0, padx=5, pady=5, sticky="ew")

        self.menuOption2 = customtkinter.CTkButton(self, text="RSA Encryption", command=master.openRSAEncryptionWindow)
        self.menuOption2.grid(row=2, column=0, padx=5, pady=5, sticky="ew")

        self.menuOption3 = customtkinter.CTkButton(self, text="AES Encryption", command=master.openAESEncryptionWindow)
        self.menuOption3.grid(row=3, column=0, padx=5, pady=5, sticky="ew")

        self.menuOption4 = customtkinter.CTkButton(self, text="Hashing", command=master.openHashingWindow)
        self.menuOption4.grid(row=4, column=0, padx=5, pady=5, sticky="ew")

        self.menuOption5 = customtkinter.CTkButton(self, text="Encoding/Decoding", command=master.openEncodingWindow)
        self.menuOption5.grid(row=5, column=0, padx=5, pady=5, sticky="ew")

        self.menuOption6 = customtkinter.CTkButton(self, text="Random Key Generation", command=master.openKeyGenerationWindow)
        self.menuOption6.grid(row=6, column=0, padx=5, pady=5, sticky="ew")

        self.menuOption7 = customtkinter.CTkButton(self, text="Text to Hex/Binary", command=master.openConversionWindow)
        self.menuOption7.grid(row=7, column=0, padx=5, pady=5, sticky="ew")

        self.title = customtkinter.CTkLabel(self, text=self.title, fg_color="gray30", corner_radius=8)
        self.title.grid(row=0, column=0, padx=5, pady=5)

class newTopLevelWindow(customtkinter.CTkToplevel):
    def __init__(self, master, title, content):
        super().__init__(master)
        self.geometry("800x500")
        self.title(title)
        self.grid_rowconfigure((5, 0), weight=1)
        self.grid_columnconfigure((1, 0), weight=1)

        self.instructions = customtkinter.CTkLabel(self, text=content, wraplength=500, justify="left")
        self.instructions.grid(row=0, column=0, columnspan=2, padx=10, pady=10)

class userInterface(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.title("CryptoSuite")
        self.geometry("600x400")
        self.grid_rowconfigure((1, 0), weight=0)
        self.grid_columnconfigure((1, 0), weight=0)

        self.buttonFrame = buttonFrame(self, title="CryptoSuite Features")
        self.buttonFrame.grid(row=0, column=0, padx=10, pady=10)

    def openFrequencyAnalysisWindow(self):
        content = (
            "Frequency Analysis allows you to analyze the occurrence of each character in a given ciphertext.\n"
            "Enter the ciphertext below and click 'Analyze' to see the frequency of each character."
        )
        self.frequencyWindow = newTopLevelWindow(self, "Frequency Analysis", content)

        self.cipherTextBox = customtkinter.CTkTextbox(self.frequencyWindow, width=300, height=200)
        self.cipherTextBox.insert("0.0", "Enter Ciphertext Here")
        self.cipherTextBox.grid(row=1, column=0, padx=10, pady=5, sticky="ew")

        self.analyzeButton = customtkinter.CTkButton(self.frequencyWindow, text="Analyze", command=self.doFrequencyAnalysis)
        self.analyzeButton.grid(row=2, column=0, padx=10, pady=5)

        self.plainTextBox = customtkinter.CTkTextbox(self.frequencyWindow, width=300, height=200)
        self.plainTextBox.grid(row=1, column=1, padx=10, pady=5, sticky="ew")

    def doFrequencyAnalysis(self):
        ciphertext = self.cipherTextBox.get("1.0", "end-1c")
        frequencyCount = {}
        for char in ciphertext:
            frequencyCount[char] = frequencyCount.get(char, 0) + 1
        total = sum(frequencyCount.values())
        formattedOutput = "Frequency Analysis:\n"
        for char, count in sorted(frequencyCount.items(), key=lambda x: -x[1]):
            formattedOutput += f"'{char}': {count} times, {count/total:.2%}\n"
        self.plainTextBox.delete("1.0", "end")
        self.plainTextBox.insert("1.0", formattedOutput)

    def openRSAEncryptionWindow(self):
        content = (
            "RSA Encryption/Decryption allows secure communication using a pair of keys.\n"
            "- Use the public key for encryption and the private key for decryption.\n"
            "- Keys must be in PEM format (beginning with '-----BEGIN PUBLIC KEY-----' or '-----BEGIN PRIVATE KEY-----')."
        )
        self.rsaWindow = newTopLevelWindow(self, "RSA Encryption", content)

        self.messageTextBox = customtkinter.CTkTextbox(self.rsaWindow, width=300, height=150)
        self.messageTextBox.insert("0.0", "Enter Message Here")
        self.messageTextBox.grid(row=1, column=0, padx=10, pady=5, sticky="ew")

        self.publicKeyTextBox = customtkinter.CTkTextbox(self.rsaWindow, width=300, height=100)
        self.publicKeyTextBox.insert("0.0", "Enter Public Key (for encryption)")
        self.publicKeyTextBox.grid(row=2, column=0, padx=10, pady=5, sticky="ew")

        self.privateKeyTextBox = customtkinter.CTkTextbox(self.rsaWindow, width=300, height=100)
        self.privateKeyTextBox.insert("0.0", "Enter Private Key (for decryption)")
        self.privateKeyTextBox.grid(row=3, column=0, padx=10, pady=5, sticky="ew")

        self.encryptButton = customtkinter.CTkButton(self.rsaWindow, text="Encrypt", command=self.doRSAEncryption)
        self.encryptButton.grid(row=4, column=0, padx=10, pady=5)

        self.decryptButton = customtkinter.CTkButton(self.rsaWindow, text="Decrypt", command=self.doRSADecryption)
        self.decryptButton.grid(row=5, column=0, padx=10, pady=5)

        self.resultTextBox = customtkinter.CTkTextbox(self.rsaWindow, width=300, height=150)
        self.resultTextBox.grid(row=1, column=1, rowspan=5, padx=10, pady=5, sticky="ew")

    def doRSAEncryption(self):
        try:
            message = self.messageTextBox.get("1.0", "end-1c").encode()
            publicKeyData = self.publicKeyTextBox.get("1.0", "end-1c").strip()
            publicKey = RSA.import_key(publicKeyData)
            cipher = PKCS1_OAEP.new(publicKey)
            encryptedMessage = cipher.encrypt(message)
            encodedMessage = b64encode(encryptedMessage).decode()
            self.resultTextBox.delete("1.0", "end")
            self.resultTextBox.insert("1.0", encodedMessage)
        except Exception as e:
            self.resultTextBox.delete("1.0", "end")
            self.resultTextBox.insert("1.0", f"Error: {str(e)}")

    def doRSADecryption(self):
        try:
            encryptedMessage = self.messageTextBox.get("1.0", "end-1c")
            privateKeyData = self.privateKeyTextBox.get("1.0", "end-1c").strip()
            privateKey = RSA.import_key(privateKeyData)
            cipher = PKCS1_OAEP.new(privateKey)
            decryptedMessage = cipher.decrypt(b64decode(encryptedMessage))
            self.resultTextBox.delete("1.0", "end")
            self.resultTextBox.insert("1.0", decryptedMessage.decode())
        except Exception as e:
            self.resultTextBox.delete("1.0", "end")
            self.resultTextBox.insert("1.0", f"Error: {str(e)}")

    def openAESEncryptionWindow(self):
        content = (
            "AES Encryption/Decryption uses a secret key of length 16, 24, or 32 bytes for secure communication.\n"
            "Enter a message and a key, then click 'Encrypt' or 'Decrypt'."
        )
        self.aesWindow = newTopLevelWindow(self, "AES Encryption", content)

        self.messageTextBox = customtkinter.CTkTextbox(self.aesWindow, width=300, height=150)
        self.messageTextBox.insert("0.0", "Enter Message Here")
        self.messageTextBox.grid(row=1, column=0, padx=10, pady=5, sticky="ew")

        self.keyTextBox = customtkinter.CTkTextbox(self.aesWindow, width=300, height=50)
        self.keyTextBox.insert("0.0", "Enter AES Key (16, 24, or 32 bytes)")
        self.keyTextBox.grid(row=2, column=0, padx=10, pady=5, sticky="ew")

        self.encryptButton = customtkinter.CTkButton(self.aesWindow, text="Encrypt", command=self.doAESEncryption)
        self.encryptButton.grid(row=3, column=0, padx=10, pady=5)

        self.decryptButton = customtkinter.CTkButton(self.aesWindow, text="Decrypt", command=self.doAESDecryption)
        self.decryptButton.grid(row=4, column=0, padx=10, pady=5)

        self.resultTextBox = customtkinter.CTkTextbox(self.aesWindow, width=300, height=150)
        self.resultTextBox.grid(row=1, column=1, rowspan=4, padx=10, pady=5, sticky="ew")

    def doAESEncryption(self):
        try:
            message = self.messageTextBox.get("1.0", "end-1c").encode()
            key = self.keyTextBox.get("1.0", "end-1c").encode()
            if len(key) not in [16, 24, 32]:
                raise ValueError("AES key must be 16, 24, or 32 bytes long.")
            cipher = AES.new(key, AES.MODE_CBC)
            ciphertext = cipher.encrypt(pad(message, AES.block_size))
            encodedCipher = b64encode(cipher.iv + ciphertext).decode()
            self.resultTextBox.delete("1.0", "end")
            self.resultTextBox.insert("1.0", encodedCipher)
        except Exception as e:
            self.resultTextBox.delete("1.0", "end")
            self.resultTextBox.insert("1.0", f"Error: {str(e)}")

    def doAESDecryption(self):
        try:
            encryptedMessage = self.messageTextBox.get("1.0", "end-1c")
            key = self.keyTextBox.get("1.0", "end-1c").encode()
            if len(key) not in [16, 24, 32]:
                raise ValueError("AES key must be 16, 24, or 32 bytes long.")
            encryptedData = b64decode(encryptedMessage)
            iv = encryptedData[:16]
            ciphertext = encryptedData[16:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            self.resultTextBox.delete("1.0", "end")
            self.resultTextBox.insert("1.0", plaintext.decode())
        except Exception as e:
            self.resultTextBox.delete("1.0", "end")
            self.resultTextBox.insert("1.0", f"Error: {str(e)}")

    def openHashingWindow(self):
        content = (
        "Hashing allows you to generate fixed-size digests from input data using algorithms like SHA-256, SHA-512, or MD5.\n"
        "Enter a message below and select a hashing algorithm."
        )
        self.hashingWindow = newTopLevelWindow(self, "Hashing", content)

        self.messageTextBox = customtkinter.CTkTextbox(self.hashingWindow, width=300, height=150)
        self.messageTextBox.insert("0.0", "Enter Message Here")
        self.messageTextBox.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

        self.hashAlgorithm = customtkinter.CTkComboBox(self.hashingWindow, values=["SHA-256", "SHA-512", "MD5"])
        self.hashAlgorithm.grid(row=2, column=0, padx=10, pady=10, sticky="ew")
        self.hashAlgorithm.set("SHA-256")

        self.hashButton = customtkinter.CTkButton(self.hashingWindow, text="Generate Hash", command=self.doHashing)
        self.hashButton.grid(row=3, column=0, padx=10, pady=10, sticky="ew")

        self.resultTextBox = customtkinter.CTkTextbox(self.hashingWindow, width=300, height=150)
        self.resultTextBox.grid(row=1, column=1, rowspan=3, padx=10, pady=10, sticky="nsew")

    def doHashing(self):
        try:
            if not hasattr(self, 'resultTextBox') or not self.resultTextBox.winfo_exists():
                raise ValueError("Result text box is not available.")

            message = self.messageTextBox.get("1.0", "end-1c").encode()
            algorithm = self.hashAlgorithm.get()
            if algorithm == "SHA-256":
                hashObj = SHA256.new(message)
            elif algorithm == "SHA-512":
                hashObj = SHA512.new(message)
            elif algorithm == "MD5":
                hashObj = MD5.new(message)
            else:
                raise ValueError("Invalid hashing algorithm selected.")
            self.resultTextBox.delete("1.0", "end")
            self.resultTextBox.insert("1.0", hashObj.hexdigest())
        except Exception as e:
            if hasattr(self, 'resultTextBox') and self.resultTextBox.winfo_exists():
                self.resultTextBox.delete("1.0", "end")
                self.resultTextBox.insert("1.0", f"Error: {str(e)}")
            else:
                print(f"Error: {str(e)}")

    def openEncodingWindow(self):
        content = (
        "Encoding and decoding allows you to convert messages to Base64 format and back.\n"
        "Enter your message below and select an action."
    )
        self.encodingWindow = newTopLevelWindow(self, "Encoding/Decoding", content)

        self.messageTextBox = customtkinter.CTkTextbox(self.encodingWindow, width=300, height=150)
        self.messageTextBox.insert("0.0", "Enter Message Here")
        self.messageTextBox.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

        self.encodeButton = customtkinter.CTkButton(self.encodingWindow, text="Encode to Base64", command=self.doBase64Encoding)
        self.encodeButton.grid(row=2, column=0, padx=10, pady=10, sticky="ew")

        self.decodeButton = customtkinter.CTkButton(self.encodingWindow, text="Decode from Base64", command=self.doBase64Decoding)
        self.decodeButton.grid(row=3, column=0, padx=10, pady=10, sticky="ew")

        self.resultTextBox = customtkinter.CTkTextbox(self.encodingWindow, width=300, height=150)
        self.resultTextBox.grid(row=1, column=1, rowspan=3, padx=10, pady=10, sticky="nsew")

    def doBase64Encoding(self):
        message = self.messageTextBox.get("1.0", "end-1c").encode()
        encodedMessage = b64encode(message).decode()
        self.resultTextBox.delete("1.0", "end")
        self.resultTextBox.insert("1.0", encodedMessage)

    def doBase64Decoding(self):
        encodedMessage = self.messageTextBox.get("1.0", "end-1c")
        try:
            decodedMessage = b64decode(encodedMessage).decode()
            self.resultTextBox.delete("1.0", "end")
            self.resultTextBox.insert("1.0", decodedMessage)
        except Exception as e:
            self.resultTextBox.delete("1.0", "end")
            self.resultTextBox.insert("1.0", f"Error: {str(e)}")

    def openKeyGenerationWindow(self):
        content = (
            "Generate random keys for use with AES and RSA.\n"
            "- AES keys should be 16, 24, or 32 bytes long.\n"
            "- RSA key sizes should typically be 2048 or 4096 bits."
        )
        self.keyGenWindow = newTopLevelWindow(self, "Key Generation", content)

        self.keySizeEntry = customtkinter.CTkEntry(self.keyGenWindow, placeholder_text="Enter key size (e.g., 16 for AES, 2048 for RSA)")
        self.keySizeEntry.grid(row=1, column=0, padx=10, pady=5, sticky="ew")

        self.generateAESKeyButton = customtkinter.CTkButton(self.keyGenWindow, text="Generate AES Key", command=self.generateAESKey)
        self.generateAESKeyButton.grid(row=2, column=0, padx=10, pady=5)

        self.generateRSAKeyButton = customtkinter.CTkButton(self.keyGenWindow, text="Generate RSA Key Pair", command=self.generateRSAKeyPair)
        self.generateRSAKeyButton.grid(row=3, column=0, padx=10, pady=5)

        self.resultTextBox = customtkinter.CTkTextbox(self.keyGenWindow, width=300, height=150)
        self.resultTextBox.grid(row=1, column=1, rowspan=3, padx=10, pady=5, sticky="ew")

    def generateAESKey(self):
        try:
            size = int(self.keySizeEntry.get())
            if size not in [16, 24, 32]:
                raise ValueError("AES key size must be 16, 24, or 32 bytes.")
            key = get_random_bytes(size)
            self.resultTextBox.delete("1.0", "end")
            self.resultTextBox.insert("1.0", b64encode(key).decode())
        except Exception as e:
            self.resultTextBox.delete("1.0", "end")
            self.resultTextBox.insert("1.0", f"Error: {str(e)}")

    def generateRSAKeyPair(self):
        try:
            size = int(self.keySizeEntry.get())
            if size < 2048:
                raise ValueError("RSA key size should be at least 2048 bits.")
            key = RSA.generate(size)
            privateKey = key.export_key()
            publicKey = key.publickey().export_key()
            self.resultTextBox.delete("1.0", "end")
            self.resultTextBox.insert("1.0", f"Private Key:\n{privateKey.decode()}\n\nPublic Key:\n{publicKey.decode()}")
        except Exception as e:
            self.resultTextBox.delete("1.0", "end")
            self.resultTextBox.insert("1.0", f"Error: {str(e)}")

    def openConversionWindow(self):
        content = (
        "Convert text to hexadecimal or binary representation and back.\n"
        "Enter text below and select the desired conversion."
    )
        self.conversionWindow = newTopLevelWindow(self, "Text Conversion", content)

        self.messageTextBox = customtkinter.CTkTextbox(self.conversionWindow, width=300, height=150)
        self.messageTextBox.insert("0.0", "Enter message here")
        self.messageTextBox.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

        self.toHexButton = customtkinter.CTkButton(self.conversionWindow, text="Convert to Hex", command=self.convertToHex)
        self.toHexButton.grid(row=2, column=0, padx=10, pady=10, sticky="ew")

        self.toBinaryButton = customtkinter.CTkButton(self.conversionWindow, text="Convert to Binary", command=self.convertToBinary)
        self.toBinaryButton.grid(row=3, column=0, padx=10, pady=10, sticky="ew")

        self.resultTextBox = customtkinter.CTkTextbox(self.conversionWindow, width=300, height=150)
        self.resultTextBox.grid(row=1, column=1, rowspan=3, padx=10, pady=10, sticky="nsew")

    def convertToHex(self):
        message = self.messageTextBox.get("1.0", "end-1c")
        hexOutput = message.encode().hex()
        self.resultTextBox.delete("1.0", "end")
        self.resultTextBox.insert("1.0", hexOutput)

    def convertToBinary(self):
        message = self.messageTextBox.get("1.0", "end-1c")
        binaryOutput = ' '.join(format(ord(char), '08b') for char in message)
        self.resultTextBox.delete("1.0", "end")
        self.resultTextBox.insert("1.0", binaryOutput)

app = userInterface()
app.mainloop()
