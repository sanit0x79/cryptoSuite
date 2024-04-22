from typing import Tuple
import customtkinter
import tkinter as tk
from features.frequencyAnalysis import frequencyAnalysis

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

        self.menuOption4 = customtkinter.CTkButton(self, text="placeholder4", command=self.master.openPlaceholder4Window)
        self.menuOption4.grid(row=4, column=0, padx=5, pady=5)

        self.menuOption5 = customtkinter.CTkButton(self, text="placeholder5", command=self.master.openPlaceholder5Window)
        self.menuOption5.grid(row=5, column=0, padx=5, pady=5)

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
            self.iconbitmap("features/media/logicleap_transparent.ico")

            self.cipherTextBox = customtkinter.CTkTextbox(self.frequencyWindow, width=200, height=350)
            self.cipherTextBox.insert("0.0", "Enter Ciphertext Here")
            self.cipherTextBox.grid(row=0,column=20)

            self.analyzeButton = customtkinter.CTkButton(self.frequencyWindow, text="Analyze", command=self.doFrequencyAnalysis)
            self.analyzeButton.grid(row=10,column=20)

            self.clearButton = customtkinter.CTkButton(self.frequencyWindow, text="Clear", command=self.clearTextBox)
            self.clearButton.grid(row=10, column=30)

            self.plainTextBox = customtkinter.CTkTextbox(self.frequencyWindow, width=200, height=350)
            self.plainTextBox.grid(row=0, column=30, padx=5)

    def doFrequencyAnalysis(self):
        ciphertext = self.cipherTextBox.get("1.0", "end-1c")
        frequencies = frequencyAnalysis(ciphertext)
        formatted_output = "Frequency Analysis:\n"
        for char, (count, percentage) in frequencies.items():
            formatted_output += f"'{char}' appears {count} times, which is {percentage:.2f}% of the total\n"
        self.plainTextBox.insert("1.0", formatted_output)

    def clearTextBox(self):
        self.plainTextBox.delete("1.0", "end")
        self.cipherTextBox.delete("1.0", "end")
        self.publicKeyTextBox.delete("1.0", "end")
        self.privateKeyTextBox.delete("1.0", "end")
        
    def openRSAEncryptionWindow(self):
        if hasattr(self, "rsaWindow") and self.rsaWindow.winfo_exists():
            self.rsaWindow.focus()
        else:
            self.rsaWindow = newTopLevelWindow(self, "RSA Encryption", "RSA Content")
            self.iconbitmap("features/media/logicleap_transparent.ico")

            self.cipherTextBox = customtkinter.CTkTextbox(self.rsaWindow, width=200, height=350)
            self.cipherTextBox.insert("0.0", "Enter Ciphertext Here")
            self.cipherTextBox.grid(row=0,column=20)

            self.analyzeButton = customtkinter.CTkButton(self.rsaWindow, text="Encrypt", command=self.doRSAEncryption)
            self.analyzeButton.grid(row=10,column=20)

            self.clearButton = customtkinter.CTkButton(self.rsaWindow, text="Clear", command=self.clearTextBox)
            self.clearButton.grid(row=10, column=30)

            self.plainTextBox = customtkinter.CTkTextbox(self.rsaWindow, width=200, height=350)
            self.plainTextBox.grid(row=0, column=30, padx=5)

            self.publicKeyTextBox = customtkinter.CTkTextbox(self.rsaWindow, width=200, height=175)
            self.publicKeyTextBox.insert("0.0", "Enter your public key here")
            self.publicKeyTextBox.grid(row=0, column=40, pady=(0,0), sticky="ew", columnspan=2)

            self.privateKeyTextBox = customtkinter.CTkTextbox(self.rsaWindow, width=200, height=175)
            self.privateKeyTextBox.insert("0.0", "Enter your private key here")
            self.privateKeyTextBox.grid(row=1, column=40, pady=(0,0), sticky="ew", columnspan=2)


    def doRSAEncryption(self):
        print("Working")

    def openAESEncryptionWindow(self):
        if hasattr(self, "aesWindow") and self.aesWindow.winfo_exists():
            self.aesWindow.focus()
        else:
            self.aesWindow = newTopLevelWindow(self, "AES Encryption", "AES Content")
            self.iconbitmap("features/media/logicleap_transparent.ico")

    def openPlaceholder4Window(self):
        if hasattr(self, "ph4_window") and self.aes_window.winfo_exists():
            self.ph4_window.focus()
        else:
            self.ph4_window = newTopLevelWindow(self, "Placeholder 4", "Placeholder 4 Content")

    def openPlaceholder5Window(self):
        if hasattr(self, "ph5_window") and self.aes_window.winfo_exists():
            self.ph5_window.focus()
        else:
            self.ph5_window = newTopLevelWindow(self, "Placeholder 5 Encryption", "Placeholder 5 Content")

app = userInterface()
app.mainloop()