from typing import Tuple
import customtkinter
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

        self.title = customtkinter.CTkLabel(self, text=self.title, fg_color="gray30", corner_radius=8)
        self.title.grid(row=0, column=0, padx=5, pady=5)

class newTopLevelWindow(customtkinter.CTkToplevel):
    def __init__(self, master, title, content):
        super().__init__(master)
        self.geometry("400x300")
        self.title(title)

        self.content = customtkinter.CTkLabel(self, text=content)
        self.content.pack(padx=20, pady=20)

class userInterface(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.title("CryptoSuite")
        self.geometry("400x180")
        self.grid_rowconfigure((0,0), weight=0)
        self.grid_columnconfigure((0, 0), weight=0)

        self.buttonFrame = buttonFrame(self, title="Features")
        self.buttonFrame.grid(row=0, column=0, padx=10, pady=10)

    def openFrequencyAnalysisWindow(self):
        if hasattr(self, "frequency_window") and self.frequency_window.winfo_exists():
            self.frequency_window.focus()
        else:
            self.frequency_window = newTopLevelWindow(self, "Frequency Analysis", "Frequency Analysis Content")

    def openRSAEncryptionWindow(self):
        if hasattr(self, "rsa_window") and self.rsa_window.winfo_exists():
            self.rsa_window.focus()
        else:
            self.rsa_window = newTopLevelWindow(self, "RSA Encryption", "RSA Content")

    def openAESEncryptionWindow(self):
        if hasattr(self, "aes_window") and self.aes_window.winfo_exists():
            self.aes_window.focus()
        else:
            self.aes_window = newTopLevelWindow(self, "AES Encryption", "AES Content")

app = userInterface()
app.mainloop()