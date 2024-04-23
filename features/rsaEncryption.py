from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def generateRSAKeyPair():
    key = RSA.generate(2048)
    privateKey = key.export_key()
    publicKey = key.publickey().export_key()
    return privateKey, publicKey

def encryptWithRSA(publicKey, plaintext):
    publicKeyObj = RSA.import_key(publicKey)
    CipherRSA = PKCS1_OAEP.new(publicKeyObj)
    ciphertext = CipherRSA.encrypt(plaintext.encode())
    ciphertextEncoded = base64.b64encode(ciphertext).decode()

def decryptWithRSA(privateKey, ciphertext):
    privateKeyObj= RSA.import_key(privateKey)
    CipherRSA = PKCS1_OAEP.new(privateKeyObj)
    ciphertextDecoded = base64.b64decode(ciphertext.decode())
    plaintext = CipherRSA.decrypt(ciphertextDecoded).decode()
    return plaintext
    
if __name__ == "__main__":
    privateKey, publicKey = generateRSAKeyPair()

    userPublicKey = input("Enter the public key")
    userPrivateKey = input("Enter the private key")