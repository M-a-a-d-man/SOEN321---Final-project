from fileinput import filename
import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization


class CryptoUtils:
    def __init__(self):
        pass
    
    class KeyExchange:
        def __init__(self):
            pass

        def generate_rsa_key_pair(self):
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()
            return private_key, public_key

        def encrypt_with_rsa(self, public_key, plaintext):
            """Encrypts the plaintext using the provided RSA public key. The public key is stored in the server, and is the exponent public key."""
            ciphertext = public_key.encrypt(
                plaintext.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return ciphertext

        def decrypt_with_rsa(self, private_key, ciphertext):
            """Decrypts the ciphertext using the provided RSA private key. The private key is stored in the client, and is the exponent private key."""
            plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return plaintext.decode()
        
        def save_private_key(private_key, filepath: str, passphrase: bytes = None) -> None:
            if passphrase is not None:
                encryption = serialization.BestAvailableEncryption(passphrase)
            else:
                encryption = serialization.NoEncryption()

            pem_data = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=encryption,
            )

            with open(filepath, "wb") as f:
                f.write(pem_data)
    
        def load_private_key(filepath: str, passphrase: bytes = None):
            with open(filepath, "rb") as f:
                pem_data = f.read()

            private_key = serialization.load_pem_private_key(
                pem_data,
                password=passphrase
            )
            return private_key
        
        def save_public_key(public_key, filepath: str) -> None:
            pem_data = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            with open(filepath, "wb") as f:
                f.write(pem_data)
        
        def load_public_key(filepath: str):
            with open(filepath, "rb") as f:
                pem_data = f.read()

            serialization.load_pem_public_key(pem_data)
            public_key = serialization.load_pem_public_key(pem_data)
            return public_key
        
        def public_key_to_bytes(public_key) -> bytes:
            return public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        def public_key_from_bytes(pem_bytes: bytes):
            return serialization.load_pem_public_key(pem_bytes)
        
        def rsa_encrypt_session_key(session_key: bytes, recipient_public_key) -> bytes:
            encrypted_key = recipient_public_key.encrypt(
                session_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            return encrypted_key
        
        def rsa_decrypt_session_key(encrypted_key_bytes: bytes, private_key) -> bytes:
            session_key = private_key.decrypt(
                encrypted_key_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            return session_key
    class SymmetricEncryption:
        def __init__(self):
                pass