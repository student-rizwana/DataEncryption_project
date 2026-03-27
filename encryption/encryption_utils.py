"""
Encryption utilities for AES and RSA encryption/decryption.
"""
import os
import base64
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class EncryptionManager:
    """Manager class for handling AES and RSA encryption operations."""
    
    def __init__(self):
        self.backend = default_backend()
        self.aes_key_size = 32  # 256 bits
        self.iv_size = 16  # 128 bits
        self.rsa_key_size = 2048
    
    def generate_aes_key(self):
        """Generate a random AES-256 key."""
        return os.urandom(self.aes_key_size)
    
    def generate_iv(self):
        """Generate a random initialization vector."""
        return os.urandom(self.iv_size)
    
    def generate_rsa_keypair(self):
        """Generate RSA-2048 key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.rsa_key_size,
            backend=self.backend
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def rsa_private_key_to_pem(self, private_key):
        """Convert RSA private key to PEM format."""
        from cryptography.hazmat.primitives import serialization
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    def rsa_public_key_to_pem(self, public_key):
        """Convert RSA public key to PEM format."""
        from cryptography.hazmat.primitives import serialization
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def rsa_private_key_from_pem(self, pem_data, password=None):
        """Load RSA private key from PEM format."""
        from cryptography.hazmat.primitives import serialization
        return serialization.load_pem_private_key(
            pem_data,
            password=password,
            backend=self.backend
        )
    
    def rsa_public_key_from_pem(self, pem_data):
        """Load RSA public key from PEM format."""
        from cryptography.hazmat.primitives import serialization
        return serialization.load_pem_public_key(
            pem_data,
            backend=self.backend
        )
    
    def encrypt_aes(self, data, key, iv):
        """
        Encrypt data using AES-256-CBC.
        
        Args:
            data: bytes to encrypt
            key: 32-byte AES key
            iv: 16-byte initialization vector
            
        Returns:
            Encrypted data as bytes
        """
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        encryptor = cipher.encryptor()
        
        # PKCS7 padding
        padding_length = 16 - (len(data) % 16)
        padded_data = data + bytes([padding_length] * padding_length)
        
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return encrypted
    
    def decrypt_aes(self, encrypted_data, key, iv):
        """
        Decrypt data using AES-256-CBC.
        
        Args:
            encrypted_data: encrypted bytes
            key: 32-byte AES key
            iv: 16-byte initialization vector
            
        Returns:
            Decrypted data as bytes
        """
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        decryptor = cipher.decryptor()
        
        decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Remove PKCS7 padding
        padding_length = decrypted[-1]
        return decrypted[:-padding_length]
    
    def encrypt_aes_key(self, aes_key, public_key_pem):
        """
        Encrypt AES key using RSA public key.
        
        Args:
            aes_key: 32-byte AES key
            public_key_pem: RSA public key in PEM format
            
        Returns:
            Encrypted AES key as base64 string
        """
        public_key = self.rsa_public_key_from_pem(public_key_pem)
        
        encrypted = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return base64.b64encode(encrypted).decode('utf-8')
    
    def decrypt_aes_key(self, encrypted_aes_key_b64, private_key_pem):
        """
        Decrypt AES key using RSA private key.
        
        Args:
            encrypted_aes_key_b64: Base64-encoded encrypted AES key
            private_key_pem: RSA private key in PEM format
            
        Returns:
            Decrypted AES key as bytes
        """
        encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
        
        private_key = self.rsa_private_key_from_pem(private_key_pem)
        
        decrypted = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return decrypted
    
    def encrypt_file(self, file_data, public_key_pem):
        """
        Encrypt file data using AES and RSA.
        
        Args:
            file_data: Raw file bytes
            public_key_pem: RSA public key in PEM format
            
        Returns:
            Dictionary with encrypted_data, encrypted_aes_key, and iv
        """
        # Generate AES key and IV
        aes_key = self.generate_aes_key()
        iv = self.generate_iv()
        
        # Encrypt file with AES
        encrypted_data = self.encrypt_aes(file_data, aes_key, iv)
        
        # Encrypt AES key with RSA
        encrypted_aes_key = self.encrypt_aes_key(aes_key, public_key_pem)
        
        return {
            'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8'),
            'encrypted_aes_key': encrypted_aes_key,
            'iv': base64.b64encode(iv).decode('utf-8')
        }
    
    def decrypt_file(self, encrypted_data_b64, encrypted_aes_key_b64, iv_b64, private_key_pem):
        """
        Decrypt file data using RSA and AES.
        
        Args:
            encrypted_data_b64: Base64-encoded encrypted file data
            encrypted_aes_key_b64: Base64-encoded encrypted AES key
            iv_b64: Base64-encoded IV
            private_key_pem: RSA private key in PEM format
            
        Returns:
            Decrypted file data as bytes
        """
        # Decode base64
        encrypted_data = base64.b64decode(encrypted_data_b64)
        iv = base64.b64decode(iv_b64)
        
        # Decrypt AES key
        aes_key = self.decrypt_aes_key(encrypted_aes_key_b64, private_key_pem)
        
        # Decrypt file
        decrypted_data = self.decrypt_aes(encrypted_data, aes_key, iv)
        
        return decrypted_data


# Singleton instance
encryption_manager = EncryptionManager()

