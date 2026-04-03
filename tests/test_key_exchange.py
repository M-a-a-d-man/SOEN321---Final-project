import os
import tempfile
import unittest

from crypto import CryptoUtils


class TestKeyExchange(unittest.TestCase):
    def setUp(self):
        self.ke = CryptoUtils.KeyExchange()
        self.private_key, self.public_key = self.ke.generate_rsa_key_pair()

    def test_rsa_encrypt_decrypt_round_trip(self):
        message = "hello secure world"
        ciphertext = self.ke.encrypt_with_rsa(self.public_key, message)
        plaintext = self.ke.decrypt_with_rsa(self.private_key, ciphertext)
        self.assertEqual(plaintext, message)

    def test_public_key_bytes_round_trip(self):
        pem = CryptoUtils.KeyExchange.public_key_to_bytes(self.public_key)
        loaded_public = CryptoUtils.KeyExchange.public_key_from_bytes(pem)

        message = "public key conversion"
        ciphertext = self.ke.encrypt_with_rsa(loaded_public, message)
        plaintext = self.ke.decrypt_with_rsa(self.private_key, ciphertext)
        self.assertEqual(plaintext, message)

    def test_session_key_exchange_round_trip(self):
        session_key = os.urandom(32)
        encrypted_key = CryptoUtils.KeyExchange.rsa_encrypt_session_key(session_key, self.public_key)
        decrypted_key = CryptoUtils.KeyExchange.rsa_decrypt_session_key(encrypted_key, self.private_key)
        self.assertEqual(decrypted_key, session_key)

    def test_save_and_load_private_key_with_passphrase(self):
        passphrase = b"strong-test-passphrase"

        with tempfile.NamedTemporaryFile(delete=False) as f:
            private_path = f.name

        try:
            CryptoUtils.KeyExchange.save_private_key(self.private_key, private_path, passphrase)
            loaded_private = CryptoUtils.KeyExchange.load_private_key(private_path, passphrase)

            message = "private key load"
            ciphertext = self.ke.encrypt_with_rsa(self.public_key, message)
            plaintext = self.ke.decrypt_with_rsa(loaded_private, ciphertext)
            self.assertEqual(plaintext, message)
        finally:
            if os.path.exists(private_path):
                os.remove(private_path)


if __name__ == "__main__":
    unittest.main(verbosity=2)