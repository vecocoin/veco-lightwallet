import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Generate key to code / decode sensitive user data using password and salt
def generate_key(password, salt):

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key


def encrypt_data(data, password, salt):
    password_bytes = password.encode()
    key = generate_key(password_bytes, salt)
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data


def decrypt_data(encrypted_data, password, salt):
    password_bytes = password.encode()
    key = generate_key(password_bytes, salt)
    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data).decode()
    return decrypted_data

# Example

#data_to_encrypt = json.dumps({"username": "user1", "wallet_addresses": ["address1", "address2"], "cwifs": ["cwif1", "cwif2"]})
#password = "hello123"
#salt_ex = os.urandom(16)
#encrypted_data = encrypt_data(data_to_encrypt, password, salt_ex)
#print("encrypted data:", encrypted_data)

#decrypted_data = decrypt_data(encrypted_data, password, salt_ex)
#print("decrypted data:", decrypted_data)
