from ecdsa import SigningKey, SECP256k1
import base58
import hashlib


def generate_cwif_and_address():
    # Generate a new ECDSA key pair for SECP256k1
    private_key = SigningKey.generate(curve=SECP256k1)
    public_key = private_key.get_verifying_key()

    # Convert the private key to hexadecimal format and add network and compression bytes
    private_key_hex = private_key.to_string().hex()
    network_byte = '4B'
    compress_byte = '01'
    pkey_full_hex = network_byte + private_key_hex + compress_byte
    pkey_full_bytes = bytes.fromhex(pkey_full_hex)
    checksum = hashlib.sha256(hashlib.sha256(pkey_full_bytes).digest()).digest()[:4]
    cwif = base58.b58encode(pkey_full_bytes + checksum).decode()

    # Generate the compressed form of the public key
    public_key_compressed_hex = public_key.to_string("compressed").hex()

    # Generate the wallet address from the compressed public key
    address = pub_key_to_addr(public_key_compressed_hex)

    return cwif, address


def pub_key_to_addr(pub_key_compressed_hex):
    sha256_hash = hashlib.sha256(bytes.fromhex(pub_key_compressed_hex)).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    ripemd_hash = ripemd160.digest()
    network_byte = b'\x46'
    network_and_ripemd = network_byte + ripemd_hash
    checksum = hashlib.sha256(hashlib.sha256(network_and_ripemd).digest()).digest()[:4]
    address = base58.b58encode(network_and_ripemd + checksum).decode('utf-8')
    return address


def cwif_to_address(cwif):
    network_byte_hex = '46'
    # Decode CWIF to extract the private key and the network byte
    decoded_cwif = base58.b58decode(cwif)
    private_key_bytes = decoded_cwif[1:-5]  # Remove network byte and checksum
    # Generate the public key from the private key
    sk = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
    public_key = sk.get_verifying_key().to_string("compressed")
    # print(public_key.hex())
    # SHA-256 and RIPEMD-160 hash of the public key
    sha256_hash = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160', sha256_hash).digest()
    # Add network byte
    network_byte = bytes.fromhex(network_byte_hex)
    address_bytes = network_byte + ripemd160
    # Calculate checksum and perform Base58Check coding
    checksum = hashlib.sha256(hashlib.sha256(address_bytes).digest()).digest()[:4]
    address = base58.b58encode(address_bytes + checksum)
    return address.decode()


def verify_address(address):
    try:
        # Decode the address back into bytes
        decoded = base58.b58decode(address)

        # The decoded address should consist of the network byte, the RIPEMD-160 hash and the 4-byte checksum
        if len(decoded) != 25:
            return False

        # Extract the network byte, the RIPEMD-160 hash and the checksum
        network_byte = decoded[0]
        ripemd_hash = decoded[1:-4]
        checksum = decoded[-4:]

        # Recalculate the checksum to compare it with the existing checksum
        calculated_checksum = hashlib.sha256(hashlib.sha256(bytes([network_byte]) + ripemd_hash).digest()).digest()[:4]

        return checksum == calculated_checksum
    except Exception as e:
        # For each error (e.g. invalid base58 coding), assume that the address is invalid
        return False
