import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# === Helper Functions ===

def base64url_decode(val: str) -> bytes:
    """Decodes a Base64URL-encoded string (without padding)."""
    val += '=' * ((4 - len(val) % 4) % 4)  # Add missing padding
    return base64.urlsafe_b64decode(val)

def jwk_to_pem(jwk: dict, encrypt_key: bool = False, encryption_password: bytes = None, pkcs_format: str = "PKCS8") -> bytes:
    """Converts a JWK (JSON Web Key) to a PEM-encoded RSA private key."""
    
    # Extract base64url-encoded fields and convert to integers
    n = int.from_bytes(base64url_decode(jwk["n"]), byteorder='big')
    e = int.from_bytes(base64url_decode(jwk.get("e", "AQAB")), byteorder='big')  # Default to 65537
    d = int.from_bytes(base64url_decode(jwk["d"]), byteorder='big')
    p = int.from_bytes(base64url_decode(jwk["p"]), byteorder='big')
    q = int.from_bytes(base64url_decode(jwk["q"]), byteorder='big')
    dp = int.from_bytes(base64url_decode(jwk["dp"]), byteorder='big')
    dq = int.from_bytes(base64url_decode(jwk["dq"]), byteorder='big')
    qi = int.from_bytes(base64url_decode(jwk["qi"]), byteorder='big')

    # Reconstruct the RSA private key
    private_key = rsa.RSAPrivateNumbers(
        p=p, q=q, d=d, dmp1=dp, dmq1=dq, iqmp=qi,
        public_numbers=rsa.RSAPublicNumbers(e, n)
    ).private_key()

    # Choose encryption method
    encryption = serialization.BestAvailableEncryption(encryption_password) if encrypt_key else serialization.NoEncryption()

    # Default to PKCS#8 because PKCS#1 is not always available
    private_format = serialization.PrivateFormat.PKCS8
    
    # Convert to PEM format
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=private_format,
        encryption_algorithm=encryption
    )
    
    return pem

def validate_pem(pem_data: bytes):
    """Validates if the PEM key is properly formatted and matches its expected public key."""
    private_key = serialization.load_pem_private_key(pem_data, password=None)
    public_key = private_key.public_key()
    
    public_numbers = public_key.public_numbers()
    print(f"✅ RSA Key is valid")
    print(f"Modulus (n): {public_numbers.n}")
    print(f"Exponent (e): {public_numbers.e}")

    return public_numbers

def extract_public_key_from_pem(pem_data: bytes) -> bytes:
    """Extracts the public key from a given PEM private key and returns it in PEM format."""
    private_key = serialization.load_pem_private_key(pem_data, password=None)
    public_key = private_key.public_key()

    # Convert public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return public_pem


# === Main Execution ===

if __name__ == "__main__":
    # Load the JWK from file (update filename if needed)
    with open("test_key.jwk", "r") as f:
        jwk_data = json.load(f)["key"]

    # Convert to PEM
    pem_key = jwk_to_pem(jwk_data, encrypt_key=False)

    # Save to a file
    with open("rsa_private.pem", "wb") as pem_file:
        pem_file.write(pem_key)
    print("🔑 RSA Private Key saved as rsa_private.pem")

    # Validate the key
    print("\n🔍 Validating RSA Key...")
    validate_pem(pem_key)

    # Extract and save the public key
    public_pem = extract_public_key_from_pem(pem_key)
    with open("rsa_public.pem", "wb") as pub_file:
        pub_file.write(public_pem)
    print("🔓 RSA Public Key saved as rsa_public.pem")
