from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from database import get_connection
import os


# Folder where private keys will be stored
KEY_FOLDER = "private_keys"

os.makedirs(KEY_FOLDER, exist_ok=True)


# Users who are members of Account 2
USER_IDS = [4, 5, 6, 7]


def generate_key_pair(user_id):

    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Create public key
    public_key = private_key.public_key()

    # Convert private key to PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Convert public key to PEM
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save private key locally
    private_file = os.path.join(
        KEY_FOLDER,
        f"user_{user_id}_private.pem"
    )

    with open(private_file, "wb") as file:
        file.write(private_pem)

    # Store public key in MySQL
    connection = get_connection()

    try:
        cursor = connection.cursor()

        cursor.execute("""
            UPDATE users
            SET public_key = %s
            WHERE user_id = %s
        """, (
            public_pem.decode("utf-8"),
            user_id
        ))

        connection.commit()

    finally:
        cursor.close()
        connection.close()

    print(f"User {user_id}: key pair generated")
    print(f"Private key: {private_file}")
    print("Public key stored in database")
    print()


for user_id in USER_IDS:
    generate_key_pair(user_id)

print("All key pairs generated successfully.")