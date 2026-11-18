
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64

# Generate RSA private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Save private key
with open("private_key.pem", "wb") as file:
    file.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

# Get public key
public_key = private_key.public_key()

# Convert public key into DER format
public_key_der = public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.PKCS1
)

# Convert public key into Base64
public_key_dns = base64.b64encode(
    public_key_der
).decode("utf-8")

# Save public key
dns_record = "v=DKIM1; k=rsa; p=" + public_key_dns

with open("public_key.txt", "w") as file:
    file.write(dns_record)

print("DKIM keys generated successfully!")
print("Private key saved as: private_key.pem")
print("Public key saved as: public_key.txt")
print("\nDNS TXT Record:")
print("default._domainkey.example.com")
print(dns_record)
