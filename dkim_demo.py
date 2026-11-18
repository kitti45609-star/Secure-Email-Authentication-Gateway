
import dkim

# Read private key
with open("private_key.pem", "rb") as file:
    private_key = file.read()

# Read public DNS record
with open("public_key.txt", "r") as file:
    dns_record = file.read().strip()


# Create sample email
email = (
    b"From: test@example.com\r\n"
    b"To: recipient@example.com\r\n"
    b"Subject: DKIM Security Test\r\n"
    b"\r\n"
    b"This is a sample email for DKIM testing."
)


# Sign the email
signature = dkim.sign(
    message=email,
    selector=b"default",
    domain=b"example.com",
    privkey=private_key,
    include_headers=[b"from", b"to", b"subject"]
)

# Add DKIM signature to email
signed_email = signature + email

print("Email signed successfully!")

# Simulate DNS lookup using our generated public key
def dns_lookup(name, timeout=5):
    expected_name = b"default._domainkey.example.com."

    if name.lower() == expected_name:
        return dns_record.encode("utf-8")

    return None


# Verify the signed email
try:
    result = dkim.verify(
        signed_email,
        dnsfunc=dns_lookup
    )

    if result:
        print("DKIM Verification: PASS")
    else:
        print("DKIM Verification: FAIL")

except Exception as error:
    print("Verification Error:", error)
