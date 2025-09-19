from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

with open("certificate.pem","rb") as f:
    cert = x509.load_pem_x509_certificate(f.read())

pub = cert.public_key()
try:
    pub.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )
    print("Certificate signature verified (self-signed OK).")
except Exception as e:
    print("Verification failed:", e)
