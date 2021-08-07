from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.hazmat.primitives.serialization.base import load_pem_private_key
from cryptography.x509.oid import NameOID

def generate_private_key():
    public_exponent = 65537
    key_size = 4096
    key = rsa.generate_private_key(
        public_exponent, 
        key_size
    )

    with open("privateKeyForSelfOneDrive.pem", "wb") as keyFile:
        keyFile.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.BestAvailableEncryption(b"passphrase")
            )
        )

def generate_CSR_with_key(key: rsa.RSAPrivateKey):
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, u"DE"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Niedersachsen"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, u"Braunschweig"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SelfOneDrive Corp."),
                x509.NameAttribute(NameOID.COMMON_NAME, u"selfonedrive.home-webserver.de")
            ]
        )
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(u"selfonedrive.home-webserver.de"),
            x509.DNSName(u"www.selfonedrive.home-webserver.de")
        ]),
        False
    ).sign(key, hashes.SHA256())

    with open("CSRForSelfOneDrive.pem", "wb") as csrFile:
        csrFile.write(
            csr.public_bytes(
                serialization.Encoding.PEM
            )
        )

if __name__ == "__main__":
    generate_private_key()

    bytes_of_key = None
    with open("privateKeyForSelfOneDrive.pem", "rb") as keyFile:
        bytes_of_key = keyFile.read()
    
    myPrivateKey = load_pem_private_key(bytes_of_key, b"passphrase")

    generate_CSR_with_key(myPrivateKey)