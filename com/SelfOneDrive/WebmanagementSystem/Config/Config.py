import os
class Config():
    publicKeyExponent: int = int(os.environ.get("CERT_DEFAULT_PUBLIC_EXPONENT"))
    keySize: int = int(os.environ.get("CERT_DEFAULT_KEY_SIZE"))
    certInstallationPath: str = os.environ.get("CERT_INSTALLATION_PATH")
