import os
class Config():
    publicKeyExponent: int = int(os.environ.get("CERT_DEFAULT_PUBLIC_EXPONENT"))
    keySize: int = int(os.environ.get("CERT_DEFAULT_KEY_SIZE"))
    certInstallationPath: str = os.environ.get("CERT_INSTALLATION_PATH")
    keyDefaultFiletype: str = os.environ.get("KEY_DEFAULT_FILETYPE")
    csrDefaultFiletype: str = os.environ.get("CSR_DEFAULT_FILETYPE")
    certDefaultFiletype: str = os.environ.get("CERT_DEFAULT_FILETYPE")
    certDefaultCANamespace: str = os.environ.get("CERT_DEFAULT_CA_NAMESPACE")
