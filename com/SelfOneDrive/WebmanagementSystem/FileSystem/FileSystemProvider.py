# Verifizierung der Zertifikate... openssl verify -CAfile rootcrt.pem servercrt.pem
from cryptography.hazmat.primitives import serialization

from ..Config import Config
from pathlib import Path
from flask import current_app
from cryptography.x509.base import rsa, Certificate


class FileSystemProvider():

    cert_installation_path = Path(Config.certInstallationPath)

    def __init__(self) -> None:
        pass

    def getInstallationPath(self) -> Path:
        return self.cert_installation_path

    def check_prerequisite(self):
        if not self.cert_installation_path.exists():
            current_app.logger.info("Specified installationpath: " + str(self.cert_installation_path))
            current_app.logger.error("The default installationpath for the certificates does not exist! You have to create manually yourself! :(")

    @classmethod
    def checkDomainExists(cls, persistence_identifier: str) -> bool:
        domainDependingDirectory = cls.cert_installation_path.joinpath(persistence_identifier)
        return domainDependingDirectory.exists()

    @classmethod
    def createNamespaceForDomainForSavingKeysAndCertificate(cls, persistence_identifier: str) -> bool:
        domainNamespace = cls.cert_installation_path.joinpath(persistence_identifier)
        if not cls.checkDomainExists(persistence_identifier):
            domainNamespace.mkdir(mode=0o777)
            return True
        else:
            return domainNamespace.exists()

    @classmethod
    def checkKeyExists(cls, persistence_identifier: str) -> bool:
        keyFilename = persistence_identifier + Config.keyDefaultFiletype
        return cls.cert_installation_path.joinpath(persistence_identifier, keyFilename).exists()

    @classmethod
    def createKeyEntry(cls, persistence_identifier: str, key: rsa.RSAPrivateKey) -> bool:
        if not cls.createNamespaceForDomainForSavingKeysAndCertificate(persistence_identifier):
            return False
        else:
            if not cls.checkKeyExists(persistence_identifier):
                keyFilename = persistence_identifier + Config.keyDefaultFiletype
                keyFile = cls.cert_installation_path.joinpath(persistence_identifier, keyFilename)
                keyFile.touch()
                keyFile.write_bytes(key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()
                ))
                return True
            else:
                return False

    @classmethod
    def checkCertExists(cls, persistence_identifier: str) -> bool:
        certFilename = persistence_identifier + Config.certDefaultFiletype
        return cls.cert_installation_path.joinpath(persistence_identifier, certFilename).exists()

    @classmethod
    def createCertEntry(cls, persistence_identifier: str, cert: Certificate) -> bool:
        if not cls.createNamespaceForDomainForSavingKeysAndCertificate(persistence_identifier):
            return False
        else:
            if not cls.checkCertExists(persistence_identifier):
                certFilename = persistence_identifier + Config.certDefaultFiletype
                certFile = cls.cert_installation_path.joinpath(persistence_identifier, certFilename)
                certFile.touch()
                certFile.write_bytes(cert.public_bytes(
                    serialization.Encoding.PEM
                ))
                return True
            else:
                return False

    @classmethod
    def checkCSRExists(cls, persistence_identifier: str):
        pass
