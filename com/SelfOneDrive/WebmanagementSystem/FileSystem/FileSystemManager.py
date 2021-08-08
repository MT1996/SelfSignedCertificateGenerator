# Verifizierung der Zertifikate... openssl verify -CAfile rootcrt.pem servercrt.pem

from ..Config import Config
from pathlib import Path
from flask import current_app

class FileSystemManager():

    cert_installation_path = Path(Config.certInstallationPath)

    def __init__(self) -> None:
        pass

    def getInstallationPath(self) -> Path:
        return self.cert_installation_path

    def check_prerequisite(self):
        if not self.cert_installation_path.exists():
            current_app.logger.info("Specified installationpath: " + str(self.cert_installation_path))
            current_app.logger.error("The default installationpath for the certificates does not exist! You have to create manually yourself! :(")
