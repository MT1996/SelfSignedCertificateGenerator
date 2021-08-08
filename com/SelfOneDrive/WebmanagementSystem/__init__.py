from cryptography import x509
from com.SelfOneDrive.WebmanagementSystem.Domain.Model.CertData import CertData
from com.SelfOneDrive.WebmanagementSystem.FileSystem.FileSystemManager import FileSystemManager
from flask import Flask, request
from .CertificateGenerator.SelfSignedCertificateGenerator import SelfSignedCertificateGenerator
from .CertificateGenerator.CertDataValidator import CertDataValidator

def create_app(test_config=None):

    app = Flask(__name__)

    with app.app_context():
        fsManager = FileSystemManager()
        fsManager.check_prerequisite()

    @app.route("/api/v1/certauths", methods=['POST'])
    def createNewCert():
        jsonData = request.get_json()
        certData = CertData(**jsonData)
        certDataValidator = CertDataValidator()
        if certDataValidator.dataObjectContainsAllInformation(certData):
            app.logger.info("Daten sind volständig")
            # Daten sind bis hier hin vollständig...
            # Repository-Klasse erstellen, welche Daten für Generator nimmt und reinwirft und returnt ...
            # cert = SelfSignedCertificateGenerator().generate_Certificate_Authority()
        # app.logger.info(jsonData)
        return "getAllCertAuths"

    @app.route("/api/v1/sslconfigs")
    def getAllSslConfigs():
        return "getAllSSLConfigs"

    return app