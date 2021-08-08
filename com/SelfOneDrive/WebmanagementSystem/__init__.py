from dataclasses import fields
from typing import List
import datetime
from cryptography.x509 import NameAttribute, NameOID, BasicConstraints
from com.SelfOneDrive.WebmanagementSystem.Domain.Model.CertData import CertData
from com.SelfOneDrive.WebmanagementSystem.FileSystem.FileSystemProvider import FileSystemProvider
from flask import Flask, request, jsonify
from .CertificateGenerator.SelfSignedCertificateGenerator import SelfSignedCertificateGenerator
from .CertificateGenerator.CertDataValidator import CertDataValidator
from .Domain.Repository.CertificateRepository import CertificateRepository
from .Domain.Repository.KeyRepository import KeyRepository


def create_app(test_config=None):

    app = Flask(__name__)

    certDataValidator = CertDataValidator()
    sscGenerator = SelfSignedCertificateGenerator()
    certRepository = CertificateRepository()
    keyRepository = KeyRepository()

    with app.app_context():
        fsManager = FileSystemProvider()
        fsManager.check_prerequisite()

    @app.route("/api/v1/certauths", methods=['POST'])
    def createNewCert():
        jsonData = request.get_json()
        certData = CertData(**jsonData)
        if certDataValidator.dataObjectContainsAllInformation(certData):
            app.logger.info("Daten sind volständig")
            ca_information: List[NameAttribute] = [
                # Simple Example for creating the ca-information...
                #
                # x509.NameAttribute(NameOID.COUNTRY_NAME, u"DE"),
                # x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Niedersachsen"),
                # x509.NameAttribute(NameOID.LOCALITY_NAME, u"Braunschweig"),
                # x509.NameAttribute(NameOID.COMMON_NAME, u"selfonedrive.home-webserver.de"),
                # x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'SelfOneDrive Corp. Root CA'),
                # x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'Development')
                NameAttribute(NameOID.COUNTRY_NAME, certData.country_name),
                NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, certData.state_or_province_name),
                NameAttribute(NameOID.LOCALITY_NAME, certData.local_city_name),
                NameAttribute(NameOID.COMMON_NAME, certData.common_name),
                NameAttribute(NameOID.ORGANIZATION_NAME, certData.organization_name),
                NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, certData.organization_unit_name),
            ]
            privateKey, certificate = sscGenerator.generate_Certificate_Authority(
                ca_information,
                datetime.datetime.utcnow() + datetime.timedelta(days=certData.validation_range),
                BasicConstraints(True, None)
            )
            keySuccessfullySaved = keyRepository.persistOne(certData.persistence_identifier, privateKey)
            certSuccessfullySaved = certRepository.persistOne(certData.persistence_identifier, certificate)
            if keySuccessfullySaved and certSuccessfullySaved:
                return jsonify({"successful": True})
            else:
                return jsonify({"succesful": False})
        else:
            return jsonify({"successful": False})

    @app.route("/api/v1/sslconfigs")
    def getAllSslConfigs():
        return "getAllSSLConfigs"

    return app