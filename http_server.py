import os
import signal

from flask import Flask, request

CERTIFICATE_PORT = 5001
CHALLENGE_PORT = 5002
SHUTDOWN_PORT = 5003


class ChallengeServer:
    def __init__(self, token, auth_key, address):
        self.token = token
        self.auth_key = auth_key
        self.address = address
        self.app = None

        self.create_app()

    def create_app(self):
        self.get_app().run(host=self.address,
                           port=CHALLENGE_PORT)

    def get_app(self):
        self.app = Flask(__name__)

        @self.app.route(f"/.well-known/acme-challenge/{self.token}", methods=["GET"])
        def get_response():
            return self.auth_key

        return self.app


class CertificateServer:
    def __init__(self, certificate, address):
        self.certificate = certificate
        self.address = address
        self.app = None

        self.create_app()

    def create_app(self):
        self.get_app().run(host=self.address,
                           port=CERTIFICATE_PORT,
                           ssl_context=('certificate.pem', 'private_key.pem'))

    def get_app(self):
        self.app = Flask(__name__)

        @self.app.route("/", methods=["GET"])
        def get_response():
            return self.certificate

        return self.app


class ShutdownServer:
    def __init__(self, address):
        self.address = address
        self.app = None

        self.create_app()

    def create_app(self):
        self.get_app().run(host=self.address,
                           port=SHUTDOWN_PORT)

    def get_app(self):
        self.app = Flask(__name__)

        @self.app.route("/shutdown")
        def shutdown():
            os.kill(os.getpid(), signal.SIGTERM)

        return self.app
