import collections
import json
import multiprocessing
import requests
from time import sleep

import utils
from dns_server import DnsServer
from http_server import ChallengeServer, CertificateServer, ShutdownServer

JSON_HEADER = {"Content-Type": "application/jose+json"}


class CommunicationsManager:

    def __init__(self, directory):

        self.directory = directory
        self.nonce = self.get_new_nonce()

        self.jose = utils.JOSE()

        self.dns_server = None
        self.challenge_server = None
        self.certificate_server = None
        self.shutdown_server = None

        self.cert = None

    def get_new_nonce(self):
        response = requests.head(self.directory.newNonce_url, verify='pebble.minica.pem')
        return response.headers.get("Replay-Nonce")

    def post(self, url, payload, protected, key_type):

        if protected:
            payload = json.dumps(self.jose.get_jws(payload, self.nonce, url, key_type)).encode('utf8')

        response = requests.post(url, headers=JSON_HEADER, data=payload, verify='pebble.minica.pem')

        self.nonce = response.headers.get('Replay-Nonce')

        return response

    def post_as_get(self, url, protected, key_type):
        return self.post(url, '', protected, key_type)

    def get_auth_key(self, token):

        # from RFC7638
        keys_thumbprint = ["kty", "n", "e"]
        jwk_thumbprint = {key: self.jose.get_jwk().get(key) for key in keys_thumbprint}

        return utils.get_auth_key(token, json.dumps(jwk_thumbprint, sort_keys=True, separators=(",", ":")))

    def start_dns_server(self, challenge_type, domain, zone_append, address):
        zone = None

        if challenge_type == 'http01':
            zone = f"{domain}. 60 IN A {zone_append}"

        if challenge_type == 'dns01':
            zone = f"{domain}. 300 IN TXT {zone_append}"

        self.dns_server = DnsServer(zone, address)

    def terminate_dns_server(self):
        self.dns_server.terminate()

    def start_challenge_server(self, token, auth_key, address):
        self.challenge_server = multiprocessing.Process(target=ChallengeServer, args=(token, auth_key, address))
        self.challenge_server.start()

    def terminate_challenge_server(self):
        self.challenge_server.terminate()
        self.challenge_server.join()

    def poll_for_status(self, status_object):
        response = None

        while status_object.get_status() != "valid":
            response = self.post_as_get(status_object.get_status_url(), protected=True, key_type='kid')
            status_object.set_status(response.json().get("status"))
            sleep(3)

        return response

    def finalize(self, order, domains):

        csr = self.jose.get_csr(domains)

        payload = {'csr': csr}
        self.post(order.get_finalize(), payload, protected=True, key_type='kid')

        response = self.poll_for_status(order).json()

        return response.get('certificate')

    def install_certificate(self, cert_tmp, address):

        with open("certificate.pem", 'wb') as file:
            file.write(cert_tmp)
            file.close()

        self.start_certificate_server(cert_tmp.decode('utf8'), address)

        self.cert = utils.load_pem_x509(cert_tmp)

        return utils.encodePEM(self.cert)

    def start_certificate_server(self, cert, address):
        self.certificate_server = multiprocessing.Process(target=CertificateServer, args=(cert, address))
        self.certificate_server.start()

    def terminate_certificate_server(self):
        self.certificate_server.terminate()
        self.certificate_server.join()

    def issue_revocation(self):
        payload = {'certificate': utils.encode_base64(utils.encodeDER(self.cert))}
        self.post(self.directory.revokeCert_url, payload, protected=True, key_type='kid')

    def start_shutdown(self, address, domains):
        zone_list = list()

        for domain in domains:
            zone = f"{domain}. 60 IN A {address}"
            zone_list.append(zone)

        self.dns_server = DnsServer(zone_list, address)

        self.shutdown_server = ShutdownServer(address)
        self.terminate_certificate_server()
