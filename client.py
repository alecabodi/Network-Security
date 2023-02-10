import communication
import structs
import utils

global kid


class AcmeClient:

    def __init__(self, dir_url):
        self.directory = structs.Directory(dir_url)
        self.communicationsManager = communication.CommunicationsManager(self.directory)

        self.account_url = None
        self.create_account(self.directory.newAccount_url)

        self.order = None
        self.challenges = list()

    def create_account(self, newAccount_url):

        payload = {
            "contact": [
                "mailto:cert-admins@example.org",
                "mailto:admin@example.org",
            ],
            "termsOfServiceAgreed": True,
        }

        response = self.communicationsManager.post(newAccount_url, payload, protected=True, key_type='jwk')

        self.account_url = response.headers.get("Location")

        global kid
        kid = self.account_url

    def create_order(self, domain_list):

        self.order = structs.Order()

        self.order.set_identifiers(domain_list)

        response = self.apply_for_certificate(self.order.identifiers)

        self.order.set_submitted_order_url(response.headers.get("Location"))
        self.order.set_authorizations(response.json().get("authorizations"))
        self.order.set_finalize(response.json().get("finalize"))

        self.create_authorizations(self.order.authorizations)

    def apply_for_certificate(self, identifiers):

        payload = {"identifiers": identifiers}
        response = self.communicationsManager.post(self.directory.newOrder_url, payload, protected=True, key_type='kid')

        return response

    def create_authorizations(self, authorizations):

        for auth_url in authorizations:
            response = self.communicationsManager.post_as_get(auth_url, protected=True, key_type='kid')
            auth_tmp = response.json()

            auth = structs.Authorization(auth_url,
                                         auth_tmp.get("status"),
                                         auth_tmp.get("identifier"),
                                         auth_tmp.get("challenges"),
                                         auth_tmp.get("wildcard"))

            self.order.auth_objects.append(auth)

    def set_challenges(self, challenge_type, record):

        for auth in self.order.auth_objects:

            for challenge in auth.challenges:

                if challenge.get("type").replace("-", "") == challenge_type:
                    challenge_tmp = structs.Challenge(challenge.get("url"),
                                                      challenge_type,
                                                      challenge.get("status"),
                                                      challenge.get("token"))
                    challenge_tmp.set_auth_url(auth.get_auth_url())
                    challenge_tmp.set_domain(auth.get_identifier().get("value"))

                    self.challenges.append(challenge_tmp)

        for challenge in self.challenges:
            self.solve_challenge(challenge, record)

    def solve_challenge(self, challenge, record):

        auth_key = self.communicationsManager.get_auth_key(challenge.get_token())

        if challenge.get_challenge_type() == "http01":
            self.communicationsManager.start_dns_server("http01",
                                                        domain=challenge.get_domain(),
                                                        zone_append=record,
                                                        address=record)

            self.communicationsManager.start_challenge_server(token=challenge.get_token(),
                                                              auth_key=auth_key,
                                                              address=record)

        if challenge.get_challenge_type() == "dns01":
            hash_auth_key = utils.encode_base64(utils.hash256(auth_key))

            self.communicationsManager.start_dns_server("dns01",
                                                        domain=challenge.get_domain(),
                                                        zone_append=hash_auth_key,
                                                        address=record)

        self.communicationsManager.post(challenge.get_url(), {}, protected=True, key_type='kid')

        self.communicationsManager.poll_for_status(challenge)

        self.communicationsManager.terminate_dns_server()

        if challenge.get_challenge_type() == "http01":
            self.communicationsManager.terminate_challenge_server()

    def get_certificate(self, domains, record):

        certificate_url = self.communicationsManager.finalize(self.order, domains)

        response = self.communicationsManager.post_as_get(certificate_url, protected=True, key_type='kid')
        certificate = self.communicationsManager.install_certificate(response.content, record)

        return certificate

    def revoke_certificate(self):
        self.communicationsManager.issue_revocation()

    def shutdown(self, record, domains):
        self.communicationsManager.start_shutdown(record, domains)
