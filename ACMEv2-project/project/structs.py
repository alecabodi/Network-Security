import requests


class Directory:

    def __init__(self, dir_url):
        response = requests.get(dir_url, verify='pebble.minica.pem').json()

        self.keyChange_url = response.get("keyChange")
        self.newAccount_url = response.get("newAccount")
        self.newNonce_url = response.get("newNonce")
        self.newOrder_url = response.get("newOrder")
        self.revokeCert_url = response.get("revokeCert")


class Order:

    def __init__(self):
        self.status = "pending"
        self.identifiers = []
        self.authorizations = None
        self.finalize = None
        self.certificate = None

        self.submitted_order_url = None
        self.auth_objects = []

    def set_identifiers(self, domain_list):
        for domain in domain_list:
            self.identifiers.append({"type": "dns", "value": domain})

    def set_submitted_order_url(self, submitted_order_url):
        self.submitted_order_url = submitted_order_url

    def set_authorizations(self, authorizations):
        self.authorizations = authorizations

    def set_finalize(self, finalize):
        self.finalize = finalize

    def get_finalize(self):
        return self.finalize

    def get_status_url(self):
        return self.submitted_order_url

    def set_status(self, status):
        self.status = status

    def get_status(self):
        return self.status


class Authorization:

    def __init__(self, auth_url, status, identifier, challenges, wildcard):
        self.auth_url = auth_url
        self.status = status
        self.identifier = identifier
        self.challenges = challenges
        self.wildcard = wildcard

    def get_auth_url(self):
        return self.auth_url

    def get_identifier(self):
        return self.identifier


class Challenge:

    def __init__(self, challenge_url, challenge_type, status, token):
        self.challenge_url = challenge_url
        self.status = status
        self.challenge_type = challenge_type
        self.token = token

        self.auth_url = None
        self.domain = None

    def set_status(self, status):
        self.status = status

    def get_status(self):
        return self.status

    def get_challenge_type(self):
        return self.challenge_type

    def get_token(self):
        return self.token

    def get_url(self):
        return self.challenge_url

    def set_auth_url(self, auth_url):
        self.auth_url = auth_url

    def get_auth_url(self):
        return self.auth_url

    def set_domain(self, domain):
        self.domain = domain

    def get_domain(self):
        return self.domain

    def get_status_url(self):
        return self.auth_url

