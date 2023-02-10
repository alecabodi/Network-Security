from dnslib.server import DNSServer
from dnslib.dns import RR

PORT = 10053


# from dnslib documentation implement TestResolver as inner class of custom dns server
class DnsServer:
    def __init__(self, zone_list, address):
        self.zone_list = zone_list
        self.address = address

        self.server = None
        self.create_dns_server()

    def create_dns_server(self):

        resolver = self.TestResolver(self.zone_list)

        self.server = DNSServer(resolver, port=PORT, address=self.address, tcp=False)
        self.server.start_thread()

    def terminate(self):
        self.server.server.server_close()

    class TestResolver:
        def __init__(self, zone_list):
            self.zone_list = zone_list

        def resolve(self, request, handler):

            reply = request.reply()

            if isinstance(self.zone_list, list):
                for z in self.zone_list:
                    reply.add_answer(*RR.fromZone(z))
            else:
                zone = self.zone_list
                reply.add_answer(*RR.fromZone(zone))

            return reply
