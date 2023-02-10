import argparse

from client import AcmeClient

if __name__ == '__main__':

    # parse arguments
    parser = argparse.ArgumentParser()

    parser.add_argument("challenge", choices=["http01", "dns01"])
    parser.add_argument('--dir', required=True)
    parser.add_argument('--record', required=True)
    parser.add_argument('--domain', action="append", required=True)
    parser.add_argument('--revoke', action="store_true", required=False)

    args = parser.parse_args()

    # create account and setup client
    client = AcmeClient(args.dir)

    # submit order and solve challenges
    client.create_order(args.domain)
    client.set_challenges(args.challenge, args.record)

    # download the certificate
    certificate = client.get_certificate(args.domain, args.record)

    # revoke certificate
    if args.revoke:
        client.revoke_certificate()

    # shutdown routine
    client.shutdown(args.record, args.domain)






