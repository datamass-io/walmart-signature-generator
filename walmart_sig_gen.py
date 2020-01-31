from argparse import ArgumentParser
from apscheduler.schedulers.background import BackgroundScheduler
import logging
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from base64 import b64encode
import os
import time


class SignatureGenerator:
    def __init__(self, headers, private_key):
        self.headers = headers
        self.private_key = private_key

    def generate_signature(self, intimestamp):
        self.headers.update(intimestamp)
        array = self.canonicalize()

        hasher = SHA256.new(array[1].encode())
        signer = PKCS1_v1_5.new(self.private_key)
        signature = signer.sign(hasher)

        return str(b64encode(signature), 'utf-8')

    def canonicalize(self):
        keys = self.headers.keys()
        sorted_keys = sorted(keys)

        canonicalized_string = ""
        parameter_names = ""

        for key in sorted_keys:
            value = self.headers[key]
            parameter_names += key.strip() + ';'
            canonicalized_string += str(value).strip() + '\n'

        return [parameter_names, canonicalized_string]


def load_private_key(p_key_path):
    p_key = None
    if p_key_path == '.':
        for file in os.listdir('.'):
            if file.endswith('.pem'):
                try:
                    with open(file, "rb") as key_file:
                        p_key = RSA.import_key(key_file.read())
                        logging.info(f"[INFO] Successfully loaded Walmart private key")
                    break
                except IOError as e:
                    print(e)
                    logging.critical(f"[CRITICAL] An error occurred during loading Walmart private key. "
                                     f"Error details: \n{e}")

    else:
        try:
            with open(p_key_path, "rb") as key_file:
                p_key = RSA.import_key(key_file.read())
                logging.info(f"[INFO] Successfully loaded Walmart private key")
        except IOError as e:
            print(e)
            logging.critical(f"[CRITICAL] An error occurred during loading Walmart private key. Error details: \n{e}")

    return p_key


def refresh_signature(private_key, consumer_id, private_key_version):
    global headers

    headers = {'WM_CONSUMER.ID': consumer_id, 'WM_SEC.KEY_VERSION': private_key_version}

    signature_generator = SignatureGenerator(headers, private_key)

    intimestamp = int(round(time.time() * 1000))
    intimestamp_header = {'WM_CONSUMER.INTIMESTAMP': str(intimestamp)}

    signature = signature_generator.generate_signature(intimestamp_header)

    headers.update(intimestamp_header)
    headers.update({'WM_SEC.AUTH_SIGNATURE': signature})

    logging.info("[INFO] Signature refreshed")
    logging.info(f"[INFO] WM_CONSUMER.ID: {consumer_id}")
    logging.info(f"[INFO] WM_CONSUMER.INTIMESTAMP: {intimestamp}")
    logging.info(f"[INFO] WM_SEC.KEY_VERSION: {private_key_version}")
    logging.info(f"[INFO] WM_SEC.AUTH_SIGNATURE: {signature}")
    print("Signature refreshed")
    print(f"WM_CONSUMER.ID: {consumer_id}")
    print(f"WM_CONSUMER.INTIMESTAMP: {intimestamp}")
    print(f"WM_SEC.KEY_VERSION: {private_key_version}")
    print(f"WM_SEC.AUTH_SIGNATURE: {signature}")


if __name__ == "__main__":

    parser = ArgumentParser(description="Walmart API data downloader tool")
    parser.add_argument('-i', '--consumerId', required=True, dest="consumer_id", help="Walmart consumer Id")
    parser.add_argument('-v', '--key_v', required=True, dest="private_key_version",
                        help="Version of key uploaded to Walmart API")
    parser.add_argument('-k', '--key_path', nargs='?', default='.', dest='pkey_path',
                        help='Local path to your private key. If not specified, a first found file in script location '
                             'with .pem extension will be used')

    args = parser.parse_args()

    CONSUMER_ID = args.consumer_id
    PRIVATE_KEY_VERSION = args.private_key_version
    PKEY_PATH = args.pkey_path

    logging.basicConfig(filename="walmart_sig_gen.log", level=logging.DEBUG, format="%(asctime)s %(message)s")
    logging.info("[INFO] Start of script")

    scheduler = BackgroundScheduler()

    private_key = load_private_key(PKEY_PATH)

    headers = None
    refresh_signature(private_key, CONSUMER_ID, PRIVATE_KEY_VERSION)

    scheduler.add_job(lambda: refresh_signature(private_key, CONSUMER_ID, PRIVATE_KEY_VERSION), 'interval', seconds=150)
    scheduler.start()
