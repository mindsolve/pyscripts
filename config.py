#!/usr/bin/env python3
"""
This configuration file contains all confidential information
"""
from simplecrypt import decrypt, DecryptionException
import sys
import os
import json
import base64

if __name__ == '__main__':
    print('This script is not meant to be called directly.')
    sys.exit(1)

if os.path.isfile(os.path.join(os.path.dirname(__file__), 'config_decrypted.json')):
    print("Loading configuration from decrypted cache...")
    config_json = open(os.path.join(os.path.dirname(__file__), 'config_decrypted.json'), mode="r").read()

else:
    print("Loading encrypted configuration... ", end="")
    if 'KEY' in os.environ:
        print('Using password from ENV.')
        password = os.getenv('KEY')
    else:
        print('Using interactive input.')
        try:
            password = input("Please enter the password: ")
        except EOFError:
            print("Input aborted, exiting.")
            sys.exit(1)

    if not os.path.isfile(os.path.join(os.path.dirname(__file__), 'config_encrypted.txt')):
        print("Error: Encrypted config non-existent.")
        sys.exit(1)

    base64_config = open("config_encrypted.txt").read()

    enc_config_base64_bytes = base64_config.encode('utf8')
    enc_config_bytes = base64.decodebytes(enc_config_base64_bytes)
    try:
        config_json = decrypt(password, enc_config_bytes).decode('utf8')
        print("Decryption successful.")
    except DecryptionException as e:
        print('ERROR:', e)
        sys.exit(1)

    # Caching decrypted json text to file, as decryption is quite slow (>5 seconds)
    # This encryption is purely to protect internal data (COMPANY INTERNAL), not for actual "confidentiality"/"secrecy"
    open(os.path.join(os.path.dirname(__file__), 'config_decrypted.json'), mode="w").write(config_json)

print()
try:
    config_obj = json.loads(config_json)
except:
    print("Error: The decrypted JSON is invalid. Something unusual went wrong.")
    os.unlink(os.path.join(os.path.dirname(__file__), 'config_decrypted.json'))
    print("Please try again.")
    exit(1)

# End of decryption, now assign config variables

proxy_dict = config_obj["proxy_dict"]
baseurl = config_obj["baseurl"]

# Newton username
newton_username = config_obj['newton_username']
newton_password = config_obj['newton_password']

basedn = config_obj['basedn']
ldap_url = config_obj['ldap_url']
user_basedn = config_obj['user_basedn']
