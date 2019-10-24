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
            password = input("\nPlease enter the password: ")
        except EOFError:
            print("Input aborted, exiting.")
            sys.exit(1)

    base64_config = """c2MAAo8u0ulexmGU83VGxhxo23/vnStqZkpst5L+A7qqwJIPgnQQCICWkREFKRXOsjwJkdYoLp5O
    mRw0CIglPXBoWn+kXW0ZobZroCfhNs+DnJA0N/P0ZMgsKTwuGoHSJXrz1Tc7nBroQRMoQtYQkCs8
    8l4/2YuMZzcbPIPyrS6S0uDvioMFOZzpG4XyIDXvoyvCWUtRTtyiVrsXsRgC5c5ZhSo9oSrGVsBZ
    CEnnU4dfI4E4uhYY7ogK/mEL7lfKR5+ivYpNxEqlNjKrexYdM8VBFNikEtgQZhfSYSkdJBSsLku0
    Bo1mllsK7h2glUq/YckIUFtup+RlMUC/lqUUYZU796U+mnyYPFFFqADZVg7C4Idj6DMR6G5IaD0I
    YDNyY4O5RyaboqiI1hOkMN8BFcKSMKJ/tGfmZRa86nomh2ok+bUO24mDl/l6lQvPEHbXVLDf80bi
    VDSB7y0c2MHBqWHv/XxKTJbcYKtBLoojQmuY1yQejNVtyWw9cDCNCOdYNFKdybvnJ+Do+uhm4xDa
    xVRNffAZ6ZB3yFJiub4E5PC6QgKIrVVihbXjkJfkfDVjlwqflZsxsgEODO1OVw==
    """

    enc_config_base64_bytes = base64_config.encode('utf8')
    enc_config_bytes = base64.decodebytes(enc_config_base64_bytes)
    try:
        config_json = decrypt(password, enc_config_bytes).decode('utf8')
        print("Decryption successful.\n")
    except DecryptionException as e:
        print('ERROR:', e)
        sys.exit(1)

    # Caching decrypted json text to file, as decryption is quite slow (>5 seconds)
    # This encryption is purely to protect internal data (COMPANY INTERNAL), not for actual "confidentiality"/"secrecy"
    open(os.path.join(os.path.dirname(__file__), 'config_decrypted.json'), mode="w").write(config_json)


config_obj = json.loads(config_json)

# End of decryption, now assign config variables

proxy_dict = config_obj["proxy_dict"]
baseurl = config_obj["baseurl"]

# Newton username
newton_username = config_obj['newton_username']
newton_password = config_obj['newton_password']

basedn = config_obj['basedn']
ldap_url = config_obj['ldap_url']
user_basedn = config_obj['user_basedn']
