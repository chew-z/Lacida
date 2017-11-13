#!/usr/bin/env python3
# In short it is private and secure way of sending messages
# from Mac (or not Mac) to iPhone. My iPhone in this case but you
# can send messages to friends etc.
# No 3-rd party aka Apple or Facebook involved and no backdoors
# open to state agents. Just Python code that you can verify yourself..

# It is encrypting a file with AES, putting encrypted ile on Google Drive 
# and sending Pushover notification with link to Editorial workflow
# that will get encrypted file from GDrive and decrypt.

# You will need Editorial app on iPhone (it is a note-taking app with Python support)
# http://omz-software.com/editorial/
# And my Editorial Workflow for decrypting on iPhone
# http://www.editorial-workflows.com/workflow/5833682849890304/xu7eKvr4GJM
# You can review Python code inside workflow.
# And you will need Pushover API (https://pushover.net) token stored in keychain.
# And also need authorized gdrive app (https://github.com/prasmussen/gdrive)
# And perhaps store default encryption key in keychain (or pass as a parameter)
# security add-internet-password ... ....

import sys
import os
import logging
import argparse
import subprocess
import urllib
import http.client
import base64
import hashlib
import re

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util import Counter


class AESCipher(object):
    """
    classical AES Cipher. Can use any size of data and any size of password thanks to padding.
    Also ensure the coherence and the type of the data with a Unicode to byte converter.
    """

    def __init__(self, key):
        self.bs = 32
        self.key = hashlib.sha256(AESCipher.str_to_bytes(key)).digest()
        # AES.MODE_CBC i AES.MODE_CTR is recommended - CTR requires counter
        # CFB doen't have any restriction on plaintext and ciphertext lengths
        self.mode = AES.MODE_CFB
        # self.mode = AES.MODE_CTR
        if self.mode == AES.MODE_CTR:
            self.ctr = Counter.new(128)

    @staticmethod
    def str_to_bytes(data):
        u_type = type(b''.decode('utf8'))
        if isinstance(data, u_type):
            return data.encode('utf8')
        return data

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * \
            AESCipher.str_to_bytes(chr(self.bs - len(s) % self.bs))

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]

    def encrypt(self, raw):
        raw = self._pad(AESCipher.str_to_bytes(raw))
        iv = Random.new().read(AES.block_size)
        if self.mode == AES.MODE_CTR:
            cipher = AES.new(self.key, self.mode, iv, self.ctr)
        else:
            cipher = AES.new(self.key, self.mode, iv)
        # return base64.b64encode(iv + cipher.encrypt(raw)).decode('utf-8')
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        if self.mode == AES.MODE_CTR:
            cipher = AES.new(self.key, self.mode, iv, self.ctr)
        else:
            cipher = AES.new(self.key, self.mode, iv)
        # return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')
        return self._unpad(cipher.decrypt(enc[AES.block_size:]))


def read_from_clipboard():
    if sys.version_info >= (3, 0):
        return subprocess.getoutput('pbpaste')
    else:
        import commands
        return commands.getoutput('pbpaste')


def get_keychain_pass(account=None, server=None):
    # I personally store default encryption key in keychain, safer then commandline history
    # Also Pushover API and Token
    params = {
        'security': '/usr/bin/security',
        'command': 'find-internet-password',
        'account': account,
        'server': server
    }
    command = "%(security)s %(command)s -g -a %(account)s -s %(server)s -w" % params
    # logging.info(command)
    try:
        password = subprocess.getoutput(command)
        return password
    except Exception:
        logging.exception('Could not get password from keychain')
        raise


def put_at_gdrive(file='/tmp/encrypted.txt', folder='0B6bDWSes13yNTDRGdnpPNWZLNUU'):
    # Place encrypted file in Public (to avoid logging in) folder on Google Drive
    # and return downloadable link.
    # To see Public folder code do 'gdrive list' and 'gdrive help' for more info
    params = {
        'command': '/usr/local/bin/gdrive',
        'parent': folder,
        'file': file
    }
    command = "%(command)s upload --parent %(parent)s --no-progress --share %(file)s" \
        % params
    logging.info(command)
    try:
        result = subprocess.getoutput(command)
        match = re.search('https://.*export=download', result)
        s = match.start()
        e = match.end()
        link = result[s:e]
        logging.info(link)
        return link
    except Exception:
        logging.exception('Could not put file at GDrive')
        raise


def send_to_iPhone(link):
    # send x-callback-url that will trigger Editorial workflow
    # which will download and decrypt file
    encoded_link = 'editorial://?command=GDrive%20Decrypt%202&input=' + \
        urllib.parse.quote(link)
    pushover = {}
    pushover['token'] = get_keychain_pass('Python', server='pushover.net')
    pushover['user'] = get_keychain_pass('Token', server='pushover.net')
    pushover['device'] = 'YOUR DEVICE NAME in Pushover'
    pushover['title'] = 'From: Macbook'
    pushover['message'] = 'You have new encrypted message'
    pushover['url'] = encoded_link
    logging.info(pushover)

    conn = http.client.HTTPSConnection("api.pushover.net:443")
    conn.request("POST", "/1/messages.json",
                 urllib.parse.urlencode(pushover), {"Content-type": "application/x-www-form-urlencoded"})
    conn.getresponse()


def getArgs(argv=None):
    # Command line argumentu.
    parser = argparse.ArgumentParser(description='Decrypts and encrypts with AES',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-k', '--key',
                        help='Optional encryption key (default from keychain)')
    parser.add_argument('-i', '--infile', nargs='?',
                        help='Infile for encryption/decryption. Clipboard if empty.')
    parser.add_argument('-o', '--outfile', nargs='?', default='/tmp/encrypted.txt',
                        help='Outfile for encryption/decryption.')
    return parser.parse_args(argv)


if __name__ == '__main__':
    FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
    try:
        os.remove('encrypt2iPhone.log')
    except BaseException:
        pass
    logging.basicConfig(filename='encrypt2iPhone.log', level=logging.DEBUG,
                        format=FORMAT, datefmt='%a, %d %b %Y %H:%M:%S',)
    logging.info('--- encrypt2iPhone.py logging started ---.')

    args = getArgs()
    logging.info(args)

    try:
        # encryption key is either passed as argument or stored in keychain
        if args.key is not None:
            key = args.key
            cipher = AESCipher(key)
        else:
            key = get_keychain_pass('key', server='encrypt.decrypt')
            cipher = AESCipher(key)
        # if no file is specified encrypt clipboard
        if args.infile is not None:
            infilename = args.infile
            logging.info(infilename)
            with open(infilename, 'rb') as fi:
                input = fi.read()
        else:
            input = read_from_clipboard()
        # encrypt
        encrypted = cipher.encrypt(input)
        output = encrypted
        # write out to file
        outfilename = args.outfile
        logging.info(outfilename)
        with open(outfilename, 'wb') as fo:
            fo.write(output)
        # upload to Google Drive
        link = put_at_gdrive(file=outfilename)
        # send x-callback-url link to iPhone
        send_to_iPhone(link)

    except Exception as e:
        logging.exception("Fatal error in __main__ loop")

    logging.info('--- encrypt2iPhone.py logging completed ---')
    # erase log ?!
