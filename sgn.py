#!/usr/bin/python3

import hash
import rsa
import argparse
from collections import deque


md5 = hash.MD5()


def int_to_bytearray(a):
    x = deque()
    while a:
        x.appendleft(a & 0xff)
        a >>= 8
    return bytearray(x)


def generate(args):
    public, private = rsa.get_key_pair(256)
    with open(args.file + '_public', 'w+') as f:
        f.write(str(public))
    with open(args.file + '_private', 'w+') as f:
        f.write(str(private))


def sign(args):
    with open(args.file, 'rb') as f:
        message = bytearray(f.read())
        _hash = int_to_bytearray(md5.md5_digest(message))
        print(_hash)
    with open(args.private_key, 'r') as f:
        private = rsa.PrivateKey.fromstring(f.readline().replace('\n', ''))
    with open(args.file, 'ab') as f:
        f.write(private.decrypt(_hash))


def validate(args):
    with open(args.file, 'rb') as f:
        _file = f.read()
        probably_sign = bytearray(_file)[-32:]
        message_body = bytearray(_file)[:-32]
    with open(args.public_key, 'r') as f:
        public = rsa.PublicKey.fromstring(f.readline().replace('\n', ''))
    required_hash = public.encrypt(probably_sign)
    hashed_body = int_to_bytearray(md5.md5_digest(message_body))
    print('Sign is valid' if hashed_body == required_hash else 'Sign is invalid')


def unsign(args):
    with open(args.file, 'rb') as f:
        _file = bytearray(f.read())[:-32]
    with open(args.file, 'wb') as f:
        f.write(_file)

parser = argparse.ArgumentParser()

subparsers = parser.add_subparsers()

generate_keys = subparsers.add_parser('generate')
generate_keys.add_argument('-f', '--file', required=True, type=str)
generate_keys.set_defaults(func=generate)

sign_file = subparsers.add_parser('sign')
sign_file.add_argument('-f', '--file', required=True, type=str)
sign_file.add_argument('-k', '--private-key', required=True, type=str)
sign_file.set_defaults(func=sign)

validate_sign = subparsers.add_parser('validate')
validate_sign.add_argument('-f', '--file', required=True, type=str)
validate_sign.add_argument('-k', '--public-key', required=True, type=str)
validate_sign.set_defaults(func=validate)

remove_sign = subparsers.add_parser('unsign')
remove_sign.add_argument('-f', '--file', required=True, type=str)
remove_sign.add_argument('-k', '--public-key', type=str)
remove_sign.set_defaults(func=unsign)

args = parser.parse_args()

args.func(args)
