#!/usr/bin/python3

import Crypto

from Crypto.Hash import SHA256 as Hash
from Crypto.Cipher import AES as Cipher
from Crypto import Random

import operator


def obs_v0(mapping):
    """ Identity Obfuscator.

        Does nothing, is not unintelligible.
    """
    def obfuscated(in_value):
        return mapping.get(in_value)

    return obfuscated

def from_bytes(val):
    if val is None:
        return None

    try:
        return int(val)
    except:
        pass

    result = 0
    m = 1
    for b in val:
        result += m*b
        m *= 256

    return result

def to_bytes(val, cnt):
    return bytes((val & (0xFF << pos*8)) >> pos*8 for pos in range(cnt))

def combine_v1(a, b):
    pad = max(len(a), len(b))
    comb = bytes(map(operator.xor, a, b))
    return comb

def obs_v1(mapping):
    """ First attempt at obfuscation.

        Not unintelligible because the attacker can easily determine
        the size of the output space.

        Clearly broken since "encrypted" is in the closure "obfuscated".
    """ 

    encrypted = {}
    for k,v in mapping.items():
        H = Hash.new()
        kb = to_bytes(k, H.digest_size*8)
        H.update(kb)

        comb = combine_v1(kb, H.digest()) 
        cipher = Cipher.new(comb)
        encrypted[comb] = cipher.encrypt(to_bytes(v, 32))

    def obfuscated(in_value):
        H = Hash.new()
        ib = to_bytes(in_value, H.digest_size*8)
        H.update(ib)
        comb = combine_v1(ib, H.digest()) 

        E = encrypted.get(comb)
        if E is not None:
            return Cipher.new(comb).decrypt(E)
        else:
            return E

    return obfuscated

def is_zero(in_value):
    if in_value == 0:
        return 1
    else:
        return 0

def poly(x):
    return 3*x^3 + 7*x^2 + 3

def self_test():
    output_sz = 65536

    obfuscators = (obs_v0, obs_v1)
    
    functions = (is_zero, poly)

    funcMaps = tuple({i: f(i) for i in range(output_sz) if f(i) is not None} for f in functions)

    for mapping in funcMaps:
        for obs in obfuscators:
            obfuscated = obs(mapping)
            for i in range(output_sz):
                oVal = from_bytes(obfuscated(i))
                correct = mapping.get(i)
                if oVal != correct:
                    print("ERROR at {}: {} != {}".format(i, oVal, correct))

if __name__ == "__main__":
    self_test()
