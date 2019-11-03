# Elliptic curve y² = x³ + ax + b
#
# P + Q = R
# s = (Py - Qy)/(Px - Qx)
# Rx = s² -(Px + Qx)
# Ry = s(Px - Rx) - Py
#
# 2P = R
# s = (3Px² + a)/2Py
# Rx = s² - 2Px
# Ry = s(Px - Rx) - Py
#
# For signing functions, the next reference
# was used:
# https://cryptobook.nakov.com/digital-signatures/ecdsa-sign-verify-messages
#
# CURVE PARAMETERS
a = 2
b = 2
p = 17
G = (5, 1)
n = 19
bits = 24


# p = (2**128-3)//76439
# a = int('0xDB7C2ABF62E35E668076BEAD2088', 0)
# b = int('0x659EF8BA043916EEDE8911702B22', 0)
# G = (int('0x09487239995A5EE76B55F9C2F098', 0),
#      int('0xA89CE5AF8724C0A23E0E0FF77500', 0))
# n = int('0xDB7C2ABF62E35E7628DFAC6561C5', 0)
# bits = 112

p = int("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 0)
a = 0
b = 7
G = (int("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 0),
     int("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 0))
n = int("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 0)
bits = 256

print('p ', p)
print('a ', a)
print('b ', b)
print('Gx ', G[0])
print('Gy ', G[1])
print('n ', n)

from math import log2
import hashlib

def mod_mult_inv(n, p=p):
    a, b = p, n%p
    if 0 == b:
        return None
    qs = []
    while b != 0:
        qs[:0] = [a//b]
        a, b = b, a-qs[0]*b
    x, y = 1, 1
    for q in qs:
        x, y = -x*q + y, x
    return x%p

def add(P: tuple, Q: tuple) -> tuple:
    if P == Q:
        return times2(P)
    Px, Py = P
    Px, Py = Px%p, Py%p # (mod p)
    Qx, Qy = Q
    Qx, Qy = Qx%p, Qy%p # (mod p)
    try:
        s = (((Py-Qy)%p)*mod_mult_inv(Px-Qx))%p
    except:
        return None
    # print("s:", s)
    Rx = int(((s*s)%p-(Px+Qx)%p)%p)
    Ry = int((s*(Px-Rx)-Py)%p)
    return Rx, Ry

def times2(P):
    Px, Py = P
    Px, Py = Px%p, Py%p
    s = (((3*Px*Px+a)%p)*mod_mult_inv(2*Py))%p
    # print("s:", s, "(2Py)⁻¹(mod p):", mod_mult_inv(2*Py))
    Rx = int(((s*s)%p-2*Px)%p)
    Ry = int((s*(Px-Rx)-Py)%p)
    return Rx, Ry

def powers(P):
    limit_pow = int(log2(n))+1
    P2s = [P]
    for i in range(1, limit_pow):
        P2s.append(times2(P2s[-1]))
    return P2s

G2s = powers(G)

def times_k(k, G=G):
    if k == 1:
        return G
    Pub = times2(G)
    if k == 2:
        return Pub
    for i in range(2,k):
        Pub = add(Pub, G)
        # print("pub:", Pub)
    return Pub

def fast_times(number: int,
               generator: tuple=G
               ) -> tuple:
    """
    Returns the resulting point when multiplying
    the given generator times the received number.
    """
    number %= n
    if number == 0:
        return None
    
    if not generator == G:
        P2s = powers(generator)
    else:
        P2s = G2s
        
    m, i, adding = number, 0, []
    while m:
        if m & 1:
            adding.append(P2s[i])
        m >>= 1
        i += 1
    Q = adding.pop()
    while adding:
        Q = add(Q, adding.pop())
    return Q

# SIGNING (ECDSA) FUNCTIONS

def signing_k(how):
    from random import randint
    selector = {
        'random' : randint(1, n-1),
        'half' : n//2
    }
    return selector[how]

def sign_hash(hash, key, generator=G, prime=p):
    k = 2 # signing_k('half')
    inv_k = mod_mult_inv(k, p=n)
    R = fast_times(k)
    print("R:\n\t", R)
    r = R[0]
    print('hash*G:\n\t', fast_times(hash))
    print('(r*privKey)*G:\n\t', fast_times(r*key))
    s = (inv_k*(hash+r*key))
    print("s ", s)
    s %= n

    return r, s

def verify_sign_hash(hash, 
                     pubKey, 
                     signature, 
                     generator=G, 
                     prime=p):
    r, s = signature
    inv_s = mod_mult_inv(s, p=n)
    P = fast_times((hash*inv_s)%n)
    print('P:\n\t', P)
    Q = fast_times((r*inv_s)%n, pubKey)
    print('Q:\n\t', Q)
    R_ = add(P, Q)
    print("R_:\n\t", R_)
    return R_[0] == r

def tup2bytes(tup):
    out = b""
    for el in tup:
        out += el.to_bytes(bits//8, 'big')
    return out

if __name__ == "__main__":
    from time import time
    from hashlib import sha3_256 as sha3

    guide = {}
    # for i in range(1, n):
    #     guide[fast_times(i)] = i

    REPEAT = 3
    OFFSET = n//2
    RANGO = (OFFSET, OFFSET+REPEAT)

    s = time()
    for number in range(*RANGO):
        Q = fast_times(number)
        print(number, Q)

    print((time()-s)/REPEAT)

    msg = "signature!"
    sign_msg = b"\x19Ethereum Signed Message:\n" \
            + str(len(msg)).encode('utf8') \
            + msg.encode('utf8')
    print(msg)
    hash_ = int('0x'+sha3(sign_msg).hexdigest(), 0)
    pk = int(4e0)
    pubKey = fast_times(pk)
    signature = sign_hash(hash_, pk)
    validation = verify_sign_hash(hash_, pubKey, signature)
    print("signature:\n\t", signature)
    print("valid: ", validation)

    pubKey_bytes = tup2bytes(tup2bytes(pubKey))
    address = '0x'+sha3(pubKey_bytes).digest()[-20:].hex()
    print("hexas")
    print("address\n", address)
    print("signature\n0x00",tup2bytes(signature).hex())    

    '''
    print("\nTests:")
    priv = 15
    pubKey = fast_times(priv)
    hash = 15
    k = 11
    R = fast_times(k)
    r = R[0]
    inv_k = mod_mult_inv(k)
    sk = (hash+r*priv)
    s = (inv_k*sk)%p
    print(k, inv_k, sk, s)
    print('r:',r)
    inv_s = mod_mult_inv(s)
    ra = (hash*inv_s)%p
    rb = (r*inv_s)%p
    P = fast_times(ra)
    Q = times_k(rb, pubKey)
    print(times_k(rb, pubKey) == fast_times(rb, pubKey))
    Q_ = fast_times((rb*priv)%p)
    R_ = add(P, Q)
    print(ra, rb, (rb*priv)%p, (ra+rb)%p)
    print(P, Q, Q_, R_)
    # print(guide.get(Q), guide.get(Q_))

    print("\nadd test:")
    B = fast_times(3)
    for i in range(5):
        B = add(B, B)
        # print(B, guide.get(B))

    # print("\nTest fast_times function:")
    # P = fast_times(4)
    # Q = fast_times(12)
    # S = fast_times(3, P)
    # print(P, Q, S)'''