import rsa

def generate_keys_alice():
    (pubkey, privkey) = rsa.newkeys(1024)
    with open('a_keys/pubkey.pem', 'wb') as f:
        f.write(pubkey.save_pkcs1("PEM"))

    with open('a_keys/privkey.pem', 'wb') as f:
        f.write(privkey.save_pkcs1("PEM"))

def generate_keys_bob():
    (pubkey, privkey) = rsa.newkeys(1024)
    with open('b_keys/pubkey.pem', 'wb') as f:
        f.write(pubkey.save_pkcs1("PEM"))

    with open('b_keys/privkey.pem', 'wb') as f:
        f.write(privkey.save_pkcs1("PEM"))

def a_load_keys():
    with open('a_keys/pubkey.pem', 'rb') as f:
        pubkey = rsa.PublicKey.load_pkcs1(f.read())

    with open('a_keys/privkey.pem', 'rb') as f:
        privkey = rsa.PrivateKey.load_pkcs1(f.read())

    return pubkey, privkey

def b_load_keys():
    with open('b_keys/pubkey.pem', 'rb') as f:
        pubkey = rsa.PublicKey.load_pkcs1(f.read())

    with open('b_keys/privkey.pem', 'rb') as f:
        privkey = rsa.PrivateKey.load_pkcs1(f.read())

    return pubkey, privkey

def encrypt(msg, key):
    return rsa.encrypt(msg.encode('ascii'), key)

def decrypt(ciph, key):
    try:
        return rsa.decrypt(ciph, key).decode('ascii')
    except:
        return False