import rsa
import os
from datetime import datetime, timedelta

def get_current_time():
    """
    Returns the current time.
    """
    # Get the current date and time
    now = datetime.now()
    formatted_timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
    
    # Extract and return only the time part
    return formatted_timestamp

def compare_timestamps(t1, t2):
    """
    Compares two datetime objects, t1 and t2.
    
    Returns True if t2 does not exceed t1 by more than 10 seconds.
    Returns False if t2 exceeds t1 by more than 10 seconds.
    """
    # Calculate the difference between the two timestamps
    time_difference = t2 - t1
    
    # Check if the difference is greater than 10 seconds
    if time_difference > timedelta(seconds=5):
        return False
    else:
        return True

def sign(msg, key):
    return rsa.sign(msg.encode('ascii'), key, 'SHA-1')

def verify(msg, pub_key, sig):
    try:
        return rsa.verify(msg.encode('ascii'), sig, pub_key) == 'SHA-1'
    except:
        return False

def generate_nonce(length=16):
    return os.urandom(length).hex()

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

