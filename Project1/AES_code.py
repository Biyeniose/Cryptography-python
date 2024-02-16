from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def encrypt(plaintext):
    key = b'This is a key123'
    # Ensure the key is the correct length, AES requires keys of 16, 24, or 32 bytes
    aes_cipher = AES.new(key, AES.MODE_ECB)
    # Pad the plaintext to be a multiple of the block size
    padded_plaintext = pad(plaintext, AES.block_size)
    # Encrypt
    ciphertext = aes_cipher.encrypt(padded_plaintext)
    return ciphertext

def decrypt(ciphertext):
    key = b'This is a key123'
    aes_cipher = AES.new(key, AES.MODE_ECB)
    # Decrypt
    decrypted_padded_plaintext = aes_cipher.decrypt(ciphertext)
    # Unpad the plaintext
    plaintext = unpad(decrypted_padded_plaintext, AES.block_size)
    return plaintext

#nonce, cipher_text, tag = encrypt(input('Enter a message: '))

#plaintext = decrypt(nonce, cipher_text, tag)

#print(f'Cipher text: {cipher_text}')

#if not plaintext:
#    print('Message is corrupted')
#else:
#    print(f'Plain text: {plaintext}')
#    print(f'Nonce: {nonce}')
#    print(f'Tag: {tag}')