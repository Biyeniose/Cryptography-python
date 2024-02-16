import socket
import rsa_1
import rsa
from Crypto.PublicKey import RSA

def client_code():
    rsa_1.generate_keys_bob()
    # create socket object
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_port = 2005
    server_ip = "127.0.0.1" 

    bob_nonce = b'1%09477@@$%Bob'
    bob_id = "Bob1920847182"

    # establish connection with server
    client.connect((server_ip, server_port))
    print(f"Client Connected")
    print("-----------------------------------------------------------------------------------")
    a_pubkey, a_privkey = rsa_1.a_load_keys()
    b_pubkey, b_privkey = rsa_1.b_load_keys()
    #########################################################################################

    # 1st = Bob receives IDA & NA
    response = client.recv(1024).decode("utf-8")

    print(f"Alice message: ")
    delimiter = "|"
    alice_id, alice_nonce = response.split(delimiter)

    print(f"Alice ID = {alice_id}")
    print(f"Alice nonce Na= {alice_nonce}")
    print("-----------------------------------------------------------------------------------")

    # 2nd = Bob encrypt Na with PRb --> encrypt again with PUa --> send Nb
    msg = input("Press enter for Bob to send Nb and encrypted Na: ")
    print("-----------------------------------------------------------------------------------")
    # send non encrypted Nb
    client.sendall(bob_nonce)
    # encrypt Na with PUa
    encra_NA = rsa_1.encrypt(alice_nonce, a_pubkey)
    client.sendall(encra_NA)

    # receive encrypted Nb from Alice
    encr_Nb = client.recv(1024)
    print("RECEVIED")
    print("Encrypted NB using Bob Public Key = ")
    print(encr_Nb)
    print("")
    # decrypt message
    decr_Nb = rsa_1.decrypt(encr_Nb, b_privkey)
    print("Decrypted NB using Alic Private Key = ")
    print(decr_Nb)

    print("-----------------------------------------------------------------------------------")
 
    client.close()
    print("Server connection closed")


if __name__ == '__main__':
    client_code()
