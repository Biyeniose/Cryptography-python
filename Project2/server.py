import socket
import rsa_1
import rsa
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

def server_code():
    # generate Alice PUa and PRa
    rsa_1.generate_keys_alice()
    # create socket object with socket.socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port_num = 2005
    server_ip = "127.0.0.1"

    alice_nonce ='9$7%*349@*Alice'
    alice_id = "Alice9410922"

    # binds socket to IP addr 127.0.0.1 and port 2000
    server.bind((server_ip, port_num))
    # listen for incoming connections
    server.listen(0)
    print(f"Server listening on {server_ip}:{port_num}")

    client_socket, client_ip = server.accept()
    print(f"Connection Accepted from {client_ip[0]}:{client_ip[1]}")
    print("-----------------------------------------------------------------------------------")
    a_pubkey, a_privkey = rsa_1.a_load_keys()
    b_pubkey, b_privkey = rsa_1.b_load_keys()
    #########################################################################################

    # 1st = Alice sends IDA & NA
    msg = input("Press enter for Alice to send IDA and NA: ")
    print("-----------------------------------------------------------------------------------")
    delimiter = "|"
    message = f"{alice_id}{delimiter}{alice_nonce}"
    client_socket.sendall(message.encode('utf-8'))

    # receive Nb and E(Na)
    
    #b_nonce = client_socket.recv(1024).decode("utf-8")
    b_nonce = client_socket.recv(1024) # Nb
    encr_Na = client_socket.recv(1024) # encrypted Na
    print("RECEVIED")
    print("Bob nonce Nb = ")
    print(b_nonce)
    print("")
    print("Encrypted Na using Alice Public Key = ")
    print(encr_Na)
    print("")
    # decrypt message
    decr_Na = rsa_1.decrypt(encr_Na, a_privkey)
    print("Decrypted Na using Alice Private Key = ")
    print(decr_Na)
    print("-----------------------------------------------------------------------------------")

    # now send back the Nb with PUb
    msg = input("Press enter for Alice to send encrypted Nb : ")
    encr_Nb = rsa_1.encrypt(b_nonce.decode("utf-8"), b_pubkey)
    client_socket.sendall(encr_Nb)

    server.close()
    print("Client closed")



if __name__ == '__main__':
    server_code()


