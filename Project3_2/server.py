import socket
import RSA_code

# B -> A: Nonce
# A -> B: M || Nonce || Sig_A(M || Nonce)
def server_code():
    # generate and save Alice keys
    RSA_code.generate_keys_alice()
    # create socket object with socket.socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port_num = 2104
    server_ip = "127.0.0.1"

    # binds socket to IP addr 127.0.0.1 and port 2000
    server.bind((server_ip, port_num))
    # listen for incoming connections
    server.listen(0)
    print(f"Server listening on {server_ip}:{port_num}")

    client_socket, client_ip = server.accept()
    print(f"Connection Accepted from {client_ip[0]}:{client_ip[1]}")
    print("---------------------------------------------------------------------------")
    a_pubkey, a_privkey = RSA_code.a_load_keys()
    b_pubkey, b_privkey = RSA_code.b_load_keys()
    ##################################################################################################

    # receive message from Bob
    bob_sent = client_socket.recv(1024) # Nb
    print("RECEIVED")
    print(f'Bob said = {bob_sent.decode("utf-8")}')

    print("")
    print("---------------------------------------------------------------------------")
    print("")
    msg = input("Press enter for Alice to send Message + Signature to Bob: ")
    print("")
    # generate time stamp and include in the message
    alice_curr_time = RSA_code.get_current_time()

    # sign message M with Alice Priv Key (signature is in bytes)
    message = b'This is the correct message from Alice'
    signature = RSA_code.sign(message.decode('utf-8'), a_privkey)
    
    # join message and signature and timestamp
    alice_time = alice_curr_time.encode('utf-8')
    delimiter = b'||'
    combined_message = alice_time + delimiter + message + delimiter + signature

    # now send Bob message with signature attached
    #msg = input("Press enter for Alice to send Message + Signature to Bob: ")
    #print("")
    client_socket.sendall(combined_message)


    server.close()
    print("Client closed")


if __name__ == '__main__':
    server_code()
