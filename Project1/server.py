import socket
import AES_code

def server_code():
    # create socket object with socket.socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port_num = 2100
    server_ip = "127.0.0.1"

    key = b'This is a key123'
    shared_key = key.hex()

    alice_nonce ='9$7%*349@*Alice'
    alice_id = "Alice942"

    # binds socket to IP addr 127.0.0.1 and port 2000
    server.bind((server_ip, port_num))
    # listen for incoming connections
    server.listen(0)
    print(f"Server listening on {server_ip}:{port_num}")

    client_socket, client_ip = server.accept()
    print(f"Connection Accepted from {client_ip[0]}:{client_ip[1]}")
    print("---------------------------------------------------------------------------")

    # 1st = Alice sends IDA & NA
    msg = input("Press enter for Alice to send message: ")
    print("")
    delimiter = "|"
    message = f"{alice_id}{delimiter}{alice_nonce}"
    client_socket.sendall(message.encode('utf-8'))

    # 2nd = receive the Bob data, decrypt and display
    request_client = client_socket.recv(1024).decode("utf-8")
    print(f"RECEIVED Client Encrypted: ")
    delimiter = "|"
    bob_nonce, bob_id_enc, a_nonce_enc = request_client.split(delimiter)

    recv_bytes_bob_id = bytes.fromhex(bob_id_enc)
    recv_bytes_a_nonce = bytes.fromhex(a_nonce_enc)

    print(f"Bob Nonce = {bob_nonce}")
    print(f"Bob Encrypted ID = {recv_bytes_bob_id}")
    print(f"Alice Encrypted Nonce = {recv_bytes_a_nonce}")

    print("-------------------------------------------------------------------")
            
    print("Client Decrypted")
    bob_id_dec = AES_code.decrypt(recv_bytes_bob_id)
    a_nonce_dec = AES_code.decrypt(recv_bytes_a_nonce)
    print(f"Bob Decrypted ID = {bob_id_dec.decode('utf-8')}")
    print(f"Alice Decrypted Nonce = {a_nonce_dec.decode('utf-8')}")
    print("-------------------------------------------------------------------")

    # Step 3
    msg = input("Press enter for Alice to send message: ")
    alice_id_enc = AES_code.encrypt(alice_id.encode("utf-8"))
    b_nonce_enc = AES_code.encrypt(bob_nonce.encode("utf-8"))
    delimiter = "|"
    message = f"{alice_id_enc.hex()}{delimiter}{b_nonce_enc.hex()}"
    client_socket.sendall(message.encode('utf-8'))

    #client_socket.close()
    #print("Client Connection closed")
    server.close()
    print("Client closed")


if __name__ == '__main__':
    server_code()