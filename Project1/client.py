import socket
import AES_code

def client_code():
    # create socket object
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_port = 2100
    server_ip = "127.0.0.1" 
    
    key = b'This is a key123'
    shared_key = key.hex()

    nonce = b'\x15\x81\xb672\xa3\xdc\xe5b\xca2\xda\xd8\r+\x8d'
    bob_nonce ='1%09477@@$%Bob'

    bob_id = "0847182Bob"

    # establish connection with server
    client.connect((server_ip, server_port))

    # Bob receives IDA & NA
    response = client.recv(1024).decode("utf-8")

    print(f"Alice message: ")
    delimiter = "|"
    alice_id, alice_nonce = response.split(delimiter)

    print(f"Alice ID = {alice_id}")
    print(f"Alice nonce = {alice_nonce}")
    print("---------------------------------------------------------------------------")

    # 2nd step for Bob sending 
    msg = input("Press for Bob to send message: ")
    bob_id_encrypt = AES_code.encrypt(bob_id.encode('utf-8'))
    a_nonce_encrypt = AES_code.encrypt(alice_nonce.encode('utf-8'))

    print(f"SENT Bob ID Encrypted: {bob_id_encrypt}")
    print(f"SENT Alice Nonce Encrypted: {a_nonce_encrypt}")
    print("-------------------------------------------------------------------")
    print("")

    message = f"{bob_nonce}{delimiter}{bob_id_encrypt.hex()}{delimiter}{a_nonce_encrypt.hex()}"
    client.sendall(message.encode("utf-8")[:1024])    

    # 3rd = Bob receives and decrypts message
    response = client.recv(1024).decode("utf-8")

    print(f"RECEIVED Alice Encrypted: ")
    delimiter = "|"
    id_a, nonce_bob  = response.split(delimiter)

    recv_bytes_id_a = bytes.fromhex(id_a)
    recv_bytes_nonce_b = bytes.fromhex(nonce_bob)

    print(f"Alice Encrypted ID = {recv_bytes_id_a}")
    print(f"Bob Encrypted Nonce = {recv_bytes_nonce_b}")
    print("-------------------------------------------------------------------")
    print("")

    print("RECEIVED Alice Decrypted")
    id_a_dec = AES_code.decrypt(recv_bytes_id_a)
    b_nonce_dec = AES_code.decrypt(recv_bytes_nonce_b)
    print(f"Alice Decrypted ID = {id_a_dec.decode('utf-8')}")
    print(f"Bob Decrypted Nonce = {b_nonce_dec.decode('utf-8')}")

    # close client socket (connection to the server)
    client.close()
    print("Server connection closed")

if __name__ == '__main__':
    client_code()