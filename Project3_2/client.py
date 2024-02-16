import socket
import RSA_code
from datetime import datetime, timedelta


def client_code():
    # generate and save Bob keys
    RSA_code.generate_keys_bob()
    # create socket object
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_port = 2104
    server_ip = "127.0.0.1" 

    # establish connection with server
    client.connect((server_ip, server_port))
    a_pubkey, a_privkey = RSA_code.a_load_keys()
    b_pubkey, b_privkey = RSA_code.b_load_keys()
    #bob_nonce = RSA_code.generate_nonce()
    #############################################################################################

    # first Bob encrypts NB then sends to Alice
    msg = input("Press enter to ask Alice for signature: ")
    print("")
    # DISPLAY TIMESTAMP
    curr_time = RSA_code.get_current_time()
    print(f"Bob Start Time = {curr_time}")

    # encrypt the nonce and send it
    # encr_NB = RSA_code.encrypt(bob_nonce, a_pubkey)
    client.sendall(b'Alice please send the Message with Signature')
    print("---------------------------------------------------------------------------")

    # receive signature from Alice
    # bob_nonce = RSA_code.generate_nonce()
    delimiter = b'||'
    alice_msg = client.recv(1024)
    alice_time, msg, sig = alice_msg.split(delimiter)

    print("RECEIVED")
    print("AUTHENTICATION PROTOCOL >> Message and Signature NEED TO BE AUTHENTICATED by the Timestamp")
    print("")
    print("Message from Alice = ")
    print(alice_msg)
    print("")
    # verify the signature
    if RSA_code.verify(msg.decode('utf-8'), a_pubkey, sig):
        print("Signature VERIFIED")
        print(f"Alice original message = {msg.decode('utf-8')}")
    else:
        print('Signature NOT VERIFIED')

    print("")
    print("TIMESTAMP AUTHENTICATION >>>>")

    # compare the timestamps
    b_time = datetime.strptime(curr_time, "%Y-%m-%d %H:%M:%S")
    a_time = datetime.strptime(alice_time.decode("utf-8"), "%Y-%m-%d %H:%M:%S")
    # see if the time is ok
    is_time_good = RSA_code.compare_timestamps(b_time, a_time)

    if(is_time_good == True):
        print("AUTHENTICATED !!!!")
        print("AUTHENTICATION is fine, the timestamps match up")
        print(f"Timestamp of sent message was = {a_time}")
    else:
        print("NOT AUTHENTICATED")
        print("The TIMESTAMPS ARE TOO FAR APART")
        print(f"Timestamp of sent message was = {a_time}")

    print("")
    client.close()
    print("Server connection closed")

if __name__ == '__main__':
    client_code()