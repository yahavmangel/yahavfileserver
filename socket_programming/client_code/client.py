import socket
import sys

def server_request(server_ip, command, filename):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    client_socket.connect((server_ip, 12346))
    server_msg = f"{command}|{filename}"
    client_socket.sendall(server_msg.encode()) # send server message 
    server_resp = client_socket.recv(1024).decode('utf-8') # collect initial response from server 
    
    while True: 
        if (server_resp == 'OVERWRITE') or (server_resp == 'READY'): 
            break
    if server_resp == 'OVERWRITE': # detect overwriting
        print(server_resp)
        while True:
            user_input = input("File already exists. Overwrite? [y/n] ") # prompt user on action
            if user_input == 'n' or user_input == 'y':
                break
            else:
                print ("Invalid input, try again")
        if user_input == 'n':
            print("Request cancelled.")
            server_msg = "QUIT" # notify server that you quit
            client_socket.sendall(server_msg.encode()) 
            client_socket.close() # close connection
        elif user_input == 'y':
            server_msg = "ACK" # notify server that you acknowledge overwrite
            client_socket.sendall(server_msg.encode())
    if not server_msg == "QUIT": 
        while True: 
            server_resp = client_socket.recv(1024).decode('utf-8')
            if (server_resp == 'READY'): 
                break
    if server_resp == 'READY': # server indicates operation is ready 
        print(server_resp)
        if command == 'STORE':
            with open(filename, 'rb') as file:
                data = file.read()  # Read the whole file
                client_socket.sendall(data)  # Send all the data
                print("File sent successfully")
                client_socket.close()
        elif command == 'REQUEST':
            print("Server requests not implemented yet")
    
    if server_msg == 'SERVFAIL': # case of no authorization? 
        print("Error sending file")
        client_socket.close()

if __name__ == "__main__":
    server_request(sys.argv[1], sys.argv[2], sys.argv[3])