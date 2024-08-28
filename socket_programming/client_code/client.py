import socket

def server_request(filename, server_ip, command):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, 12347))

    server_msg = f"{command}|{filename}"
    client_socket.sendall(server_msg.encode()) # send server message 
    server_resp = client_socket.recv(1024).decode('utf-8') # collect initial response from server 

    if server_resp == 'OVERWRITE': # detect overwriting
        user_input = input("File already exists. Overwrite? [y/n] ") # prompt user on action
        if user_input == 'n':
            print("Request cancelled.")
            server_msg = "QUIT" # notify server that you quit
            client_socket.sendall(server_msg.encode()) 
            client_socket.close() # close connection
        elif user_input == 'y':
            server_msg = "ACK" # notify server that you acknowledge overwrite
            client_socket.sendall(server_msg.encode())
    
    if server_resp == 'READY': # server indicates operation is ready 
        if command == 'STORE':
            with open(filename, 'rb') as file:
                data = file.read()  # Read the whole file
                client_socket.sendall(data)  # Send all the data
                print("File sent successfully")
        elif command == 'REQUEST':
            print("Server requests not implemented yet")
    
    if server_msg == 'SERVFAIL': # case of no authorization? 
        print("Error sending file")
    client_socket.close()

if __name__ == "__main__":
    server_request('ye.png', '192.168.1.224', 'STORE')