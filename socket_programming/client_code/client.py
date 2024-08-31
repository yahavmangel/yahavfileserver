import socket
import sys
import json
import os

def server_request(server_ip, command, filename):

    # input validation
    
    if not (command == 'STORE' or command == 'REQUEST'):
        print("Error: invalid command")
        return 
    
    # connection setup

    cancel_flag = 0 
    
    try: 

        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            client_socket.connect((server_ip, 12345))
            server_msg = f"{command}|{filename}"
            client_socket.sendall(server_msg.encode()) # send server message 
        except socket.gaierror:
            print("Error: Invalid server IP. Exiting.")
            return

        # handle initial server response
        
        if command == 'STORE':

            while True: 
                server_resp = client_socket.recv(1024).decode('utf-8') # collect initial response from server 
                if (server_resp == 'OVERWRITE') or (server_resp == 'READY'): 
                    break
            
            # handle file overwriting case

            if server_resp == 'OVERWRITE': # detect overwriting
                while True:
                    user_input = input("File already exists. Overwrite? [y/n] ") # prompt user on action
                    if user_input == 'n' or user_input == 'y':
                        break
                    else:
                        print ("Invalid input, try again\n")
                if user_input == 'n':
                    print("Request canceled.")
                    server_msg = "QUIT" # notify server that you quit
                    cancel_flag = 1
                    client_socket.sendall(server_msg.encode()) 
                    client_socket.close() # close connection
                elif user_input == 'y':
                    server_msg = "ACK" # notify server that you acknowledge overwrite
                    client_socket.sendall(server_msg.encode())
                if not server_msg == "QUIT": 
                    wait_for_server_resp(client_socket, "READY")

        # handle server response to request 
        
        if not cancel_flag: 
            if command == 'STORE':
                try: 
                    with open(filename, 'rb') as file:
                        data = file.read()  # Read the whole file
                        client_socket.sendall(data)  # Send all the data
                        print("File sent successfully")
                except FileNotFoundError:
                    print("Error: the file you requested to store does not exist. Exiting.")
                finally: 
                    client_socket.close()

            elif command == 'REQUEST':
            
                wait_for_server_resp(client_socket, "READY")
                json_list = client_socket.recv(4096).decode('utf-8')
                try: 
                    options = json.loads(json_list)
                    if (len(options) > 0): 
                        print("Server returned multiple results: \n")
                        i = 0
                        for option in options: 
                            i += 1
                            print (str(i) + ': ' + option)
                        print (str(i + 1) + ": N/A \n")
                        while True:
                            user_input = input("Which one? ")
                            try: 
                                if(int(user_input) > 0 and int(user_input) < len(options) + 2):
                                    break
                                else: 
                                    print("Invalid choice, try again\n")
                            except ValueError: 
                                print("Please choose one of the numbers above.")

                        server_msg = user_input
                        client_socket.sendall(server_msg.encode()) # send server message 
                        if int(user_input) > len(options):
                            print("Sorry we couldn't find your file :(")
                            client_socket.close()
                        else: 
                            with open(os.path.join('client-code/', (options[int(user_input)-1]).replace('/', '_', 1)), 'wb') as file: 
                                while True: 
                                    data = client_socket.recv(1024)
                                    if not data:
                                        break
                                    file.write(data)
                                print("File received successfully")
                                client_socket.close()
                    else: 
                        print("Error: File not found in server. Exiting.")
                        client_socket.close()
                except json.decoder.JSONDecodeError:
                    print("No matching results in server. Exiting.")
                    client_socket.close()

        if server_msg == 'SERVFAIL': # case of no authorization? 
            print("Error sending file")
            client_socket.close()
        
    except ConnectionError: 
        print("Connection Error. Exiting.")

def wait_for_server_resp(client_socket, resp):
    resp_len = len(resp)
    while True:
        server_resp = client_socket.recv(resp_len).decode('utf-8')
        if resp in server_resp:
            break

if __name__ == "__main__":
    server_request(sys.argv[1], sys.argv[2], sys.argv[3])