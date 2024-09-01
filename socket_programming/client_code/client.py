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
    
    try: 

        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            client_socket.connect((server_ip, 12345))
            server_msg = f"{command}|{filename}"
            client_socket.sendall(server_msg.encode())                                      # send server message 
        except socket.gaierror:
            print("Error: Invalid server IP. Exiting.")                                     # invalid format case 
            return

        # handle initial server response
        
        if command == 'STORE':

            while True: 
                server_resp = client_socket.recv(1024).decode('utf-8')                      # collect initial response from server 
                if (server_resp == 'OVERWRITE') or (server_resp == 'READY'): 
                    break
            
            # handle file overwriting case

            if server_resp == 'OVERWRITE':                                                  # detect overwriting
                while True:
                    user_input = input("File already exists. Overwrite? [y/n] ")            # prompt user on action
                    if user_input == 'n' or user_input == 'y':
                        break
                    else:
                        print ("Invalid input, try again\n")
                if user_input == 'n':
                    print("Request canceled.")
                    server_msg = "QUIT"                                                     # notify server that you quit
                    client_socket.sendall(server_msg.encode()) 
                    client_socket.close()                                                   
                    return 
                elif user_input == 'y':
                    server_msg = "ACK"                                                      # notify server that you acknowledge overwrite
                    client_socket.sendall(server_msg.encode())
                    wait_for_server_resp(client_socket, "READY")                            # check that server is ready AFTER overwrite

        # handle server response to request 

        if command == 'STORE':
            try: 
                with open(filename, 'rb') as file:
                    data = file.read()                                                      # Read the whole file
                    client_socket.sendall(data)                                             # Send all the data
                    print("File sent successfully")
            except FileNotFoundError:
                print("Error: the file you requested to store does not exist. Exiting.")    # case of invalid file name

        elif command == 'REQUEST':
            wait_for_server_resp(client_socket, "READY")                                    # check that server is ready for request
            try: 
                json_list = client_socket.recv(4096).decode('utf-8')
                wait_for_server_resp(client_socket, "OPTIONS")                              # wait for server to return search options
                options = json.loads(json_list)                                             # decode sent options into local array 
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
                            print("Please choose one of the numbers above.")                # case of non-int input

                    server_msg = user_input                                                 # send chosen number as server message
                    client_socket.sendall(server_msg.encode())                              # send server message 
                    if int(user_input) > len(options):                                      # chose N/A option    
                        print("Sorry we couldn't find your file :(")
                    else: 
                        with open(os.path.join('client-code/', (options[int(user_input)-1]).replace('/', '_', 1)), 'wb') as file: 
                            while True: 
                                data = client_socket.recv(1024)
                                if not data:
                                    break
                                file.write(data)
                            print("File received successfully")
                else: 
                    print("Error: File not found in server. Exiting.")
            except json.decoder.JSONDecodeError:
                print("No matching results in server. Exiting.")
    
        #close connection

        client_socket.close()
        
    except ConnectionError: 
        print("Connection Error. Exiting.")

def wait_for_server_resp(client_socket, resp):                                              # helper function that polls for specific server response
    resp_len = len(resp)
    while True:
        server_resp = client_socket.recv(resp_len).decode('utf-8')
        if resp in server_resp:
            break

if __name__ == "__main__":
    server_request(sys.argv[1], sys.argv[2], sys.argv[3])