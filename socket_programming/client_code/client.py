import socket

def send_text_file(filename, server_ip):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_ip, 65432))

    with open(filename, "w") as file:
        file.write("Please receive this \n")
    with open(filename, 'rb') as file:
        while True:
            data = file.read(1024)
            if not data:
                break
            client_socket.send(data)
    print("File sent successfully")

    client_socket.close()

# def send_pdf_file(filename, server_ip):
#     client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     client_socket.connect((server_ip, 65432))

if __name__ == "__main__":
    send_text_file('test_file.txt', '192.168.1.224')