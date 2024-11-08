import tkinter as tk
import subprocess
import os
import threading
import configparser

script_dir = os.path.dirname(os.path.abspath(__file__))

try: 
    config = configparser.ConfigParser()
    config.read(os.path.join(script_dir, 'config.ini'))
    server_ip = config['client']['server_ip']
except: 
    pass

class clientGUI(tk.Tk):
    def __init__(self, server_ip): 
        super().__init__()
        
        # main setup
        self.geometry('1200x800')
        self.title("YahavFileServer")

        # create static top frame
        self.init_top_frame(server_ip)

        # launch rest of GUI 
        self.launch_user_gui()

    def init_top_frame(self, server_ip):
        top_frame = tk.Frame(self, height=155, bg="lightblue", relief="ridge", bd=5)
        self.grid_columnconfigure(0, weight=1)
        top_frame.grid(column=0, row=0, sticky="ew")
        top_frame.pack_propagate(False)  # prevent children widgets from changing frame

        # make title label within top frame
        title = tk.Label(top_frame, text="Welcome to YFS Services!", bg="lightblue", font=('Times New Roman', 24, 'bold', 'underline'))
        title.pack(side="top")

        subtitle = tk.Label(top_frame, text=f'Connected to server: {server_ip}', bg="lightblue", font=('Times New Roman', 18))
        subtitle.pack(side="bottom")

    def launch_user_gui(self):
        command_frame = tk.Frame(self, height=345, bg="lightgrey", relief="ridge", bd=5)
        command_frame.grid(column=0, row=1, sticky="ew")
        command_frame.pack_propagate(False)

        command_label = tk.Label(command_frame, bg="lightgrey", text="Enter Request to Server:", font=('Times New Roman', 30))
        command_label.pack(side="top")

        self.command_entry = tk.Entry(command_frame, font=('Times New Roman', 24), width=50)
        self.command_entry.pack(pady=(90, 0))
        command_submit_button = tk.Button(command_frame, text="Submit", command=self.get_user_input)
        command_submit_button.pack(pady=(100, 0))  

    def get_user_input(self):
        user_input = self.command_entry.get()
        if user_input: 
            self.command_entry.delete(0, tk.END)
            request_thread = threading.Thread(target=self.execute_request, args=(user_input,))
            request_thread.daemon = True
            request_thread.start()

    def execute_request(self, user_input):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        script_path = os.path.join(script_dir, "../../powershell_scripts/execute_request.ps1")
        target_client, server_request = user_input.split(" ", 2)[0], " ".join(user_input.split(" ", 2)[1:])
        subprocess.run(["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", script_path, target_client, server_request])

if __name__ == "__main__": 
    gui = clientGUI("192.168.1.224")
    gui.mainloop()
