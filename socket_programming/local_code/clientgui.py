import tkinter as tk
import subprocess
import os
import threading
import configparser
import socket 

script_dir = os.path.dirname(os.path.abspath(__file__))

try: 
    config = configparser.ConfigParser()
    config.read(os.path.join(script_dir, 'config.ini'))
    server_ip = config['local']['server_ip']
    port2 = int(config['local']['port2'])
except: 
    pass

class clientGUI(tk.Tk):
    def __init__(self, server_ip): 
        super().__init__()
        
        # main setup
        self.geometry('1200x800')
        self.title("YahavFileServer Client")

        # create static top frame
        self.init_top_frame(server_ip)

        # launch rest of GUI 
        self.launch_user_gui()

    def init_top_frame(self, server_ip):
        self.top_frame = tk.Frame(self, height=155, bg="lightblue", relief="ridge", bd=5)
        self.grid_columnconfigure(0, weight=1)
        self.top_frame.grid(column=0, row=0, sticky="ew")
        self.top_frame.pack_propagate(False)  # prevent children widgets from changing frame

        # make title label within top frame
        self.title = tk.Label(self.top_frame, text="Welcome to YFS Services!", bg="lightblue", font=('Times New Roman', 24, 'bold', 'underline'))
        self.title.pack(side="top")
        self.subtitle = tk.Label(self.top_frame, text=f'Connected to server: {server_ip}', bg="lightblue", font=('Times New Roman', 18))
        self.subtitle.pack(side="bottom")

    def launch_user_gui(self):
        self.command_frame = tk.Frame(self, height=245, bg="lightgrey", relief="ridge", bd=5)
        self.command_frame.grid(column=0, row=1, sticky="ew")
        self.command_frame.pack_propagate(False)

        self.command_label = tk.Label(self.command_frame, bg="lightgrey", text="Enter Request to Server:", font=('Times New Roman', 30))
        self.command_label.pack(side="top")

        self.command_entry = tk.Entry(self.command_frame, font=('Times New Roman', 24), width=50)
        self.command_entry.pack(pady=(45, 0))
        self.command_submit_button = tk.Button(self.command_frame, text="Submit", command=self.get_user_input, width=40, height=60)
        self.command_submit_button.pack(pady=(50, 0))  

        self.prompt_frame = tk.Frame(self, height=400, bg="lightgrey", relief="ridge", bd=5)
        self.prompt_frame.grid(column=0, row=2, sticky="ew")
        self.prompt_frame.grid_propagate(False)

        self.prompt_frame.grid_rowconfigure(0, minsize=50)
        self.prompt_frame.grid_rowconfigure(1, minsize=200)
        self.prompt_frame.grid_rowconfigure(2, minsize=50)
        self.prompt_frame.grid_rowconfigure(3, minsize=25)
        self.prompt_frame.grid_rowconfigure(4, minsize=25)
        self.prompt_label = tk.Label(self.prompt_frame, font=('Times New Roman', 30), text="Server console", bg="lightgrey")
        self.prompt_label.grid(column=0, row=0, sticky="n", pady=10)
        self.prompt_text = tk.Text(self.prompt_frame, wrap=tk.WORD, bg="white", height = 8, width=140)
        self.prompt_text.grid(column=0, row=1, sticky="nsew", padx=34)

        self.prompt_label2 = tk.Label(self.prompt_frame, font=('Times New Roman', 25), text="Enter Responses Here:", bg="lightgrey")
        self.prompt_label2.grid(column=0, row=2, sticky="nw")
        self.prompt_entry = tk.Entry(self.prompt_frame, font=('Times New Roman', 16), width=70)
        self.prompt_entry.grid(column=0, row=3)

        self.prompt_resp_submit_button = tk.Button(self.prompt_frame, text="Send", command=self.get_prompt_response, width=20)
        self.prompt_resp_submit_button.grid(column=0, row=4)

    def get_prompt_response(self):
        prompt_response = self.prompt_entry.get()
        if prompt_response:
            self.prompt_entry.delete(0, tk.END)
        # add more functionality here when tried on actual client machine
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
    gui = clientGUI(server_ip)
    gui.mainloop()
