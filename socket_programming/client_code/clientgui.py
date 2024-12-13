"""
The class implementation for the client GUI. 
It is only launched when the client script is launched in user mode. 

"""

import tkinter as tk
import threading
import queue 

class ClientGUI(tk.Tk):
    def __init__(self, server_ip, launch_request, prompt_queue, resp_queue): 
        super().__init__()
        
        # main setup
        self.geometry('1200x730')
        self.title("YahavFileServer Client")

        # create static top frame
        self.init_top_frame(server_ip)
        self.launch_request = launch_request # function that executes client request
        self.prompt_queue = prompt_queue
        self.resp_queue = resp_queue

        # launch rest of GUI 
        self.launch_user_gui()

        # start processing thread
        self.processing_thread = threading.Thread(target=self.process_prompts, daemon=True)
        self.processing_thread.start()

    def init_top_frame(self, server_ip):
        self.top_frame = tk.Frame(self, height=85, bg="lightblue", relief="ridge", bd=5)
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
        self.command_entry.pack(pady=(15, 0))
        self.command_submit_button = tk.Button(self.command_frame, text="Submit", command=self.get_user_input, width=20)
        self.command_submit_button.pack(pady=(20,0), side="top")  

        self.error_label = tk.Label(self.command_frame, font=('Times New Roman', 18), fg="red", bg="lightgrey")
        self.error_label.pack(pady=(5,0))

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
        self.prompt_text = tk.Text(self.prompt_frame, wrap=tk.WORD, bg="white", height=8, width=140)
        self.prompt_text.grid(column=0, row=1, sticky="nsew", padx=34)

        self.prompt_label2 = tk.Label(self.prompt_frame, font=('Times New Roman', 25), text="Enter Responses Here:", bg="lightgrey")
        self.prompt_label2.grid(column=0, row=2, sticky="nw")
        self.prompt_entry = tk.Entry(self.prompt_frame, font=('Times New Roman', 16), width=70)
        self.prompt_entry.grid(column=0, row=3)

        self.prompt_resp_submit_button = tk.Button(self.prompt_frame, text="Send", command=self.get_prompt_response, width=20)
        self.prompt_resp_submit_button.grid(column=0, row=4)

    def process_prompts(self):
        while True:
            try: 
                message, prompt_type = self.prompt_queue.get_nowait()  # Block until message arrives
                self.add_prompt_message(message, prompt_type)
                tries = 0
                while tries < 50:
                    message, prompt_type = self.prompt_queue.get(timeout=0.02)
                    self.add_prompt_message(message, prompt_type)
                    tries += 1
            except queue.Empty:
                pass
    def add_prompt_message(self, message, prompt_type):
        self.prompt_text.insert(tk.END, message + '\n')
        if self.prompt_text.yview()[1] == 1.0:  # Check if we're already at the bottom
            self.prompt_text.yview(tk.END)  # auto-scroll to the end

        if prompt_type == "prompt":
            self.get_prompt_response()

        if message == "Success!":
            self.after(2000, self.prompt_text.delete, '1.0', 'end')

    def get_prompt_response(self):
        # Get the response from the prompt entry field
        prompt_response = self.prompt_entry.get()
        if prompt_response:
            # Clear the entry field after fetching the response
            self.prompt_entry.delete(0, tk.END)
            # Place the response directly in the main response queue
            self.resp_queue.put(prompt_response)


    def get_user_input(self):
        user_input = self.command_entry.get()
        if user_input:
            self.command_entry.delete(0, tk.END)
            try: 
                command, filename = (user_input.split(" ", 2)[0], user_input.split(" ", 2)[1])
                if command not in ['STORE', 'REQUEST']:
                    self.display_error("Error: Invalid Command")
                    return
                self.error_label.config(text="")        # valid request, so you can clear the error message!
                request_thread = threading.Thread(target=self.launch_request, args=(command, filename))
                request_thread.daemon = True
                request_thread.start()
            except IndexError:
                self.display_error("Error: Invalid Input")

    def display_error(self, error_msg):
        self.error_label.config(text=error_msg)
