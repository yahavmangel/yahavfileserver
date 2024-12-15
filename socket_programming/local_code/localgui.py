import tkinter as tk
from tkinter import ttk
import subprocess
import threading
import queue 
import os

class localGUI(tk.Tk): 

    def __init__(self, log_queue, prompt_queue, resp_queue, event_arr, static_info_dict):
        super().__init__()
        
        # main setup
        self.geometry('1200x800')
        self.title("YahavFileServer")
        self.grid_propagate(False)
        
        # initialize queues
        self.log_queue = log_queue
        self.prompt_queue = prompt_queue 
        self.resp_queue = resp_queue

        #initialize metadata
        self.log_src_arr = ["Aggregate"]
        self.log_text_arr = [tk.Text()]
        self.cur_display_idx = 0
        self.prev_display_idx = -1
        self.event_arr = event_arr

        self.init_top_frame(static_info_dict)

        self.notebook = ttk.Notebook(self)
    
        # create 3 main frames w/ static top frame

        self.log_frame = tk.Frame(self.notebook)
        self.dev_frame = tk.Frame(self.notebook)
        self.test_frame = tk.Frame(self.notebook)

        # create rest of GUI 
        self.launch_log_frame()
        self.launch_dev_frame()
        self.launch_test_frame()

        self.log_frame.grid(sticky="nsew", columnspan=2)
        self.dev_frame.grid(sticky="nsew", columnspan=2)
        self.test_frame.grid(sticky="nsew", columnspan=2)

        self.notebook.add(self.log_frame, text="Log View")
        self.notebook.add(self.dev_frame, text="Dev View") 
        self.notebook.add(self.test_frame, text="Test View")

        self.notebook.grid(columnspan=2)

        # start log processing
        self.processing_thread = threading.Thread(target=self.process_prompts, daemon=True)
        self.processing_thread.start()

    def init_top_frame(self, static_info_dict):

        # initialize top frame dimensions
        self.grid_columnconfigure(0, minsize=252)
        self.grid_columnconfigure(1, minsize=600)
        self.top_frame = tk.Frame(self, width=1200, height=155, bg="lightblue", relief="ridge", bd=5)
        self.top_frame.grid(row=0, column=0, columnspan=2, sticky="ew")
        self.top_frame.grid_propagate(False)  # prevent children widgets from changing frame

        # set first 2 columns of top frame to have equal weight 
        self.top_frame.columnconfigure(0, weight=1)
        self.top_frame.columnconfigure(1, weight=1) 

        # make title label within top frame
        title = tk.Label(self.top_frame, text="Welcome to YFS Services!", bg="lightblue", font=('Times New Roman', 24, 'bold', 'underline'))
        title.grid(row=0, column=0, columnspan=2)

        # display information in two columns within top_frame
        for idx, (key, value) in enumerate(static_info_dict.items()):
            row = (idx % 3) + 1 # 3 items per column
            col = idx // 3      # switch to new column after 3 items

            label_text = f"{key}: {value}"
            label = tk.Label(self.top_frame, text=label_text, bg="lightblue", anchor="w", font=('Times New Roman', 16, 'bold'))
            label.grid(row=row, column=col, padx=(100, 10), sticky="w")
        
        # make quit button 
        quit_button = tk.Button(self.top_frame, text="Quit", command=self.quit_gui)
        quit_button.grid(column=2, row=0, sticky="nsew")

        # make and run status display
        self.status_text_arr = ["Launching VMs...", "Connecting to server...", "Connected!"]
        self.status_label = tk.Label(self.top_frame, text=self.status_text_arr[0])
        self.status_label.grid(column=2, row=1, sticky="nsew")
        self.after(100, self.switch_status)

    def switch_status(self):
        cur_status_idx = max((i for i in range(len(self.event_arr)) if all(self.event_arr[j].is_set() for j in range(i+1))), default=0)
        self.status_label.config(text=self.status_text_arr[cur_status_idx])
        if cur_status_idx < 2: # stop when reached 'connected' phase 
            self.after(100, self.switch_status)

    def quit_gui(self): 
        self.quit()
        self.destroy()
        self.event_arr[3].set()
    
################ LOG FRAME ##################
        
    def launch_log_frame(self):

        self.log_frame.grid_columnconfigure(0, minsize=600)
        self.log_frame.grid_columnconfigure(1, minsize=600)
        
        # create log title frames
        self.log_frame.log_title_frame = tk.Frame(self.log_frame, bg="lightgrey")
        self.log_frame.log_title_frame.grid(row=1, column=0, columnspan=2, sticky="nsew")
        self.log_frame.log_title_frame.grid_propagate(False)
        self.log_frame.log_label_frame = tk.Frame(self.log_frame.log_title_frame, bg="lightgrey")
        self.log_frame.log_label_frame.pack(side="left")
        self.log_frame.log_label = tk.Label(self.log_frame.log_label_frame, text='Select Log Source:', bg="lightgrey", font=('Times New Roman', 15, 'bold'), padx=20)
        self.log_frame.log_label.pack(side="left")
        self.log_frame.log_display_label = tk.Label(self.log_frame.log_title_frame, bg="lightgrey", text='Aggregate Logs', font=('Times New Roman', 17, 'bold'))
        self.log_frame.log_display_label.pack(side="top")
        
        # create main frame
        self.log_frame.main_frame = tk.Frame(self.log_frame, width=118, height=613, bg="lightgrey", relief="ridge", bd=5)
        self.log_frame.main_frame.grid(row=2, column=0, columnspan=2, sticky="nsew")
        self.log_frame.main_frame.grid_propagate(False)

        # configure main frame grid
        for i in range(6):
            self.log_frame.main_frame.columnconfigure(i, minsize=200) # divide into 6 200px columns
            if i==5: self.log_frame.main_frame.columnconfigure(i, minsize=187)

        # create menu frame and link to canvas 
        self.log_frame.scrollbar_frame = tk.Frame(self.log_frame.main_frame)
        self.log_frame.scrollbar_frame.grid(row=0, column=0, sticky="nsew")

        # create canvas object for menu 
        self.log_frame.canvas = tk.Canvas(self.log_frame.scrollbar_frame, height=600, width=199)
        self.log_frame.canvas.pack_propagate(False)
        self.log_frame.canvas.pack(side="left", fill="both", expand=True)

        # create scrollbar for menu
        self.log_frame.scrollbar = tk.Scrollbar(self.log_frame.canvas, orient="vertical", command=self.log_frame.canvas.yview)
        self.log_frame.scrollbar.pack(side="right", fill="y")

        # create log menu frame and link to canvas 
        self.log_frame.log_menu = tk.Frame(self.log_frame.canvas, bg="white", relief="ridge", bd=2)
        self.log_frame.log_menu.pack()
        self.log_frame.canvas.create_window((0,0), window=self.log_frame.log_menu, anchor="nw")
        self.log_frame.canvas.config(scrollregion=self.log_frame.canvas.bbox("all"), yscrollcommand=self.log_frame.scrollbar.set)

        # create log display frame
        self.log_frame.log_display = tk.Frame(self.log_frame.main_frame, bg="lightgrey")
        self.log_frame.log_display.grid(row=0, column=1, columnspan=5, sticky="nsew")
        self.log_frame.log_display.grid_propagate(False)
        
        # create a scrollbar for log display 
        self.log_frame.log_scrollbar = tk.Scrollbar(self.log_frame.log_display, orient="vertical", command=self.log_text_arr[self.cur_display_idx].yview)
        self.log_frame.log_scrollbar.pack(side="right", fill="y")

        # create "Aggregate" log button
        tk.Button(self.log_frame.log_menu, text=self.log_src_arr[-1], height=4, width=24, command=lambda index=0: self.switch_text(index)).grid(row=0, column=0)
        self.log_frame.log_menu.update_idletasks() # update frame with new button

        # create text widget for log display (init to Aggregate)
        self.log_text_arr[self.cur_display_idx] = tk.Text(self.log_frame.log_display, wrap=tk.WORD, bg="white", yscrollcommand=self.log_frame.log_scrollbar.set)
        self.log_text_arr[self.cur_display_idx].pack(expand=True, fill=tk.BOTH, side="left")
        self.log_frame.log_scrollbar.config(command=self.log_text_arr[self.cur_display_idx].yview)  # link the scrollbar to the text widget

        # check for logs/prompts and update GUI
        self.after(0, self.check_for_logs) 

    def check_for_logs(self):

        # check for incoming logs
        while not self.log_queue.empty():

            # parse received log
            level, message, extra = self.log_queue.get()
            if extra['conn_counter'] == 'N/A':
                loggername = extra['loggername'] 
                log_message = f"({loggername}) {level}: {message}" 
            else:
                loggername = extra['loggername']
                conn_id = extra['conn_counter']
                log_message = f"({loggername}, ID: {conn_id}) {level}: {message}"
            
            # check if log is from a new source 
            if loggername not in self.log_src_arr: 
                # add new log source to source array and create new button in canvas
                self.log_src_arr.append(loggername) 
                self.log_text_arr.append(tk.Text(self.log_frame.log_display, wrap=tk.WORD, bg="white", yscrollcommand=self.log_frame.log_scrollbar.set))
                cur_idx = len(self.log_src_arr)-1
                tk.Button(self.log_frame.log_menu, text=self.log_src_arr[-1], height=4, width=24, command=lambda index=cur_idx: self.switch_text(index)).grid(row=cur_idx, column=0)
                self.log_frame.log_menu.update_idletasks()
                self.log_frame.canvas.config(scrollregion=self.log_frame.canvas.bbox("all"))
            
            # update text boxes (source-only AND aggregate) with new log
            self.log_text_arr[0].insert(tk.END, log_message + '\n')
            self.log_text_arr[0].yview(tk.END) # auto-scroll to the end
            self.log_text_arr[self.log_src_arr.index(loggername)].insert(tk.END, log_message + '\n')
            self.log_text_arr[self.log_src_arr.index(loggername)].yview(tk.END)  # auto-scroll to the end
            self.log_queue.task_done()
        
        # schedule the next log check
        self.after(100, self.check_for_logs)  # check every 100ms

    def switch_text(self, index):
        self.prev_display_idx = self.cur_display_idx
        self.cur_display_idx = index
        self.log_text_arr[self.prev_display_idx].pack_forget()
        self.log_text_arr[self.cur_display_idx].pack(expand=True, fill=tk.BOTH, side="left")
        self.log_frame.log_scrollbar.config(command=self.log_text_arr[self.cur_display_idx].yview)  # link the scrollbar to the text widget

        self.log_frame.log_display_label.pack_forget()
        self.log_frame.log_display_label = tk.Label(self.log_frame.log_title_frame, bg="lightgrey", text=f'{self.log_src_arr[self.cur_display_idx]} Logs', font=('Times New Roman', 17, 'bold'))
        self.log_frame.log_display_label.pack(side="top")

################ DEV FRAME ##################

    def launch_dev_frame(self):

        self.dev_frame.grid_columnconfigure(0, minsize=600)
        self.dev_frame.grid_columnconfigure(1, minsize=600)

        self.dev_frame.command_frame = tk.Frame(self.dev_frame, height=245, bg="lightgrey", relief="ridge", bd=5)
        self.dev_frame.command_frame.grid(column=0, row=1, columnspan=2, sticky="ew")
        self.dev_frame.command_frame.pack_propagate(False)

        self.dev_frame.command_label = tk.Label(self.dev_frame.command_frame, bg="lightgrey", text="Enter Request to Server:", font=('Times New Roman', 30))
        self.dev_frame.command_label.pack(side="top")

        self.dev_frame.command_entry = tk.Entry(self.dev_frame.command_frame, font=('Times New Roman', 24), width=50)
        self.dev_frame.command_entry.pack(pady=(45, 0))
        self.dev_frame.command_submit_button = tk.Button(self.dev_frame.command_frame, text="Submit", command=self.get_user_input, width=40, height=60)
        self.dev_frame.command_submit_button.pack(pady=(50, 0))  

        self.dev_frame.prompt_frame = tk.Frame(self.dev_frame, height=400, bg="lightgrey", relief="ridge", bd=5)
        self.dev_frame.prompt_frame.grid(column=0, row=2, columnspan=2, sticky="ew")
        self.dev_frame.prompt_frame.grid_propagate(False)

        self.dev_frame.prompt_frame.grid_rowconfigure(0, minsize=50)
        self.dev_frame.prompt_frame.grid_rowconfigure(1, minsize=200)
        self.dev_frame.prompt_frame.grid_rowconfigure(2, minsize=50)
        self.dev_frame.prompt_frame.grid_rowconfigure(3, minsize=25)
        self.dev_frame.prompt_frame.grid_rowconfigure(4, minsize=25)
        self.dev_frame.prompt_label = tk.Label(self.dev_frame.prompt_frame, font=('Times New Roman', 30), text="Server console", bg="lightgrey")
        self.dev_frame.prompt_label.grid(column=0, row=0, sticky="n", pady=10)
        self.dev_frame.prompt_text = tk.Text(self.dev_frame.prompt_frame, wrap=tk.WORD, bg="white", height=8, width=140)
        self.dev_frame.prompt_text.grid(column=0, row=1, sticky="nsew", padx=34)

        self.dev_frame.prompt_label2 = tk.Label(self.dev_frame.prompt_frame, font=('Times New Roman', 25), text="Enter Responses Here:", bg="lightgrey")
        self.dev_frame.prompt_label2.grid(column=0, row=2, sticky="nw")
        self.dev_frame.prompt_entry = tk.Entry(self.dev_frame.prompt_frame, font=('Times New Roman', 16), width=70)
        self.dev_frame.prompt_entry.grid(column=0, row=3)

        self.dev_frame.prompt_resp_submit_button = tk.Button(self.dev_frame.prompt_frame, text="Send", command=self.get_prompt_response, width=20)
        self.dev_frame.prompt_resp_submit_button.grid(column=0, row=4)

    def process_prompts(self):
        while True:
            prompt_type, message = self.prompt_queue.get()  # block until a message arrives
            self.add_prompt_message(message, prompt_type)
            for _ in range(50):                             # if multiple prompts arrive, try to fetch a bunch at once
                try:
                    prompt_type, message = self.prompt_queue.get(timeout=0.02)
                    self.add_prompt_message(message, prompt_type)
                except queue.Empty:
                    break                                   # exit early if no more messages

    def add_prompt_message(self, message, prompt_type):
        self.dev_frame.prompt_text.insert(tk.END, message + '\n')
        if self.dev_frame.prompt_text.yview()[1] == 1.0:    # Check if we're already at the bottom
            self.dev_frame.prompt_text.yview(tk.END)        # auto-scroll to the end

        if prompt_type == "prompt":
            self.get_prompt_response()

        if message == "Success!":
            self.after(2000, self.dev_frame.prompt_text.delete, '1.0', 'end')

    def get_prompt_response(self):
        # Get the response from the prompt entry field
        prompt_response = self.dev_frame.prompt_entry.get()
        if prompt_response:
            # Clear the entry field after fetching the response
            self.dev_frame.prompt_entry.delete(0, tk.END)
            # Place the response directly in the main response queue
            self.resp_queue.put(prompt_response)

    def launch_request(self, user_input): 
        script_dir = os.path.dirname(os.path.abspath(__file__))
        script_path = os.path.join(script_dir, "../../powershell_scripts/execute_request.ps1")
        target_client, server_request = user_input.split(" ", 2)[0], " ".join(user_input.split(" ", 2)[1:])
        subprocess.run(["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", script_path, target_client, server_request, "dev"])

    def get_user_input(self):
        user_input = self.dev_frame.command_entry.get()
        if user_input:
            self.dev_frame.command_entry.delete(0, tk.END)
            request_thread = threading.Thread(target=self.launch_request, args=(user_input,))
            request_thread.daemon = True
            request_thread.start()

############### TEST FRAME ##################

    def launch_test_frame(self): 
        pass
