import tkinter as tk

class localGUI(tk.Tk): 
    def __init__(self, log_queue, print_queue, prompt_queue, mode_num, domain_name, server_ip, domain_controller_ip, local_ip, ldap_server):
        super().__init__()
        
        # main setup
        self.geometry('1200x800')
        self.title("YahavFileServer")
        
        # initialize queues
        self.log_queue = log_queue
        self.print_queue = print_queue 
        self.prompt_queue = prompt_queue 
        self.log_src_arr = ["Aggregate"]
        self.log_text_arr = [tk.Text()]
        self.cur_display_idx = 0
        self.prev_display_idx = -1
        # create top frame for static information
        self.init_top_frame(mode_num, domain_name, server_ip, domain_controller_ip, local_ip, ldap_server)

        # create rest of GUI based on mode

        match mode_num: 
            case 0:         # handle dev mode 
                pass
            case 1:         # handle test mode
                pass
            case 2:         # handle user mode 
                self.launch_user_mode()

    def init_top_frame(self, mode_num, domain_name, server_ip, domain_controller_ip, local_ip, ldap_server):
        top_frame = tk.Frame(self, width=1200, height=155, bg="lightblue", relief="ridge", bd=5)
        top_frame.grid(row=0, column=0, sticky="ew")
        top_frame.grid_propagate(False)  # prevent children widgets from changing frame

        # set first 2 columns of top frame to have equal weight 
        top_frame.columnconfigure(0, weight=1)
        top_frame.columnconfigure(1, weight=1) 

        # make title label within top frame
        title = tk.Label(top_frame, text="Welcome to YFS Services!", bg="lightblue", font=('Times New Roman', 24, 'bold', 'underline'))
        title.grid(row=0, column=0, columnspan=2)

        # static information for labels
        mode_text_arr = ["Developer", "Test", "User"]
        label_dict = {
            "Domain": domain_name,
            "Server IP": server_ip,
            "Domain Controller IP": domain_controller_ip,
            "Localserver IP": local_ip,
            "LDAP Server": ldap_server,
            "Mode": mode_text_arr[mode_num]
        }

        # display information in two columns within top_frame
        for idx, (key, value) in enumerate(label_dict.items()):
            row = (idx % 3) + 1 # 3 items per column
            col = idx // 3      # switch to new column after 3 items

            label_text = f"{key}: {value}"
            label = tk.Label(top_frame, text=label_text, bg="lightblue", anchor="w", font=('Times New Roman', 16, 'bold'))
            label.grid(row=row, column=col, padx=(100, 10), sticky="w")
    
    def launch_user_mode(self):

        # create main frame
        main_frame = tk.Frame(self, width=118, height=645, bg="lightgrey", relief="ridge", bd=5)
        main_frame.grid(row=1, column=0, sticky="nsew")
        main_frame.grid_propagate(False)

        # configure main frame grid
        for i in range(6):
            main_frame.columnconfigure(i, minsize=200) # divide into 6 200px columns
            if i==5: main_frame.columnconfigure(i, minsize=187)

        # create menu frame and link to canvas 
        scrollbar_frame = tk.Frame(main_frame)
        scrollbar_frame.grid(row=0, column=0, sticky="nsew")

        # create canvas object for menu 
        canvas = tk.Canvas(scrollbar_frame, height=631, width=199)
        canvas.pack_propagate(False)
        canvas.pack(side="left", fill="both", expand=True)

        # create scrollbar for menu
        scrollbar = tk.Scrollbar(canvas, orient="vertical", command=canvas.yview)
        scrollbar.pack(side="right", fill="y")

        # create log menu frame and link to canvas 
        log_menu = tk.Frame(canvas, bg="white", relief="ridge", bd=2)
        log_menu.pack()
        canvas.create_window((0,0), window=log_menu, anchor="nw")
        canvas.config(scrollregion=canvas.bbox("all"), yscrollcommand=scrollbar.set)

        # create log display frame
        log_display = tk.Frame(main_frame, bg="lightgrey", relief="ridge", bd=2)
        log_display.grid(row=0, column=1, columnspan=5, sticky="nsew")
        log_display.grid_propagate(False)
        
        # create a scrollbar for log display 
        log_scrollbar = tk.Scrollbar(log_display, orient="vertical", command=self.log_text_arr[self.cur_display_idx].yview)
        log_scrollbar.pack(side="right", fill="y")

        # create "Aggregate" log button
        tk.Button(log_menu, text=self.log_src_arr[-1], height=4, width=24, command=lambda index=0, log_scrollbar=log_scrollbar: self.switch_text(index, log_scrollbar)).grid(row=0, column=0)
        log_menu.update_idletasks() # update frame with new button

        # create text widget for log display (init to Aggregate)
        self.log_text_arr[self.cur_display_idx] = tk.Text(log_display, wrap=tk.WORD, bg="white", yscrollcommand=log_scrollbar.set)
        self.log_text_arr[self.cur_display_idx].pack(expand=True, fill=tk.BOTH, side="left")
        log_scrollbar.config(command=self.log_text_arr[self.cur_display_idx].yview)  # link the scrollbar to the text widget

        # check for logs and update GUI
        self.check_for_logs(log_menu, canvas, log_scrollbar, log_display) 

    def check_for_logs(self, log_menu, canvas, log_scrollbar, log_display):

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
                self.log_text_arr.append(tk.Text(log_display, wrap=tk.WORD, bg="white", yscrollcommand=log_scrollbar.set))
                cur_idx = len(self.log_src_arr)-1
                tk.Button(log_menu, text=self.log_src_arr[-1], height=4, width=24, command=lambda index=cur_idx, log_scrollbar=log_scrollbar: self.switch_text(index, log_scrollbar)).grid(row=cur_idx, column=0)
                log_menu.update_idletasks()
                canvas.config(scrollregion=canvas.bbox("all"))
            
            # update text boxes (source-only AND aggregate) with new log
            self.log_text_arr[0].insert(tk.END, log_message + '\n')
            self.log_text_arr[0].yview(tk.END) # auto-scroll to the end
            self.log_text_arr[self.log_src_arr.index(loggername)].insert(tk.END, log_message + '\n')
            self.log_text_arr[self.log_src_arr.index(loggername)].yview(tk.END)  # auto-scroll to the end
            self.log_queue.task_done()
        
        # schedule the next log check
        self.after(100, self.check_for_logs, log_menu, canvas, log_scrollbar, log_display)  # check every 100ms

    def switch_text(self, index, log_scrollbar):
        self.prev_display_idx = self.cur_display_idx
        self.cur_display_idx = index
        self.log_text_arr[self.prev_display_idx].pack_forget()
        self.log_text_arr[self.cur_display_idx].pack(expand=True, fill=tk.BOTH, side="left")
        log_scrollbar.config(command=self.log_text_arr[self.cur_display_idx].yview)  # link the scrollbar to the text widget
