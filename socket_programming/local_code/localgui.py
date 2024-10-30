import tkinter as tk
from tkinter import ttk

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
        main_frame = tk.Frame(self, width=1200, height=645, bg="lightgrey", relief="ridge", bd=5)
        main_frame.grid(row=1, column=0, sticky="ew")
        main_frame.grid_propagate(False)
        for i in range(6):
            main_frame.columnconfigure(i, minsize=199) # divide into 6 200px columns
        log_menu = tk.Frame(main_frame, height=638, bg="white", relief="ridge", bd=2)
        log_menu.grid(row=0, column=0, sticky="nsew")
        log_display = tk.Frame(main_frame, height=638, bg="lightgrey", relief="ridge", bd=2)
        log_display.grid(row=0, column=1, columnspan=5, sticky="nsew")
        self.log_text = tk.Text(log_display, wrap=tk.WORD, bg="white")
        self.log_text.pack(expand=True, fill=tk.BOTH)  # Expand and fill the log_display frame
        self.check_log_queue()  # Start checking the log queue

    def check_log_queue(self):
        while not self.log_queue.empty():
            level, message, extra = self.log_queue.get()
            if extra['conn_counter'] == 'N/A':
                loggername = extra['loggername'] 
                log_message = f"({loggername}) {level}: {message}" 
            else:
                loggername = extra['loggername']
                conn_id = extra['conn_counter']
                log_message = f"({loggername}, ID: {conn_id}) {level}: {message}"
            
            self.log_text.insert(tk.END, log_message + '\n')
            self.log_text.yview(tk.END)  # auto-scroll to the end
            self.log_queue.task_done()
        
        # schedule the next check
        self.after(100, self.check_log_queue)  # check queue every 100msms

    

    
if __name__ == "__main__": 
    gui = localGUI(None, None, None)
    gui.mainloop()


