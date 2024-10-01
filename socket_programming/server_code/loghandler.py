"""
    Custom JSON-based logging socket handler.
    Overrides the logging.Handler class emit() and close() functions. 
    This is a multithreaded implentation to prevent premature connection closure.
"""
import logging
import json
import socket
import threading

class JSONSocketHandler(logging.Handler):
    """
    Custom JSON Socket Handler class. See module docstring for more info. 
    """
    def __init__(self, host, port):                                                     # initialize both the superclass constructor, and the socket connection.
        super().__init__()
        self.host = host
        self.port = port
    
    def emit(self, record):                                                             # multithreaded: create a thread for each log

        thread = threading.Thread(target=self.send_log, args=(record,))
        thread.start()

    def send_log(self, record):
        try:

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.host, self.port))
            
                                                                                        
            log_entry = {                                                               # Prepare the log entry
                'name': record.name,
                'level': record.levelname,
                'message': record.getMessage()
            }
            conn_counter = {k: v for k, v in record.__dict__.items()                    # iterate through record dict structure, grabbing the 'conn_counter' extra param
                            if k not in log_entry and k.startswith('conn_counter')}
            log_entry.update(conn_counter)
            

            sock.sendall(b'LOG' + json.dumps(log_entry).encode('utf-8') + b'END')       # send the log to the logserver, encapsulating the message with LOG prefix and with END suffix. 
        except Exception:
            self.handleError(record)
        finally:
            sock.close() 
    
    def close(self):
        super().close()
