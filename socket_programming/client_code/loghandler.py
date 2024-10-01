"""
    Custom JSON-based logging socket handler.
    Overrides the logging.Handler class emit() and close() functions. 
    This is a multithreaded implentation to prevent premature connection closure.
    For the client, no "conn_counter" attribute is necessary in the log entry. 
"""
import logging
import json
import socket
import threading

class JSONSocketHandler(logging.Handler):
    """
    Custom JSON Socket Handler class. See module docstring for more info. 
    """
    def __init__(self, host, port):
        super().__init__()                      # init logging handler class constructor
        self.host = host                        # init socket connection
        self.port = port

    def emit(self, record):                     # multithreaded: create a thread for each log

        thread = threading.Thread(target=self.send_log, args=(record,))
        thread.start()

    def send_log(self, record):
        """
        Constructs log into JSON dict, then sends it over socket.
        """
        try:

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.host, self.port))

            log_entry = {                       # Prepare the log entry
                'name': record.name,
                'level': record.levelname,
                'message': record.getMessage()
            }

            # send the log to the logserver, encapsulating message with LOG prefix and END suffix.
            sock.sendall(b'LOG' + json.dumps(log_entry).encode('utf-8') + b'END')
        except Exception:
            self.handleError(record)
        finally:
            sock.close()

    def close(self):
        super().close()
