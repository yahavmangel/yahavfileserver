import socket
import configparser
import threading
import json
import logging 
import os
import sys
import queue

class CustomFormatter(logging.Formatter):                                           # log formatting class
    """
    Custom logging formatter that either includes/excludes the 'conn_counter' attribute from the log.

    The 'conn_counter' attribute is the connection ID, which can be used by admins to distinguish b/w each server connection. 
    When a logger does not know what ID their log is associated with, they pass "N/A" to this attribute. This formatter will then remove the attribute entirely.  
    """

    def format(self, record):
        if getattr(record, 'conn_counter', 'N/A') == "N/A":                         # Exclude conn_counter from the log if it's "N/A"
            log_message = f"({record.loggername}) {record.levelname}: {record.msg}"
        else:
            log_message = f"({record.loggername}, ID: {record.conn_counter}) {record.levelname}: {record.msg}"
        
        return log_message

# logging and metadata

script_dir = os.path.dirname(os.path.abspath(__file__))                             # make script execution dynamic 

log_queue = queue.Queue()                                                           # instantiate thread safe log queue
logger = logging.getLogger("YFS")
logger.setLevel(logging.DEBUG)
formatter = CustomFormatter()                                                       # set the formatter to the custom one
file_handler = logging.FileHandler(os.path.join(script_dir, 'YFS.log'), mode='w')   # create default file handler to divert logs to file 
file_handler.setFormatter(formatter)                                                # associate logger with this handler/formatter
logger.addHandler(file_handler)

try: 
    config = configparser.ConfigParser()
    config.read(os.path.join(script_dir, 'config.ini'))
    port = int(config['local']['port'])                                             # port for communication for all logs and user prompts
except KeyError:                                                                    # check for misconfigured config file 
    logger.critical(f"Missing or misconfigured config file", extra={'conn_counter': "N/A"})
    sys.exit(1)

# magic numbers 

BUF_SIZE_LARGE = 4096

# main code

def logger_thread():
    """
    Extra thread responsible for processing incoming logs in parallel with the local server polling for them. This makes for much faster log processing.

    All incoming logs are placed in the log queue. This thread will then dequeue and write the oldest log. 
    """
    while True:
        level, message, extra = log_queue.get()
        if level == "DEBUG":
            logger.debug(message, extra=extra)
        elif level == "INFO":
            logger.info(message, extra=extra)
        elif level == "WARNING":
            logger.warning(message, extra=extra)
        elif level == "ERROR":
            logger.error(message, extra=extra)
        elif level == "CRITICAL":
            logger.critical(message, extra=extra)
        log_queue.task_done()


threading.Thread(target=logger_thread, daemon=True).start()                         # Start the logger thread

def local_handler(conn):
    """
    Main local server code: receives log/user prompt from some source -> processes accordingly: 
        - logs get placed in log queue and then written to aggregate log 
        - user prompts get directed to localserver terminal
    
    Args:
        conn: connection of current thread
    """

    data = b""
    while True:
        chunk = conn.recv(BUF_SIZE_LARGE)                                                     
        if not chunk:
            break
        data += chunk
        if b'END' in data: 
            data = data.replace(b'END', b'')                                        # receive logs/user prompts, separating each by 'END' suffix
            break
    
    data = data.decode('utf-8')                                                 

    match data[:3]:
        case "LOG":                                                                 # data contained LOG prefix: is a log entry 
            data = data[3:].split('LOG')
            for msg in data:                                                        # separate and parse each log
                log_entry = json.loads(msg)
                process_log_entry(log_entry)
        case "USR":                                                                 # data contained USR prefix: is a user prompt 
            pass 

    conn.close()

def process_log_entry(log_entry):
    """
    Log entry processing: parses received log and place it in log queue. 
    
    Args:
        log_entry: received log entry.
    """

    loggername = log_entry.get('name') 
    conn_counter = log_entry.get('conn_counter', "N/A")                             # if attribute DNE, default to N/A
    loggerlevelname = log_entry.get('level')
    message = log_entry.get('message')                                              # place in log queue
    log_queue.put((loggerlevelname, message, {'loggername': loggername, 'conn_counter': conn_counter}))

if __name__ == "__main__":

    local_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_sock.bind(('0.0.0.0', port))
    local_sock.listen(50)

    logging.info("localserver is listening...", extra={'loggername':"localserver", 'conn_counter': "N/A"})

    while True:
        conn, addr = local_sock.accept()
        local_thread = threading.Thread(target=local_handler, args=(conn,))
        local_thread.start()

