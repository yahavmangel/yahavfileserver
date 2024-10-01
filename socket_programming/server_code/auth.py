"""
Run LDAP-based Authentication services for the fileserver:
- Query LDAP server for user info, groups, and security descriptor
- connect with DC to authenticate. 

Functions: 
    check_ldap_auth(ldap_conn, username, perm, conn_counter) -> Bool 
    auth_request(security_desc, target_permission, sid_list, conn_counter) -> Bool
    initiate_ldap_conn(conn_counter) -> ldap connection
    get_ldap_user_info(ldap_conn, username, attributes) -> query results 
    construct_dn(basename) -> string 
    wait_for_server_resp(dc_socket, resp, client_name, conn_counter) 
"""
import socket
import logging
import os
import configparser
import sys
import json
from ldap3 import Server, Connection, ALL, SASL, GSSAPI

# logging and metadata

login_name = os.getlogin()                                      # base logging and ID based on login
script_dir = os.path.dirname(os.path.abspath(__file__))         # make script execution dynamic
logger = logging.getLogger(login_name)

try:                                                            # collect config file info
    config = configparser.ConfigParser()
    config.read(os.path.join(script_dir, 'config.ini'))
    port2 = int(config['server']['port2'])
    domain_controller = config['server']['domain_controller']
    domain_controller_ip = config['server']['domain_controller_ip']
    target_dir = os.path.join(script_dir, config['server']['target_dir'])
except KeyError:
    logger.critical("Missing or misconfigured config file", extra={'conn_counter': "N/A"})
    sys.exit(1)
dc_array = domain_controller.split('.')[1:]

command_table = {

    # client commands

    'STORE': 'STORE',
    'REQUEST': 'REQUEST',

    # internal commands

    'OPTIONS': 'OPTIONS',
    'READY': 'READY',
    'OVERWRITE': 'OVERWRITE',
    'QUIT': 'QUIT',
    'ACK': 'ACK',
    'STOREFILE': 'STOREFILE',
    'STOREDIRE': 'STOREDIRE',
    'AUTHSUCCESS': 'AUTHS',
    'AUTHFAIL': 'AUTHF'
}

# magic numbers

SEC_GROUP_BITMASK = 0x80000000
# This delimiter will not show up in any misc binary data.
DELIMITER = b'\x1F'

# main code

def check_ldap_auth(ldap_conn, username, perm, conn_counter):
    """
    Main LDAP authentization function: 
    1. uses LDAP queries to scan for all security groups the target client is a member of
    2. sends SIDs of those groups to DC for authentication.

    Args:
        ldap_conn: connection to LDAP server
        username: host name for computer accounts, login name for user accounts
        perm: permission to authenticate user against
        conn_counter: current connection ID (to send to DC for logging)
    
    Returns: 
        Bool: Final authentication decision. (True = Authorized, False = not authorized)
    """

    logger.debug("verifying permissions for client %s...",
                 username, extra={'conn_counter': conn_counter})

    # query #1: get DN and nTSecurityDescriptor of client
    entries = get_ldap_user_info(ldap_conn, username, ['distinguishedName', 'nTSecurityDescriptor'])

    if entries:
        user_dn = entries[0].distinguishedName.value
        bin_sd = entries[0].ntSecurityDescriptor.raw_values[0]  # get binary data of security desc

        # query #2: get all groups that the client is member of

        domain_dn = construct_dn('')

        logger.debug("Scanning for %s's group membership...",
                     username, extra={'conn_counter': conn_counter})

        # Look for groups that the client is a member of,
        # as they will contain the permissions which the user will inherit
        ldap_conn.search(search_base=domain_dn,
                         search_filter=f'(&(objectCategory=group)(member={user_dn}))',
                         attributes=['cn', 'groupType', 'objectSid'])

        if ldap_conn.entries:
            groups_to_check = []
            for entry in ldap_conn.entries:

                # check if the group is a security group (not a distribution group)
                if (entry.groupType.value & SEC_GROUP_BITMASK) != 0:
                    logger.debug("%s is a member of the %s security group",
                                  username, entry.cn.value, extra={'conn_counter': conn_counter})

                    # add SID of security group to the list that the DC will check.
                    groups_to_check.append(entry.objectSid.value)

            # send authentication request to domain controller, and return result to main code
            return bool(auth_request(bin_sd, perm, groups_to_check, conn_counter))

        logger.debug("Client %s is not member of any security group.",
                     username, extra={'conn_counter': conn_counter})

        # edge case: client is not a member of any group
        return False

    logger.debug("Client %s was not found in LDAP server.",
                 username, extra={'conn_counter': conn_counter})

    # edge case: client does not exist in domain
    return False

def auth_request(security_desc, target_permission, sid_list, conn_counter):
    """
    Sends an "authentication request" to the DC, and returns its authentication decision.

    Args:
        security_desc: binary of security descriptor of target client
        target_permission: permission to authenticate client against 
        sid_list: list of SIDs of security groups the client is a member of 
        conn_counter: current connection ID (to send to DC for logging) 
    
    Returns: 
        Bool: authentication decision from DC. (True = Authorized, False = not authorized)
    """

    logger.debug("Initiating connection with DC for authorization...",
                 extra={'conn_counter': conn_counter})

    # set up socket connection with DC
    dc_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    dc_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        dc_socket.settimeout(10)
        dc_socket.connect((domain_controller_ip, port2))
    except socket.timeout:
        logger.critical("Connection timed out. DC unreachable.",
                        extra={'conn_counter': conn_counter})
        return False
    except socket.error:
        logger.critical("Failed to connect to DC",
                        extra={'conn_counter': conn_counter})
        return False

    # Convert binary data to bytes and combine everything into a single message.
    server_msg = DELIMITER.join([
        security_desc,
        target_permission.encode('utf-8'),
        json.dumps(sid_list).encode('utf-8'),
        str(conn_counter).encode('utf-8')                       # pass conn ID to DC for logging
    ])

    # send information to the domain controller for processing
    dc_socket.sendall(server_msg)                               # send server message to DC
    dc_socket.shutdown(socket.SHUT_WR)                          # force all buffered data to send
    wait_for_server_resp(dc_socket, command_table['AUTHSUCCESS'], "DC", conn_counter)
    resp = int(dc_socket.recv(1).decode('utf-8'))               # receive DC's auth decision
    dc_socket.close()
    return resp                                                 # return DC's decision to main code

def initiate_ldap_conn(conn_counter):
    """
    Initializes connection to LDAP server (called at the start of server script)

    Args: 
        conn_counter: current connection ID (for logging)

    Returns: 
        ldap_conn: connection point to LDAP server (or None if LDAP conn failure)
    """

    ldap_server = f'ldap://{domain_controller}'
    logger.debug("Connecting to LDAP server: %s", ldap_server, extra={'conn_counter': conn_counter})
    try:

        # Connect to the LDAP server using GSSAPI (Kerberos) authentication
        server = Server(ldap_server, get_info=ALL)
        ldap_conn = Connection(server, authentication=SASL, sasl_mechanism=GSSAPI)
        ldap_conn.bind()
    except Exception:
        logger.critical("Error connecting to LDAP server. Ensure you have a valid Kerberos ticket.",
                        extra={'conn_counter': conn_counter})
        return ldap_conn
    logger.info("Successfully connected to LDAP server: %s",
                ldap_server, extra={'conn_counter': conn_counter})
    return ldap_conn

def get_ldap_user_info(ldap_conn, username, attributes):
    """
    Helper function to search for a particular user in domain 
    and return a list of desired attributes.

    Args:
        ldap_conn: connection to LDAP server
        username: host name for computer accounts, login name for user accounts
        attributes: list of desired attributes to return from search

    Returns:
        Results of query.
    """
    domain_dn = construct_dn('')                                # get DN of full domain
    try:

        # this query works on either user or computer accounts (using AND/OR syntax)
        ldap_conn.search(search_base=domain_dn,
                        search_filter=f'(|(&(objectClass=user)(|(cn={username})\
                            (sAMAccountName={username})))(&(objectClass=computer)(cn={username})))',
                        attributes=attributes)
    except Exception:
        return None

    return ldap_conn.entries

def construct_dn(basename):
    """
    Helper function to construct a Domain Name for any desired user or object. 
    Uses the domain written in the config file as the base (via dc_array). 

    Args:
        basename: CN of user/group to construct DN of. Pass empty string for full domain DN. 
    
    Returns: 
        Final outcome DN string
    """
    for i in range(0, len(dc_array)):
        basename += ('DC=' + dc_array[i])
        if i < len(dc_array) - 1:
            basename += ','
    return basename

def wait_for_server_resp(dc_socket, resp, client_name, conn_counter):
    """
    Polls DC for message.

    Args: 
        dc_socket: socket connected to DC. 
        resp: desired response
        client_name: DC.
        conn_counter: current connection ID (for logging)
    """
    resp_len = len(resp)
    while True:
        server_resp = dc_socket.recv(resp_len).decode('utf-8')
        if resp in server_resp and resp in command_table.values():
            logger.debug("Received message from %s: %s",
                         client_name, resp, extra={'conn_counter': conn_counter})
            break
