param (
    [string] mode
)

# plan for this script: 

    # start all VMs (using manage_vms script)

    # start all server elements:

        # start DC (ssh)
        # start fileserver (ssh)
        # start localserver: Start-Process python3 -ArgumentList "$PSScriptRoot\..\socket_programming\local_code\localserver.py" -NoNewWindow

        # if mode = 2 (user mode) then start user GUI (right now local, in practice ssh)

    # after this, the rest of the workflow will be handled by either user mode GUI (user mode), automated tests (test mode), or localserver GUI (dev mode)

    # After workflow is done: graceful termination of the server. Maybe broadcast a message to all server elements via TCP to tell them that the server is closing?

    # close all VMs (using manage_vms script)

# current challenges/to do: 
    # DC key-based SSH not working.. have to manually start the DC (figure out a solution.. maybe need to cook up a new DC?)
    # fileserver Kerberos tickets aren't automatically renewed, have to manually renew (might fix with subprocess + kinit/kinit -R???)
    # integrate prompts/prints into user GUI.. essentially make a terminal. 
    # combine logs, request execution, and prompts/prints into one 'dev mode' GUI. 
    # have desktop app call this powershell script.
    # make the whole thing as easy to set up/use as possible (.iso files?)
        # explore launching the client VMs as graphical versions of ubuntu, and then launching the user GUI on them (keep fileserver VM as is)
        # add "destionation folder" functionality to command
