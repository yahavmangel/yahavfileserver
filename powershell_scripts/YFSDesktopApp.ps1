$servers = @(
    @{Name="DC"; IP="192.168.1.225"; User="Administrator"; ScriptPath="C:\Users\Administrator\Desktop\dc_code\dc.py"}
    @{Name="fileserver"; IP="192.168.1.224"; User="fileserver"; ScriptPath="server-code/server.py"}
)

# start localserver
Start-Process -NoNewWindow python3 -ArgumentList "$PSScriptRoot\..\socket_programming\local_code\localserver.py"

# set up socket connection with localserver 
$connected = $false
while(-not $connected) {
    try {
        $local_sock = New-Object System.Net.Sockets.TCPClient("localhost", 12344)
        $local_stream = $local_sock.GetStream()
        $local_sock_writer = New-Object System.IO.StreamWriter($local_stream)
        $local_sock_reader = New-Object System.IO.StreamReader($local_stream)
        $connected = $true
        $local_sock_writer.Write("ping")
        $local_sock_writer.Flush()
        Write-Host "Connected to localserver successfully."
        $connected = $true
    }
    catch { 
        Start-Sleep -Seconds 1 
        Write-Host "Connecting to localserver..."
    }
}

$local_sock_writer.Write("0") # "Booting VMs..."
$local_sock_writer.Flush()

# start all VMs (using manage_vms script)
powershell -File "$PSScriptRoot\manage_vms.ps1" -Action "Start"

$local_sock_writer.Write("1") # "Connecting to server..."
$local_sock_writer.Flush()

# wait for ssh to be ready 
foreach ($vm in $servers) {
    $isReady = $false
    while (-not $isReady) { 
        $sshCommand = "ssh $($vm.User)@$($vm.IP) whoami"    # try an ssh cmd
        $null = Invoke-Expression $sshCommand 2>$null       # redirect err stream to null
        if ($LASTEXITCODE -ne 0) {                          # check if error occured 
            Write-Host "$($vm.Name) not ready, retrying in 10 seconds..."
            Start-Sleep -Seconds 10
            continue
        } else {                                            
            Write-Host "$($vm.Name) is ready."
            $isReady = $true
        }
    }
}

# launch server-side scripts
foreach ($vm in $servers) {
    switch ($vm.Name) {
        "DC" {
            $pythonprefix = "python "
        }
        default { 
            $pythonprefix = "python3 "
        }
    }
    $command = $pythonprefix + $vm.ScriptPath 
    $sshCommand = "ssh $($vm.User)@$($vm.IP) $command"
    Write-Host "Executing on $($vm.Name): $sshCommand"

    Start-Job -ScriptBlock {
        param($sshCommand)
        Invoke-Expression $sshCommand
    } -ArgumentList $sshCommand
}

$local_sock_writer.Write("2") # "Connected!"
$local_sock_writer.Flush()

# The rest of the workflow will be handled by either user mode GUI (user mode), automated tests (test mode), or localserver GUI (dev mode)

# After workflow is done: perform graceful termination of the server. Broadcast a message to all server elements to gracefully close.

while ($true) {
    if ($local_sock_reader.Peek() -ge 0) { # check if there's data to read 
        $message = $local_sock_reader.ReadLine()
        if ($message -eq "SHUTDOWN") {
            Write-Host "Received SHUTDOWN message. Terminating..."
            
            # close the connection and exit
            $local_sock_reader.Close()
            $local_sock_writer.Close()
            $local_stream.Close()
            $local_sock.Close()
            break
        }
    }
    Start-Sleep -Seconds 1
}

# close all VMs (using manage_vms script)
powershell -File "$PSScriptRoot\manage_vms.ps1" -Action "Stop"

# current challenges/to do: 
    # update localserver GUI with status of app (launching VMs, connecting to servers, etc.) As a matter of fact, just display all the print dialog on GUI
    # integrate prompts/prints into user GUI.. essentially make a terminal. As part of this, figure out when to disable/enable text boxes. 
    # combine logs, request execution, and prompts/prints into one 'dev mode' GUI. 
    # fix client print/prompt (switch b/w user mode and other modes)
    # make the whole thing as easy to set up/use as possible (.iso files?)
        # explore launching the client VMs as graphical versions of ubuntu, and then launching the user GUI on them (keep fileserver VM as is)
        # add "destionation folder" functionality to command
