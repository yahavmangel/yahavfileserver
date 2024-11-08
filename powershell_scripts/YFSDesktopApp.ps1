param (
    [int] $mode = 2
)

$servers = @(
    @{Name="DC"; IP="192.168.1.225"; User="Administrator"; ScriptPath="C:\Users\Administrator\Desktop\dc_code\dc.py"}
    @{Name="fileserver"; IP="192.168.1.224"; User="fileserver"; ScriptPath="server-code/server.py"}
)

# start localserver
Start-Process python3 -ArgumentList "$PSScriptRoot\..\socket_programming\local_code\localserver.py $mode"
$local_process_id = (Get-WmiObject -Class Win32_Process | Where-Object { $_.CommandLine -like "*localserver*" } | Select-Object -ExpandProperty ProcessId)

# start all VMs (using manage_vms script)
powershell -File "$PSScriptRoot\manage_vms.ps1" -Action "Start"

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

# after this, the rest of the workflow will be handled by either user mode GUI (user mode), automated tests (test mode), or localserver GUI (dev mode)

# After workflow is done: graceful termination of the server. Maybe broadcast a message to all server elements via TCP to tell them that the server is closing?

while (Get-Process -Id $local_process_id -ErrorAction SilentlyContinue) {
    Start-Sleep -Seconds 1  # Wait until the local server process finishes
}

# close all VMs (using manage_vms script)
powershell -File "$PSScriptRoot\manage_vms.ps1" -Action "Stop"

# close local server 

Stop-Process -Id $local_process_id -Force

# current challenges/to do: 
    # fix quit button on local GUI!!!!!!
    # update localserver GUI with status of app (launching VMs, connecting to servers, etc.) As a matter of fact, just display all the print dialog on GUI
    # integrate prompts/prints into user GUI.. essentially make a terminal. As part of this, figure out when to disable/enable text boxes. 
    # combine logs, request execution, and prompts/prints into one 'dev mode' GUI. 
    # fix client print/prompt (switch b/w user mode and other modes)
    # make the whole thing as easy to set up/use as possible (.iso files?)
        # explore launching the client VMs as graphical versions of ubuntu, and then launching the user GUI on them (keep fileserver VM as is)
        # add "destionation folder" functionality to command
