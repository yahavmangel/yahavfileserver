$servers = @(
    @{Name="DC"; IP="192.168.1.225"; User="Administrator"; ScriptPath="Desktop\dc_code\dc.py"}
    @{Name="fileserver"; IP="192.168.1.224"; User="fileserver"; ScriptPath="server-code/server.py"}
)

$clients = @(
    @{Name="client1"; IP="192.168.1.201"; User="client1"; ScriptPath="client-code/client.py"}
    @{Name="client2"; IP="192.168.1.202"; User="client2"; ScriptPath="client-code/client.py"}
    @{Name="client3"; IP="192.168.1.203"; User="client3"; ScriptPath="client-code/client.py"}
    @{Name="client4"; IP="192.168.1.204"; User="client4"; ScriptPath="client-code/client.py"}
)

Write-Host "Starting servers..."

Start-Job -ScriptBlock {
    python3 ..\socket_programming\local_code\localserver.py
}

# foreach ($vm in $servers) {
#     switch ($vm.Name) {
#         "DC" {
#             $pythonprefix = "python "
#         }
#         default { 
#             $pythonprefix = "python3 "
#         }
#     }
#     $command = $pythonprefix + $vm.ScriptPath 
#     $sshCommand = "ssh $($vm.User)@$($vm.IP) $command"
#     Write-Host "Executing on $($vm.Name): $sshCommand"

#       # Start each command in a separate thread
#     $job = Start-Job -ScriptBlock {
#         param($sshCommand)
#         Invoke-Expression $sshCommand
#     } -ArgumentList $sshCommand
# }

Write-Host "Launching client requests"

foreach ($vm in $clients) {
    $command = "python3 " + $vm.ScriptPath + " REQUEST css"
    $sshCommand = "ssh $($vm.User)@$($vm.IP) $command"
    
    Write-Host "Executing on $($vm.Name): $sshCommand"

    $job = Start-Job -ScriptBlock {
        param($sshCommand)
        Invoke-Expression $sshCommand
    } -ArgumentList $sshCommand
}

