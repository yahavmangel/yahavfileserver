$servers = @(
    @{Name="fileserver"; IP="192.168.1.224"; User="fileserver"; ScriptPath="server-code/server.py"}
)

$clients = @(
    @{Name="client1"; IP="192.168.1.201"; User="client1"; ScriptPath="client-code/client.py"}
    @{Name="client2"; IP="192.168.1.202"; User="client2"; ScriptPath="client-code/client.py"}
    @{Name="client3"; IP="192.168.1.203"; User="client3"; ScriptPath="client-code/client.py"}
    @{Name="client4"; IP="192.168.1.204"; User="client4"; ScriptPath="client-code/client.py"}
)

# foreach ($vm in $servers) {
#     $command = "python3 " + $vm.ScriptPath 
#     $sshCommand = "ssh $($vm.User)@$($vm.IP) $command"
    
#     Write-Host "Executing on $($vm.Name): $sshCommand"
    
#     # Execute the command and capture output
#     $result = Invoke-Expression -Command $sshCommand
#     Write-Host "Output from $($vm.Name): $result"
# }

foreach ($vm in $clients) {
    $command = "python3 " + $vm.ScriptPath + " 192.168.1.224 REQUEST wtf"
    $sshCommand = "ssh $($vm.User)@$($vm.IP) $command"
    
    Write-Host "Executing on $($vm.Name): $sshCommand"
    
    # Execute the command and capture output
    $result = Invoke-Expression -Command $sshCommand
    Write-Host "Output from $($vm.Name): $result"
}


