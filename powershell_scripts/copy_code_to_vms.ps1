Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
function Send-Keys {
    param (
        [string]$keys
    )
    [System.Windows.Forms.SendKeys]::SendWait($keys)
}

$servers = @(
    @{Name="fileserver"; IP="192.168.1.224"; User="fileserver"; ScriptPath="server-code\server.py"; ScriptPath2="server-code\config.ini"; ScriptPath3="server-code\loghandler.py"; ScriptPath4="server-code\auth.py"}
)

$clients = @(
    @{Name="client1"; IP="192.168.1.201"; User="client1"; ScriptPath="client-code\client.py"; ScriptPath2="client-code\config.ini"; ScriptPath3="client-code\loghandler.py"},
    @{Name="client2"; IP="192.168.1.202"; User="client2"; ScriptPath="client-code\client.py"; ScriptPath2="client-code\config.ini"; ScriptPath3="client-code\loghandler.py"},
    @{Name="client3"; IP="192.168.1.203"; User="client3"; ScriptPath="client-code\client.py"; ScriptPath2="client-code\config.ini"; ScriptPath3="client-code\loghandler.py"},
    @{Name="client4"; IP="192.168.1.204"; User="client4"; ScriptPath="client-code\client.py"; ScriptPath2="client-code\config.ini"; ScriptPath3="client-code\loghandler.py"}
)

Write-Host "yahavgaming123"

# foreach ($vm in $servers) {
#     scp "$PSScriptRoot\..\socket_programming\server_code\server.py" "$($vm.User)@$($vm.IP):$($vm.ScriptPath)"
#     scp "$PSScriptRoot\..\socket_programming\server_code\config.ini" "$($vm.User)@$($vm.IP):$($vm.ScriptPath2)"
#     scp "$PSScriptRoot\..\socket_programming\server_code\loghandler.py" "$($vm.User)@$($vm.IP):$($vm.ScriptPath3)"
#     scp "$PSScriptRoot\..\socket_programming\server_code\auth.py" "$($vm.User)@$($vm.IP):$($vm.ScriptPath4)"
# }

foreach ($vm in $clients) {
    scp "$PSScriptRoot\..\socket_programming\client_code\client.py" "$($vm.User)@$($vm.IP):$($vm.ScriptPath)"
    scp "$PSScriptRoot\..\socket_programming\client_code\config.ini" "$($vm.User)@$($vm.IP):$($vm.ScriptPath2)"
    scp "$PSScriptRoot\..\socket_programming\client_code\loghandler.py" "$($vm.User)@$($vm.IP):$($vm.ScriptPath3)"
}
