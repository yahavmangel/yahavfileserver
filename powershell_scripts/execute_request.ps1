param(
    [string]$target_client,
    [string]$server_request,
    [string]$mode
)

$clients = @(
    @{Name="client1"; IP="192.168.1.201"; User="client1"; ScriptPath="client-code/client.py"}
    @{Name="client2"; IP="192.168.1.202"; User="client2"; ScriptPath="client-code/client.py"}
    @{Name="client3"; IP="192.168.1.203"; User="client3"; ScriptPath="client-code/client.py"}
    @{Name="client4"; IP="192.168.1.204"; User="client4"; ScriptPath="client-code/client.py"}
    @{Name="vinitg"; IP="192.168.1.205"; User="vinitg"; ScriptPath="client-code/client.py"}
    @{Name="local"; IP="192.168.1.137"; User="yahav"; ScriptPath="$PSScriptRoot\..\socket_programming\client_code\client.py"}
)

$client = $clients | Where-Object { $_.Name -eq $target_client }

# check if the client entry was found
if ($client) {
    # array to hold job references
    $jobs = @()

    # execute client command
    $command = "python3 " + $client.ScriptPath + " --" + $mode + " " + $server_request
    $sshCommand = "ssh $($client.User)@$($client.IP) $command"
    
    Write-Host "Executing on $($client.Name): $sshCommand"

    # start client job
    $clientJob = Start-Job -ScriptBlock {
        param($sshCommand)
        Invoke-Expression $sshCommand
    } -ArgumentList $sshCommand 

    $jobs += $clientJob

    # wait for all jobs to complete and display output
    foreach ($job in $jobs) {
        # Wait for the job to finish
        $job | Wait-Job
        Receive-Job -Job $job
        Remove-Job -Job $job
    }
} else { 
    Write-Host "Error: Invalid Client Entered"
    Exit
}
