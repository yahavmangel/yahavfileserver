# File: manage_vms.ps1

param (
    [string]$Action = "start"
)

# List of VM names
$vmList = VBoxManage list vms | Select-String -Pattern 'client.*' | ForEach-Object {
    $_.Line -replace '.*"([^"]+)".*', '$1'
}
$vmList2 = @("administrator", "fileserver")
function Get-VMStatus {
    param (
        [string]$VMName
    )

    $status = & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" showvminfo $VMName --machinereadable | Select-String -Pattern "^VMState="
    if ($status -match "^VMState=\""(.+)\""") {
        return $matches[1]
    } else {
        return "Unknown"
    }
}

foreach ($vm in $vmList) {
    if ($Action -eq "start") {
        Write-Host "Starting VM: $vm"
        & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" startvm $vm --type headless
    } elseif ($Action -eq "stop") {
        Write-Host "Stopping VM: $vm"
        & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm $vm acpipowerbutton
    } elseif ($Action -eq "status") {
        $status = Get-VMStatus -VMName $vm
        Write-Host "VM: $vm, Status: $status"
    }
}

foreach ($vm in $vmList2) {
    if ($Action -eq "start") {
        Write-Host "Starting VM: $vm"
        & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" startvm $vm --type gui
    } elseif ($Action -eq "stop") {
        Write-Host "Stopping VM: $vm"
        & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm $vm acpipowerbutton
    } elseif ($Action -eq "status") {
        $status = Get-VMStatus -VMName $vm
        Write-Host "VM: $vm, Status: $status"
    }
}