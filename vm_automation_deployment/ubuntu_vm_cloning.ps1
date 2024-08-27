$baseVM = "client5"   
$VMPrefix = "client"  # Prefix for the new VMs
$numberOfClients = 4   # Number of VMs to create

# Loop to create multiple VMs
for ($i = 1; $i -le $numberOfClients; $i++) {
    # Generate a new VM name based on the loop index
    $newVMName = "${VMPrefix}${i}"
    
    # Clone the base VM to create a new VM with the generated name
    VBoxManage clonevm $baseVM --name $newVMName --register

    # Start the new VM in headless mode
    VBoxManage startvm $newVMName --type headless

    # Optionally, you can output the VM creation status
    Write-Output "Created and started VM: $newVMName"
}
