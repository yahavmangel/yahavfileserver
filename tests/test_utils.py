import os
import subprocess

def launch_request(target_client, command, filename, params): 
        script_dir = os.path.dirname(os.path.abspath(__file__))
        script_path = os.path.join(script_dir, "../powershell_scripts/execute_request.ps1")
        server_request = command + filename + " " + " ".join(params)
        subprocess.run(["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", script_path, target_client, server_request, "test"])
