Stop-Service -Name "Wazuh"
$MyApp = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq "Wazuh Agent"}
$MyApp.Uninstall()
Start-Sleep -s 15
Remove-Item 'C:\Program Files (x86)\ossec-agent' -Force -Recurse
New-Item -Path "C:\" -Name "Wazuh" -ItemType "directory"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.2.4-1.msi -OutFile wazuh-agent-4.2.4.msi; ./wazuh-agent-4.2.4.msi /q WAZUH_MANAGER='' WAZUH_REGISTRATION_SERVER='' WAZUH_REGISTRATION_PASSWORD=''



