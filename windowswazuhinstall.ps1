Stop-Service -Name "Wazuh"
$MyApp = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq "Wazuh Agent"}
$MyApp.Uninstall()
Start-Sleep -s 15
Remove-Item 'C:\Program Files (x86)\ossec-agent' -Recurse –Force
New-Item -Path "C:\" -Name "Wazuh" -ItemType "directory"

Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.2.4-1.msi -OutFile wazuh-agent.msi; ./wazuh-agent.msi /q WAZUH_MANAGER='' WAZUH_REGISTRATION_KEY='C:\Wazuh\sslagent.key' WAZUH_REGISTRATION_CERTIFICATE='C:\Wazuh\sslagent.cert' WAZUH_REGISTRATION_SERVER='' WAZUH_AGENT_GROUP='Windows' 
