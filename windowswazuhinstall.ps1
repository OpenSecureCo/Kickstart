Stop-Service -Name "Wazuh"
$MyApp = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq "Wazuh Agent"}
$MyApp.Uninstall()
Start-Sleep -s 15
Remove-Item 'C:\Program Files (x86)\ossec-agent' -Force -Recurse
New-Item -Path "C:\" -Name "Wazuh" -ItemType "directory"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.2.4-1.msi -OutFile wazuh-agent-4.2.4.msi; ./wazuh-agent-4.2.4.msi /q WAZUH_MANAGER='w.g4ns.com' WAZUH_REGISTRATION_SERVER='w.g4ns.com' WAZUH_REGISTRATION_PASSWORD='ytrHWtpxQ986G8Jt

Write-Host "Installing PowerShell7"

Invoke-WebRequest -Uri https://github.com/PowerShell/PowerShell/releases/download/v7.2.0/PowerShell-7.2.0-win-x64.msi -OutFile PowerShell-7.2.0-win-x64.msi; ./PowerShell-7.2.0-win-x64.msi /q

New-Item -Path "C:\Windows" -Name "PowerShell7" -ItemType "directory"

cd C:\Windows\PowerShell7

Invoke-WebRequest -Uri https://raw.githubusercontent.com/OpenSecureCo/Kickstart/main/alienvault_otx.ps1 -OutFile alienvault_otx.ps1

cd 'C:\Program Files (x86)\ossec-agent\active-response\bin'

Invoke-WebRequest -Uri https://raw.githubusercontent.com/OpenSecureCo/Kickstart/main/otx.cmd -OutFile otx.cmd

<#
.SYNOPSIS
Install-Sysmon downloads the Sysmon executables archive and installs Sysmon64.exe
with a configuration file.
.DESCRIPTION
PowerShell script or module to install Sysmon with configuration 
.PARAMETER path
The path to the working directory.  Default is user Documents.
.EXAMPLE
Install-Sysmon -path C:\Users\example\Desktop
#>

<#[CmdletBinding()]#>

#Establish parameters for path
param (
    [string]$path=[Environment]::GetFolderPath("Windows")   
)

#Test path and create it if required

If(!(test-path $path))
{
	Write-Information -MessageData "Path does not exist.  Creating Path..." -InformationAction Continue;
	New-Item -ItemType Directory -Force -Path $path | Out-Null;
	Write-Information -MessageData "...Complete" -InformationAction Continue
}

Set-Location $path

Write-Host "Location set $path"

Write-Host "Retrieving Sysmon..."

Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -Outfile Sysmon.zip

Write-Host "Sysmon Retrived"

Write-Host "Unzip Sysmon..."

Expand-Archive Sysmon.zip

Set-Location $path\Sysmon

Write-Host "Unzip Complete."

Write-Host "Retrieving Configuration File..."

Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -Outfile sysmonconfig-export.xml

Write-Host "Configuration File Retrieved."

Write-Host "Installing Sysmon..."

.\sysmon64.exe -accepteula -i sysmonconfig-export.xml

Write-Host "Sysmon Installed!"

Write-Host "Complete!"



