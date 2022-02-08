$user = 'user'
$pass = 'pass'
$pair = "$($user):$($pass)"
$encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
$basicAuthValue = "Basic $encodedCreds"
$Headers = @{
    Authorization = $basicAuthValue
}
$wazuh_repo = 'packages.wazuh.com'
$wazuh_major = '4.x'
$wazuh_package = 'wazuh-agent-4.2.5-1.msi'
$wazuh_downloadlink = 'https://d2do8iquzszhr1.cloudfront.net/wazuh-agent-4.2.5-1.msi'
$WAZUH_MANAGER="collection.e2open.com"
$WAZUH_REGISTRATION_SERVER="collection.e2open.com"
$WAZUH_MANAGER_PORT="1514"
$WAZUH_PROTOCOL="TCP"
$WAZUH_AGENT_GROUP="Windows"
$WAZUH_OSSEC_CONF = 'https://d2do8iquzszhr1.cloudfront.net/ossec.conf'
$CYLANCE_Token="Cfz2EkMsLOhmMxZvTLahxFLE"
$CYLANCE_SelfProtectionLevel="1"
$CYLANCE_LogLevel="2"
$CYLANCE_VenueZone="Default"
$CYLANCE_UiMode="2"
$cylance_url = 'protect.cylance.com'
$LOCAL_INTERNAL_OPTIONS = 'https://d2do8iquzszhr1.cloudfront.net/local_internal_options.conf'
$OTX_CMD = 'https://d2do8iquzszhr1.cloudfront.net/otx.cmd'
$sysinternals_repo = 'download.sysinternals.com'
$sysinternals_downloadlink = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
$sysinternals_folder = 'C:\Program Files\sysinternals'
$sysinternals_zip = 'SysinternalsSuite.zip'
$sysmonconfig_downloadlink = 'https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml'
$sysmonconfig_file = 'sysmonconfig-export.xml'
$autorunsps1_downloadlink = 'https://d2do8iquzszhr1.cloudfront.net/autoruns.ps1'
$logonsession_downloadlink = 'https://d2do8iquzszhr1.cloudfront.net/logonsessions.ps1'
$sigcheck_downloadlink = 'https://d2do8iquzszhr1.cloudfront.net/sigcheck.ps1'
$alienvault_ps1 = 'https://d2do8iquzszhr1.cloudfront.net/alienvault_otx.ps1'
$Cylance_MSI = 'https://d2do8iquzszhr1.cloudfront.net/CylanceProtect_x64.msi'
$Rapid7_MSI = 'https://d2do8iquzszhr1.cloudfront.net/agentInstaller-x86_64.msi'
$Cylance_package = 'CylanceProtect_x64.msi'
$autorunsps1_file = 'autoruns.ps1'
$logonsession_file = 'logonsessions.ps1'
$sigcheck_file = 'sigcheck.ps1'
$SvcName = "Sysmon64"
$Uninstall = "Force"
$wazuhAgentVersion = "4.2.5"
#Stop-Service -Name "Wazuh"
#$MyApp = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq "Wazuh Agent"}
#$MyApp.Uninstall()
#Start-Sleep -s 15
#Remove-Item 'C:\Program Files (x86)\ossec-agent' -Force -Recurse
#New-Item -Path "C:\" -Name "Wazuh" -ItemType "directory"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$payload = @{
 "hostname" = "$env:COMPUTERNAME"
  "message" = "This is my message. Hello there!"
}
 
Invoke-WebRequest -UseBasicParsing `
 -Body (ConvertTo-Json -Compress -InputObject $payload) `
 -Method Post `
 -Uri "https://shuffler.io/api/v1/hooks/webhook_d1ff340b-5247-49dd-9a8e-1ca1e01f7573"

write-host ('Verifying Network Connection To WAZUH MANAGER ...')

$X = 0
    do {
      Write-Output "Waiting for network"
      Start-Sleep -s 5
      $X += 1
    } until(($connectreult = Test-NetConnection $WAZUH_MANAGER -Port 1515 | ? { $_.TcpTestSucceeded }) -or $X -eq 3)

    if ($connectreult.TcpTestSucceeded -eq $true){
      Try
      {
      write-host ('Connection to WAZUH_MANAGER successful ...')
      }
      Catch
      {
      $payload = @{
 "hostname" = "$env:COMPUTERNAME"
  "message" = "Connection to Wazuh Manager Failed"
}
 
Invoke-WebRequest -UseBasicParsing `
 -Body (ConvertTo-Json -Compress -InputObject $payload) `
 -Method Post `
 -Uri "https://shuffler.io/api/v1/hooks/webhook_d1ff340b-5247-49dd-9a8e-1ca1e01f7573"
          $ErrorMessage = $_.Exception.Message
          $FailedItem = $_.Exception.ItemName
          Write-Error -Message "$ErrorMessage $FailedItem"
          exit 1
      }
    } 
  

##Sysmon Install
    
if (Test-Path -Path $sysinternals_folder) {
    write-host ('Sysinternals folder already exists')
} else {
    Write-Host "$(Get-Date): Uninstalling Sysmon from $ENV:COMPUTERNAME..."
    $SysmonExePath = (get-command sysmon64.exe).Path
    if ($Uninstall -eq "Force")
                {
                & $SysmonExePath -u 
                }
  $OutPath = $env:TMP
  $output = $sysinternals_zip
  New-Item -Path "C:\Program Files" -Name "sysinternals" -ItemType "directory"
  $X = 0
  do {
    Write-Output "Waiting for network"
    Start-Sleep -s 5
    $X += 1
  } until(($connectreult = Test-NetConnection $sysinternals_repo -Port 443 | ? { $_.TcpTestSucceeded }) -or $X -eq 3)

  if ($connectreult.TcpTestSucceeded -eq $true){
    Try
    {
    write-host ('Downloading and copying Sysinternals Tools to C:\Program Files\sysinternals...')
    Invoke-WebRequest -Uri $sysinternals_downloadlink -OutFile $OutPath\$output
    Expand-Archive -path $OutPath\$output -destinationpath $sysinternals_folder
    Start-Sleep -s 10
    Invoke-WebRequest -Uri $sysmonconfig_downloadlink -Headers $Headers -OutFile $OutPath\$sysmonconfig_file
    Invoke-WebRequest -Uri $autorunsps1_downloadlink -Headers $Headers -OutFile 'C:\Program Files\sysinternals\autoruns.ps1'
    Invoke-WebRequest -Uri $logonsession_downloadlink -Headers $Headers -OutFile 'C:\Program Files\sysinternals\logonsessions.ps1'
    Invoke-WebRequest -Uri $sigcheck_downloadlink -Headers $Headers -OutFile 'C:\Program Files\sysinternals\sigcheck.ps1'
    $serviceName = 'Sysmon64'
    If (Get-Service $serviceName -ErrorAction SilentlyContinue) {
    write-host ('Sysmon is already installed')  
    } else {
    write-host ('Installing Sysmon')
    Invoke-Command {reg.exe ADD HKCU\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f}
    Invoke-Command {reg.exe ADD HKU\.DEFAULT\Software\Sysinternals /v EulaAccepted /t REG_DWORD /d 1 /f}
    Start-Process -FilePath $sysinternals_folder\Sysmon64.exe -Argumentlist @("-i", "$OutPath\$sysmonconfig_file")
    }
    }
    Catch
    {
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Error -Message "$ErrorMessage $FailedItem"
        exit 1
    }
    Finally
    {
        Remove-Item -Path $OutPath\$output
    }

  } else {
      Write-Output "Unable to connect to Sysinternals Repo"
  }
}

write-host ('Installing PowerShell7')

if (-not(Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq "PowerShell 7-x64"})) {
     try {
        Invoke-WebRequest -Uri https://github.com/PowerShell/PowerShell/releases/download/v7.2.0/PowerShell-7.2.0-win-x64.msi -OutFile PowerShell-7.2.0-win-x64.msi; ./PowerShell-7.2.0-win-x64.msi /q
        New-Item -Path "C:\Windows" -Name "PowerShell7" -ItemType "directory"
        cd C:\Windows\PowerShell7
        Invoke-WebRequest -Uri $alienvault_ps1 -Headers $Headers -OutFile alienvault_otx.ps1
     }
     catch {
         throw $_.Exception.Message
     }
 }
# If the PowerShell7 already exists, show the message and do nothing.
 else {
     Write-Host "PowerShell7 Already Exists."
 }

write-host ('Installing Wazuh')


#If Wazuh Agent is not 4.2.5, upgrade to 4.2.5 version
if ((Get-WmiObject -Class Win32_Product -Filter "vendor = 'Wazuh, Inc.'" | where version -eq "$wazuhAgentVersion" | Select-Object Version)) {
     try {
        Write-Host "Version 4.2.5 is installed"
     }
     catch {
         throw $_.Exception.Message
     }
 }
# If the Wazuh agent is not 4.2.5. Remove and install
 else {
     Write-Host "Version 4.2.5 not installed."
     Stop-Service -Name "Wazuh"
     $MyApp = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq "Wazuh Agent"} 
     $MyApp.Uninstall()
     Start-Sleep -s 15
     Remove-Item 'C:\Program Files (x86)\ossec-agent' -Force -Recurse
     $OutPath = $env:TMP
    $output = $wazuh_package

    $installArgs = @(
      "/i $OutPath\$output"
      "/q"
      "WAZUH_MANAGER=`"$WAZUH_MANAGER`""
      "WAZUH_REGISTRATION_SERVER=`"$WAZUH_REGISTRATION_SERVER`""
      "WAZUH_MANAGER_PORT=`"$WAZUH_MANAGER_PORT`""
      "WAZUH_PROTOCOL=`"$WAZUH_PROTOCOL`""
      "WAZUH_REGISTRATION_CERTIFICATE=`"$WAZUH_REGISTRATION_CERT`""
      "WAZUH_REGISTRATION_KEY=`"$WAZUH_REGISTRATION_KEY`""
      "WAZUH_AGENT_GROUP=`"$WAZUH_AGENT_GROUP`""
    )

    $X = 0
    do {
      Write-Output "Waiting for network"
      Start-Sleep -s 5
      $X += 1
    } until(($connectreult = Test-NetConnection $wazuh_repo -Port 443 | ? { $_.TcpTestSucceeded }) -or $X -eq 3)

    if ($connectreult.TcpTestSucceeded -eq $true){
      Try
      {
      write-host ('Installing Wazuh Agent...')
      New-Item -Path "C:\" -Name "Wazuh" -ItemType "directory"
$MultilineComment = @'
-----BEGIN CERTIFICATE-----
MIIE6jCCAtICCQC+BJooG9SfhTANBgkqhkiG9w0BAQsFADAsMQswCQYDVQQGEwJV
UzELMAkGA1UECAwCQ0ExEDAOBgNVBAoMB01hbmFnZXIwHhcNMjIwMTIwMTYzMjAw
WhcNNDkwNjA2MTYzMjAwWjBCMQswCQYDVQQGEwJYWDEVMBMGA1UEBwwMRGVmYXVs
dCBDaXR5MRwwGgYDVQQKDBNEZWZhdWx0IENvbXBhbnkgTHRkMIICIjANBgkqhkiG
9w0BAQEFAAOCAg8AMIICCgKCAgEA2NwOKV8uSTT4L6qL9Oa1xI1oVh+vGzt/EnDl
tMUpFPIN56KTqwICU3LHBoLli+IPDekJs2GzhqZA5hyVZahNqvE9yXonF8qtaeNt
CLbEEKkfCdO7e99KR6e4v5HaeVrL0B80oAH2OcHTsQtlGvApZ6REVuX5gPiMBd6k
p5HxeWJxCFCvx5Wk+YTA88LG/5DOjPHXeBWbP8tG4cQhjyB6PGnYBdiETRXxXoiy
nhwq0kMj3KUg/1mgvvqke1SItV3JbcL9x+dGDg5IGfZ5m9gZ6/oNFwIq2AHC+NNq
LD1BJeSzyI0HrM89kAh+4gdtrEPHfT4gPdvSBGEU8qLvQ8wRW02cwC2wVgxxW8Dw
TQ/bQygHdZcWQf2sXG88jc3znM4qXnGT+305OVEiWIrGrrSa4lCtBRZFIjsNjre+
6PC5QTcPZ/a6LcibllYXtMdkbl6UmDb2d2xLFNZI2VMWWMBPRCec9EzWaQIGpAR2
oyguqZsxFukDEywtv+RsNzgXQylZUuvcUswA3A/6pL9aYKTD1Ewhm7mt8CD7C+Ig
2xSmlgBIcBp8c1LsCWNsbMtymWf33nXKv+5QceFbyHJrh721R5Rur7fZjCoQlYxo
oeq6R/FLE7m7pUSYOzoR9Py/ikjP0j16fDHZm+B06CJY3S3qLNOdz7jbZJ2+x4F4
CWx8+4ECAwEAATANBgkqhkiG9w0BAQsFAAOCAgEALzrVV111uLOJrWuBxyO1CwiD
qdqDdeKrt6N88gp2kpTRPnkE01+Lv3iXo8TFmXCpMEatbT8fzzKCo9mEL7I/rsax
hsK/4l0uyyPuYHsmux9b9ld3g6/SnA6/uxJj2rUF4+J+SJ1GVc2GJtdE7vTkCHcV
uCQ4qJc9T6rkU1xaKpU3q0xylnyeJ9AwP/JQD9wHB4rcA9fNwJPR++GQRlJkkVCV
bJjvoy+PHnJtgwYztwYQNVYcvjPlJxZMln1MbqdxpI4iDiaVJTaoi8X9htBoqyyN
x1GLBF6KyP05gF3PGRLHUmVNgXo5ydoGLYCQy8sp1nT/ZGW101//QqYus3hY6H3f
RpqpIO7CE8fTg743a+4kVIy2U22hC9rqvr12iKLeU+8etJXztoWcu3QoLNg8l4mT
zfv5n3H8koek9KTPp/JfAan6Rw8HyADii1jTm6CMy+2/Z+95LM+LPMGTR4QR7SdS
HblNTm84e34Mshu2jMKLBvfwFctODI5si5gUgmDE1D07ySdxEjvREiQzTf/h8Pgi
6jjOSrPaOSJGf94awofCkmjcDBoTxIkXmQZe0Tr/2+YaehmRmX7EODuNZDAiEHid
26EBZ6leXm9iaHM6erPFCZgS1AFmTf1YH3bO9/GGYy0Q4edvSEngdkdPYAFQWJJI
KnscN7NrUxT7U21NWwA=
-----END CERTIFICATE-----
'@
$MultilineComment -f 'string' | Out-File -Encoding ASCII 'C:\Wazuh\sslagent.cert'
$MultilineComment2 = @'
-----BEGIN PRIVATE KEY-----
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
S5nKP9vUJqNmdJqCLXkQku38w9zLbrY=
-----END PRIVATE KEY-----
'@
$MultilineComment2 -f 'string' | Out-File -Encoding ASCII 'C:\Wazuh\sslagent.key'
#Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.2.4-1.msi -OutFile wazuh-agent.msi; ./wazuh-agent.msi /q WAZUH_MANAGER='collection.e2open.com' WAZUH_REGISTRATION_KEY='C:\Wazuh\sslagent.key' WAZUH_REGISTRATION_CERTIFICATE='C:\Wazuh\sslagent.cert' WAZUH_REGISTRATION_SERVER='collection.e2open.com' WAZUH_AGENT_GROUP='Windows'
      Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.2.5-1.msi -OutFile wazuh-agent-4.2.5-1.msi; ./wazuh-agent-4.2.5-1.msi /q WAZUH_MANAGER='collection.e2open.com' WAZUH_REGISTRATION_KEY='C:\Wazuh\sslagent.key' WAZUH_REGISTRATION_CERTIFICATE='C:\Wazuh\sslagent.cert' WAZUH_REGISTRATION_SERVER='collection.e2open.com' WAZUH_AGENT_GROUP='Windows'
      #Start-Process "msiexec.exe" -ArgumentList $installArgs -Wait
      Start-Sleep -s 10
      Stop-Service -Name "Wazuh"
      Invoke-WebRequest -Uri $LOCAL_INTERNAL_OPTIONS -Headers $Headers -OutFile 'C:\Program Files (x86)\ossec-agent\local_internal_options.conf'
      Invoke-WebRequest -Uri $OTX_CMD -Headers $Headers -OutFile 'C:\Program Files (x86)\ossec-agent\active-response\bin\otx.cmd'
      $filePath = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
      $tempFilePath = "$env:TEMP\$($filePath | Split-Path -Leaf)"
      $find = 'MANAGER'
      $replace = $WAZUH_MANAGER
      (Get-Content -Path $filePath) -replace $find, $replace | Add-Content -Path $tempFilePath
      Remove-Item -Path $filePath
      Move-Item -Path $tempFilePath -Destination $filePath
      Start-Service -Name "Wazuh"

      }
      Catch
      {
      $payload = @{
 "hostname" = "$env:COMPUTERNAME"
  "message" = "Wazuh agent could not be installed"
}
 
Invoke-WebRequest -UseBasicParsing `
 -Body (ConvertTo-Json -Compress -InputObject $payload) `
 -Method Post `
 -Uri "https://shuffler.io/api/v1/hooks/webhook_d1ff340b-5247-49dd-9a8e-1ca1e01f7573"
          $ErrorMessage = $_.Exception.Message
          $FailedItem = $_.Exception.ItemName
          Write-Error -Message "$ErrorMessage $FailedItem"
          exit 1
      }
      Finally
      {
          Remove-Item -Path 'C:\Wazuh' -Recurse –Force
      }

    } else {
        Write-Output "Unable to connect to Wazuh Repo"
}
}

write-host ('Installing Cylance')


#Check if Cylance is installed
if ((Get-WmiObject -Class Win32_Product -Filter "vendor = 'Cylance, Inc.'" | where name -eq "Cylance PROTECT" | Select-Object Name)) {
     try {
        Write-Host "Cylance is installed"
     }
     catch {
         throw $_.Exception.Message
     }
 }
# If Cylance is not installed
 else {
     Write-Host "Cylance is not installed. Proceeding with install."

    $X = 0
    do {
      Write-Output "Waiting for network"
      Start-Sleep -s 5
      $X += 1
    } until(($connectreult = Test-NetConnection $cylance_url -Port 443 | ? { $_.TcpTestSucceeded }) -or $X -eq 3)

    if ($connectreult.TcpTestSucceeded -eq $true){
      Try
      {
      write-host ('Installing Cylance Agent...')
      Invoke-WebRequest -Uri $Cylance_MSI -Headers $Headers -OutFile CylanceProtect_x64.msi
      msiexec /i CylanceProtect_x64.msi /qn PIDKEY=Cfz2EkMsLOhmMxZvTLahxFLE LAUNCHAPP=1 SELFPROTECTIONLEVEL=1

      }
      Catch
      {
      $payload = @{
 "hostname" = "$env:COMPUTERNAME"
  "message" = "Cylance could not be installed"
}
 
Invoke-WebRequest -UseBasicParsing `
 -Body (ConvertTo-Json -Compress -InputObject $payload) `
 -Method Post `
 -Uri "https://shuffler.io/api/v1/hooks/webhook_d1ff340b-5247-49dd-9a8e-1ca1e01f7573"
          $ErrorMessage = $_.Exception.Message
          $FailedItem = $_.Exception.ItemName
          Write-Error -Message "$ErrorMessage $FailedItem"
          exit 1
      }
      Finally
      {
          Write-Output "Cylance install complete"
      }

    } else {
        Write-Output "Unable to connect to Cylance Console"
}
 }

write-host ('Installing Rapid7 Agent')


#Check if Rapid7 is installed
if ((Get-WmiObject -Class Win32_Product -Filter "vendor = 'Rapid7, Inc.'" | where name -eq "Rapid7 Insight Agent" | Select-Object Name)) {
     try {
        Write-Host "Rapid7 Agent is installed"
     }
     catch {
         throw $_.Exception.Message
     }
 }
# If Rapid7 is not installed
 else {
     Write-Host "Rapid7 Agent is not installed. Proceeding with install."

    $X = 0
    do {
      Write-Output "Waiting for network"
      Start-Sleep -s 5
      $X += 1
    } until(($connectreult = Test-NetConnection $cylance_url -Port 443 | ? { $_.TcpTestSucceeded }) -or $X -eq 3)

    if ($connectreult.TcpTestSucceeded -eq $true){
      Try
      {
      write-host ('Installing Rapid7 Agent...')
      Invoke-WebRequest -Uri $Rapid7_MSI -Headers $Headers -OutFile agentInstaller-x86_64.msi
      msiexec /i agentInstaller-x86_64.msi /l*v insight_agent_install_log.log /quiet CUSTOMTOKEN=us:bde227b4-f008-49f7-ab59-4b993c84c389

      }
      Catch
      {
      $payload = @{
 "hostname" = "$env:COMPUTERNAME"
  "message" = "Rapid7 could not be installed"
}
 
Invoke-WebRequest -UseBasicParsing `
 -Body (ConvertTo-Json -Compress -InputObject $payload) `
 -Method Post `
 -Uri "https://shuffler.io/api/v1/hooks/webhook_d1ff340b-5247-49dd-9a8e-1ca1e01f7573"
          $ErrorMessage = $_.Exception.Message
          $FailedItem = $_.Exception.ItemName
          Write-Error -Message "$ErrorMessage $FailedItem"
          exit 1
      }
      Finally
      {
          Write-Output "Rapid7 install complete"
      }

    } else {
        Write-Output "Unable to connect to Rapid7 Console"
}
 }
###Check for running services
if(Get-Service | where name -eq "WazuhSvc" | Where-Object {$_.Status -EQ "Running"}){
   write-host("Wazuh Service is Running")
}else {
   write-host("Wazuh service is not running. Trying to restart")
   Start-Service -Name "WazuhSvc"
   Start-Sleep -s 3
}
if(Get-Service | where name -eq "WazuhSvc" | Where-Object {$_.Status -EQ "Running"}){
   write-host("Wazuh service was started")
}else {
   write-host("Wazuh service could not be restarted")
   $payload = @{
 "hostname" = "$env:COMPUTERNAME"
  "message" = "Wazuh Agent could not be restarted"
}
 
Invoke-WebRequest -UseBasicParsing `
 -Body (ConvertTo-Json -Compress -InputObject $payload) `
 -Method Post `
 -Uri "https://shuffler.io/api/v1/hooks/webhook_d1ff340b-5247-49dd-9a8e-1ca1e01f7573"
}
if(Get-Service | where name -eq "CylanceSvc" | Where-Object {$_.Status -EQ "Running"}){
   write-host("Cylance Service is Running")
}else {
   write-host("Cylance service is not running. Trying to restart")
   Start-Service -Name "CylanceSvc"
   Start-Sleep -s 3
}
if(Get-Service | where name -eq "CylanceSvc" | Where-Object {$_.Status -EQ "Running"}){
   write-host("Cylance service was started")
}else {
   write-host("Cylance service could not be restarted")
   $payload = @{
 "hostname" = "$env:COMPUTERNAME"
  "message" = "Cylance Agent could not be restarted"
}
 
Invoke-WebRequest -UseBasicParsing `
 -Body (ConvertTo-Json -Compress -InputObject $payload) `
 -Method Post `
 -Uri "https://shuffler.io/api/v1/hooks/webhook_d1ff340b-5247-49dd-9a8e-1ca1e01f7573"
}
if(Get-Service | where name -eq "ir_agent" | Where-Object {$_.Status -EQ "Running"}){
   write-host("Rapid7 Service is Running")
}else {
   write-host("Rapid7 service is not running. Trying to restart")
   Start-Service -Name "ir_agent"
   Start-Sleep -s 3
}
if(Get-Service | where name -eq "ir_agent" | Where-Object {$_.Status -EQ "Running"}){
   write-host("Rapid7 service was started")
}else {
   write-host("Rapid7 service could not be restarted")
   $payload = @{
 "hostname" = "$env:COMPUTERNAME"
  "message" = "Rapid7 Agent could not be restarted"
}
 
Invoke-WebRequest -UseBasicParsing `
 -Body (ConvertTo-Json -Compress -InputObject $payload) `
 -Method Post `
 -Uri "https://shuffler.io/api/v1/hooks/webhook_d1ff340b-5247-49dd-9a8e-1ca1e01f7573"
}
if(Get-Service | where name -eq "Sysmon64" | Where-Object {$_.Status -EQ "Running"}){
   write-host("Sysmon64 Service is Running")
}else {
   write-host("Sysmon64 service is not running. Trying to restart")
   Start-Service -Name "Sysmon64"
   Start-Sleep -s 3
}
if(Get-Service | where name -eq "Sysmon64" | Where-Object {$_.Status -EQ "Running"}){
   write-host("Sysmon64 service was started")
}else {
   write-host("Sysmon64 service could not be restarted")
   $payload = @{
 "hostname" = "$env:COMPUTERNAME"
  "message" = "Sysmon64 could not be restarted"
}
 
Invoke-WebRequest -UseBasicParsing `
 -Body (ConvertTo-Json -Compress -InputObject $payload) `
 -Method Post `
 -Uri "https://shuffler.io/api/v1/hooks/webhook_d1ff340b-5247-49dd-9a8e-1ca1e01f7573"
}
$payload = @{
 "hostname" = "$env:COMPUTERNAME"
  "message" = "All InfoSec services up and running"
}
 
Invoke-WebRequest -UseBasicParsing `
 -Body (ConvertTo-Json -Compress -InputObject $payload) `
 -Method Post `
 -Uri "https://shuffler.io/api/v1/hooks/webhook_d1ff340b-5247-49dd-9a8e-1ca1e01f7573"

 
