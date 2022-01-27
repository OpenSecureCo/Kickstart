$wazuh_repo = 'packages.wazuh.com'
$wazuh_major = '4.x'
$wazuh_package = 'wazuh-agent-4.2.5-1.msi'
$wazuh_downloadlink = 'https://packages.wazuh.com/4.x/windows/wazuh-agent-4.2.5-1.msi'
$WAZUH_MANAGER="w.g4ns.com"
$WAZUH_REGISTRATION_SERVER="w.g4ns.com"
$WAZUH_MANAGER_PORT="1514"
$WAZUH_PROTOCOL="TCP"
$WAZUH_REGISTRATION_PASSWORD="ytrHWtpxQ986G8Jt"
$WAZUH_AGENT_GROUP="G4NS"
$sysinternals_repo = 'download.sysinternals.com'
$sysinternals_downloadlink = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
$sysinternals_folder = 'C:\Program Files\sysinternals'
$sysinternals_zip = 'SysinternalsSuite.zip'
$sysmonconfig_downloadlink = 'https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml'
$sysmonconfig_file = 'sysmonconfig-export.xml'
$autorunsps1_downloadlink = 'https://raw.githubusercontent.com/OpenSecureCo/Kickstart/main/autoruns.ps1'
$logonsession_downloadlink = 'https://raw.githubusercontent.com/OpenSecureCo/Kickstart/main/logonsessions.ps1'
$sigcheck_downloadlink = 'https://raw.githubusercontent.com/OpenSecureCo/Kickstart/main/sigcheck.ps1'
$autorunsps1_file = 'autoruns.ps1'
$logonsession_file = 'logonsessions.ps1'
$sigcheck_file = 'sigcheck.ps1'
#Stop-Service -Name "Wazuh"
#$MyApp = Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq "Wazuh Agent"}
#$MyApp.Uninstall()
#Start-Sleep -s 15
#Remove-Item 'C:\Program Files (x86)\ossec-agent' -Force -Recurse
#New-Item -Path "C:\" -Name "Wazuh" -ItemType "directory"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
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
          $ErrorMessage = $_.Exception.Message
          $FailedItem = $_.Exception.ItemName
          Write-Error -Message "$ErrorMessage $FailedItem"
          exit 1
      }
    } 
      
write-host ('Installing Sysmon for new configuration file...')

    $serviceName = 'Sysmon64'
    If (Get-Service $serviceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $serviceName 
    write-host ('Installing Sysmon with new config')
    $path = 'C:\Windows\'
    Set-Location $path\Sysmon
    .\sysmon64.exe -u force
    Start-Sleep -s 5
    Remove-Item 'C:\Windows\Sysmon' -Recurse -Force
    else {
     Write-Host "Sysmon Uninstall Failed."
     exit 1
 }
    
if (Test-Path -Path $sysinternals_folder) {
    write-host ('Sysinternals folder already exists')
} else {
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
    Invoke-WebRequest -Uri $sysmonconfig_downloadlink -OutFile $OutPath\$sysmonconfig_file
    Invoke-WebRequest -Uri $autorunsps1_downloadlink -OutFile 'C:\Program Files\sysinternals\autoruns.ps1'
    Invoke-WebRequest -Uri $logonsession_downloadlink -OutFile 'C:\Program Files\sysinternals\logonsessions.ps1'
    Invoke-WebRequest -Uri $sigcheck_downloadlink -OutFile 'C:\Program Files\sysinternals\sigcheck.ps1'
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


#If PowerShell7 does not exist then install it
if (-not(Get-WmiObject -Class Win32_Product | Where-Object{$_.Name -eq "PowerShell 7-x64"})) {
     try {
        Invoke-WebRequest -Uri https://github.com/PowerShell/PowerShell/releases/download/v7.2.0/PowerShell-7.2.0-win-x64.msi -OutFile PowerShell-7.2.0-win-x64.msi; ./PowerShell-7.2.0-win-x64.msi /q
        New-Item -Path "C:\Windows" -Name "PowerShell7" -ItemType "directory"
        cd C:\Windows\PowerShell7
        Invoke-WebRequest -Uri https://raw.githubusercontent.com/OpenSecureCo/Kickstart/main/alienvault_otx.ps1 -OutFile alienvault_otx.ps1
     }
     catch {
         throw $_.Exception.Message
     }
 }
# If the PowerShell7 already exists, show the message and do nothing.
 else {
     Write-Host "PowerShell7 Already Exists."
 }

$serviceName = 'Wazuh'
If (Get-Service $serviceName -ErrorAction SilentlyContinue) {
    write-host ('Wazuh Agent Is Already Installed')
    write-host ('Stopping Wazuh To Configure Advanced Features')
    Stop-Service -Name "Wazuh"
    Invoke-WebRequest -Uri https://raw.githubusercontent.com/OpenSecureCo/Kickstart/main/local_internal_options.conf -OutFile 'C:\Program Files (x86)\ossec-agent\local_internal_options.conf'
    Invoke-WebRequest -Uri https://raw.githubusercontent.com/OpenSecureCo/Kickstart/main/agent_ossec.conf -OutFile 'C:\Program Files (x86)\ossec-agent\ossec.conf'
    Invoke-WebRequest -Uri https://raw.githubusercontent.com/OpenSecureCo/Kickstart/main/otx.cmd -OutFile 'C:\Program Files (x86)\ossec-agent\active-response\bin\otx.cmd'
    $filePath = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
    $tempFilePath = "$env:TEMP\$($filePath | Split-Path -Leaf)"
    $find = 'MANAGER'
    $replace = $WAZUH_MANAGER
    (Get-Content -Path $filePath) -replace $find, $replace | Add-Content -Path $tempFilePath
    Remove-Item -Path $filePath
    Move-Item -Path $tempFilePath -Destination $filePath
    write-host ('Starting Wazuh')
    Start-Service -Name "Wazuh"


} else {
    $OutPath = $env:TMP
    $output = $wazuh_package

    $installArgs = @(
      "/i $OutPath\$output"
      "/q"
      "WAZUH_MANAGER=`"$WAZUH_MANAGER`""
      "WAZUH_REGISTRATION_SERVER=`"$WAZUH_REGISTRATION_SERVER`""
      "WAZUH_MANAGER_PORT=`"$WAZUH_MANAGER_PORT`""
      "WAZUH_PROTOCOL=`"$WAZUH_PROTOCOL`""
      "WAZUH_REGISTRATION_PASSWORD=`"$WAZUH_REGISTRATION_PASSWORD`""
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
      Invoke-WebRequest -Uri $wazuh_downloadlink -OutFile $OutPath\$output
      write-host ('Installing Wazuh Agent...')
      Start-Process "msiexec.exe" -ArgumentList $installArgs -Wait
      Start-Sleep -s 10
      Stop-Service -Name "Wazuh"
      Invoke-WebRequest -Uri https://raw.githubusercontent.com/OpenSecureCo/Kickstart/main/local_internal_options.conf -OutFile 'C:\Program Files (x86)\ossec-agent\local_internal_options.conf'
      Invoke-WebRequest -Uri https://raw.githubusercontent.com/OpenSecureCo/Kickstart/main/agent_ossec.conf -OutFile 'C:\Program Files (x86)\ossec-agent\ossec.conf'
      Invoke-WebRequest -Uri https://raw.githubusercontent.com/OpenSecureCo/Kickstart/main/otx.cmd -OutFile 'C:\Program Files (x86)\ossec-agent\active-response\bin\otx.cmd'
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
        Write-Output "Unable to connect to Wazuh Repo"
}
}
