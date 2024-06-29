# Created by Matthew Dudzinski on Mar, 11th, 2024
# For use in Windows NT 10.0 and above. I cannot guarantee full functionality with older pieces of system software.
# Updated infrequently. Commands may damage your system I am not liable for any damages done to machines. 

# Task 1 Set permissions and checkpoint the begining.
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine
Enable-ComputerRestore -Drive "C:" 
Enable-ComputerRestore -Drive "D:" 
Checkpoint-Computer -Description "Clean-Installation"

# Task 2 Add Windows Features/Disable Windows Features

# Task 3 install main programs via WinGet
winget install -e --id Google.Chrome
winget install -e --id Microsoft.VisualStudio.2022.Enterprise.Preview
winget install -e --id VSCodium.VSCodium
winget install -e --id Valve.Steam
winget install -e --id Overwolf.CurseForge
winget install -e --id Microsoft.Office
winget install -e --id Rclone.Rclone
winget install -e --id SublimeHQ.SublimeText.4
winget install -e --id PuTTY.PuTTY
winget install -e --id WinDirStat.WinDirStat

# Task 4 Disable any accounts not needed
Disable-LocalUser -Name "Guest"

# Task 5 Set services to either stop or start
Set-Service -Name "wuauserv" -StartupType "Automatic" #  Windows Update service automatically begins on start-up 
Start-Service -Name "wuauserv" # Windows Update Service start 

#Set-Service -Name "ftpsvc" -Status "Stopped" // Not needed in standard Windows that doesn't run IIS
#Set-Service -Name "ftpsvc" -StartupType "Disabled" // Not needed in standard Windows that doesn't run IIS

# Task 6 Registry edits

# Disables the Windows Optional Feature SMBv1 protocol
powershell.exe Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -norestart 
# Disable SMBv1 protocol
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" /v Start /t REG_DWORD /d 4 /f

# Disable SMBv1 on LanmanServer
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f

# Restrict null session access on LanmanServer
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v RestrictNullSessAccess /t REG_DWORD /d 1 /f

# Restrict anonymous SAM access
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f

# Restrict anonymous access
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f

# Disable EveryoneIncludesAnonymous
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f

# Restrict remote SAM access
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictRemoteSAM /t REG_SZ /d "O:BAG:BAD:(A;;RC;;;BA)" /f

# Enable machine SID
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v UseMachineId /t REG_DWORD /d 1 /f

# Limit blank password use
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f

# Disable null session fallback
reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0" /v allownullsessionfallback /t REG_DWORD /d 0 /f

# Enable security signature on LanmanWorkstation
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f

# Enable RPC traffic encryption
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f

# Disable command prompt in Terminal Services
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCdm /t REG_DWORD /d 1 /f

# Disable autoplay for non-volume devices
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoAutoplayfornonVolume /t REG_DWORD /d 1 /f

# Disable drive type autorun
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f

# Disable autorun
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAutorun /t REG_DWORD /d 1 /f

# Enable SmartScreen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 1 /f

# Set SmartScreen level to Block
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v ShellSmartScreenLevel /t REG_SZ /d Block /f

# Enable secure channel sealing
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f

# Enable secure channel signing
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f

# Enable advanced protection in Google Chrome
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AdvancedProtectionAllowed" /t REG_DWORD /d 1 /f

# Enable DNS over HTTPS in Google Chrome
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "DnsOverHttpsMode" /t REG_SZ /d on /f

# Set minimum SSL version to TLS 1.0 in Google Chrome
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SSLVersionMin" /t REG_SZ /d tls1 /f

# Disable screen capture in Google Chrome
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ScreenCaptureAllowed" /t REG_DWORD /d 0 /f

# Enable site per process in Google Chrome
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "SitePerProcess" /t REG_DWORD /d 1 /f

# Enable TLS 1.3 hardening for local anchors in Google Chrome
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "TLS13HardeningForLocalAnchorsEnabled" /t REG_DWORD /d 1 /f

# Disable video capture in Google Chrome
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "VideoCaptureAllowed" /t REG_DWORD /d 0 /f

# Disable ambient authentication in private modes in Google Chrome
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AmbientAuthenticationInPrivateModesEnabled" /t REG_DWORD /d 0 /f

# Disable audio capture in Google Chrome
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AudioCaptureAllowed" /t REG_DWORD /d 0 /f

# Enable audio sandboxing in Google Chrome
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "AudioSandboxEnabled" /t REG_DWORD /d 1 /f

# Task 7 Auditiing of system events that are critical

# Enable auditing for Security Group Management with both success and failure events
Auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable

# Enable auditing for Process Creation with both success and failure events
Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# Enable auditing for Logoff with success events only and disable failure events
Auditpol /set /subcategory:"Logoff" /success:enable /failure:disable

# Enable auditing for Logon with both success and failure events
Auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# Disable auditing for Filtering Platform Connection both success and failure events
Auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:disable

# Enable auditing for Removable Storage with both success and failure events
Auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable

# Disable auditing for SAM both success and failure events
Auditpol /set /subcategory:"SAM" /success:disable /failure:disable

# Disable auditing for Filtering Platform Policy Change both success and failure events
Auditpol /set /subcategory:"Filtering Platform Policy Change" /success:disable /failure:disable

# Enable auditing for IPsec Driver with both success and failure events
Auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable

# Enable auditing for Security State Change with both success and failure events
Auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable

# Enable auditing for Security System Extension with both success and failure events
Auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable

# Enable auditing for System Integrity with both success and failure events
Auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable

# Enable auditing for System, Account Management, Account Logon, Logon/Logoff, and Policy Change categories with both success and failure events
auditpol /set /category:"System","Account Management","Account Logon","Logon/Logoff","Policy Change" /failure:enable /success:enable

# Enable auditing for DS Access and Object Access categories with failure events only
auditpol /set /category:"DS Access","Object Access" /failure:enable

# Task 8 Set firewall profiles to true
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True

# Task 9 Disable Remote Assistance
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp" -Value 0
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowToGetHelp"

# Task 10 Disable LanmanServer
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareWks" -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "AutoShareServer" -Value 0
Restart-Service -Name 'LanmanServer'

# Task 11 Set firewall rules 
netsh Advfirewall set allprofiles state on
netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files (x86)\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block appvlp.exe netconns" program="C:\Program Files\Microsoft Office\root\client\AppVLP.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\SysWOW64\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\system32\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block certutil.exe netconns" program="%systemroot%\SysWOW64\certutil.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\system32\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block cmstp.exe netconns" program="%systemroot%\SysWOW64\cmstp.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\SysWOW64\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\system32\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block esentutl.exe netconns" program="%systemroot%\SysWOW64\esentutl.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\system32\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block expand.exe netconns" program="%systemroot%\SysWOW64\expand.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\system32\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block extrac32.exe netconns" program="%systemroot%\SysWOW64\extrac32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\system32\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block findstr.exe netconns" program="%systemroot%\SysWOW64\findstr.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\system32\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\SysWOW64\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\system32\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block makecab.exe netconns" program="%systemroot%\SysWOW64\makecab.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\SysWOW64\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\system32\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block msiexec.exe netconns" program="%systemroot%\SysWOW64\msiexec.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\system32\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block nltest.exe netconns" program="%systemroot%\SysWOW64\nltest.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\SysWOW64\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\system32\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block odbcconf.exe netconns" program="%systemroot%\SysWOW64\odbcconf.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\system32\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block pcalua.exe netconns" program="%systemroot%\SysWOW64\pcalua.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\system32\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block regasm.exe netconns" program="%systemroot%\SysWOW64\regasm.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\SysWOW64\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\system32\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block replace.exe netconns" program="%systemroot%\SysWOW64\replace.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block rpcping.exe netconns" program="%systemroot%\SysWOW64\rpcping.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\system32\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block rundll32.exe netconns" program="%systemroot%\SysWOW64\rundll32.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\SysWOW64\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\system32\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block scriptrunner.exe netconns" program="%systemroot%\SysWOW64\scriptrunner.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\system32\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block SyncAppvPublishingServer.exe netconns" program="%systemroot%\SysWOW64\SyncAppvPublishingServer.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\system32\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block wmic.exe netconns" program="%systemroot%\SysWOW64\wbem\wmic.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\system32\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
netsh advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\SysWOW64\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any

# Task 12 Install the MS Powershell updater for easier and quicker method of updateing windows
# Task 12 Install the MS Powershell updater for easier and quicker method of updating windows
Install-Module PSWindowsUpdate
Add-WUServiceManager -MicrosoftUpdate
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot | Out-File "C:\($env.computername-Get-Date -f yyyy-MM-dd)-MSUpdates.log" -Force

# Task 13 The machine creates a restore point after the machine is ready and locks PowerShell execution
Checkpoint-Computer -Description "Post Script"
Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope LocalMachine
