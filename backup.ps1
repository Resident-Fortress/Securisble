# rclone usage not needed at this time, commented out for further notice
# rclone selfupdate --stable
# rclone config --config rclone.conf

# $RemoteFolder = "Google Drive:"
# $LocalBackupFolder= "BackupData"
# $LastestBackupFolder = Join-Path $LocalBackupFolder "latest"
# $HistoryBackupFolder = Join-Path $LocalBackupFolder ((Get-Date).ToString("yyyyMMdd-HHmmss"))

# rclone sync $RemoteFolder $LastestBackupFolder --backup-dir="$HistoryBackupFolder" --config rclone.conf --track-renames --progress



#Credit to Aaron Zercher for the script // Website listed here: https://community.spiceworks.com/t/user-data-backup-and-restore-with-powershell-need-help-with-the-restore/685290
$Technician = Read-Host -Prompt "What Technician is auditing this computer (First name only)"
$Username = Read-Host -Prompt "Who does this computer belong to (First initial, last name)"
$NetworkPassword = Read-Host -Prompt "Please enter the network password"

######## Declares the Backup location ########
$destination = "\\tol001\techdrive$\$Technician\$Username"

######## Declares the data to be backed up ########
$folder = "Desktop",
"Downloads",
"Favorites",
"Documents",
"Music",
"Pictures",
"Videos",
"AppData\Local\Mozilla",
"AppData\Local\Google\Chrome",
"AppData\Roaming\Mozilla"

######## Calls Eviroment Variables for the local user and data location ########
$username = gc env:username
$userprofile = gc env:userprofile
$appData = gc env:localAPPDATA

###### Backup Data section ########
		
	write-host -ForegroundColor green "Backing up data from local machine for $username"
    
    New-Item -Type Directory -Path ($destination + "\Audit Information") -Force |Out-Null
    New-Item -Type Directory -Path ($destination + "\RegistryInformation") -Force |Out-Null
    
    foreach ($f in $folder)
	{	
		$currentLocalFolder = $userprofile + "\" + $f
		$currentRemoteFolder = $destination + "\" + $f
		$currentFolderSize = (Get-ChildItem -ErrorAction silentlyContinue $currentLocalFolder -Recurse -Force | Measure-Object -ErrorAction silentlyContinue -Property Length -Sum ).Sum / 1MB
		$currentFolderSizeRounded = [System.Math]::Round($currentFolderSize)
		write-host -ForegroundColor cyan "  $f... ($currentFolderSizeRounded MB)"
		Copy-Item -ErrorAction silentlyContinue -recurse $currentLocalFolder $currentRemoteFolder
	}
	
######## Writes the password to a .txt file in Plain Text ########	
    Out-file -filepath "$destination\Audit Information\NewBuild.txt" -inputobject $NetworkPassword

######## Begin Registry Backup ########
	Write-Host -ForegroundColor Green "Backing up Network settings"
	Get-ItemProperty -Path "HKCU:\NETWORK" | Export-CliXML "$destination\RegistryInformation\network.reg"
	Write-Host -ForegroundColor Green "Backing up Printers"
	Get-ItemProperty -Path "HKCU:\Printers" | Export-CliXML "$destination\RegistryInformation\printers.reg"
	Write-Host -ForegroundColor Green "Backing up Printers1"
	Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Devices" | Export-Clixml "$destination\RegistryInformation\printers1.reg"
	Write-Host -ForegroundColor Green "Backing up Printer2"
	Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\PrinterPorts" | Export-Clixml "$destination\RegistryInformation\printers2.reg"
	Write-Host -ForegroundColor Green "Backing up Printers3"
	Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows" | Export-Clixml "$destination\RegistryInformation\printers3.reg"
    
	write-host -ForegroundColor green "Backup complete!"
