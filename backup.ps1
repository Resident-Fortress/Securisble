rclone selfupdate --stable
rclone config --config rclone.conf

$RemoteFolder = "Google Drive:"
$LocalBackupFolder= "BackupData"
$LastestBackupFolder = Join-Path $LocalBackupFolder "latest"
$HistoryBackupFolder = Join-Path $LocalBackupFolder ((Get-Date).ToString("yyyyMMdd-HHmmss"))

rclone sync $RemoteFolder $LastestBackupFolder --backup-dir="$HistoryBackupFolder" --config rclone.conf --track-renames --progress