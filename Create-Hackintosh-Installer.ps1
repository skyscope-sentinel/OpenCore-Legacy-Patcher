#Requires -Version 5.1

<#
.SYNOPSIS
    Creates a Hackintosh installer.
.DESCRIPTION
    This script gathers system hardware information and (in the future) will guide the user
    through creating a Hackintosh macOS installer.
.NOTES
    Author: Your Name
    Date: $(Get-Date -Format yyyy-MM-dd)
#>

# Strict mode for better error handling
Set-StrictMode -Version Latest

# Function to check for Administrator privileges
function Test-IsAdmin {
    <#
    .SYNOPSIS
        Checks if the script is running with Administrator privileges.
    .DESCRIPTION
        Uses the current WindowsPrincipal to determine if the user is in the Administrator role.
        If not, it displays an error message and exits the script.
    .EXAMPLE
        Test-IsAdmin
    #>
    Write-Verbose "Checking for Administrator privileges..."
    $currentUser = New-Object System.Security.Principal.WindowsPrincipal ([System.Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentUser.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "Administrator privileges are required to run this script. Please re-run as Administrator."
        # In a GUI environment, you might prompt to re-launch as admin.
        # For now, we just exit.
        Exit 1 # Exit with a non-zero status code to indicate an error
    } else {
        Write-Host "Running with Administrator privileges." -ForegroundColor Green
    }
}

# Function to gather system hardware information
function Get-SystemInfo {
    <#
    .SYNOPSIS
        Gathers essential system hardware information.
    .DESCRIPTION
        Collects details about CPU, Motherboard, RAM, GPUs, Ethernet controllers, and Storage devices.
    .OUTPUTS
        PSCustomObject - An object containing all collected hardware information.
    .EXAMPLE
        $hardwareInfo = Get-SystemInfo
        Write-Host "CPU: $($hardwareInfo.CPU)"
    #>
    Write-Host "Gathering system hardware information..." -ForegroundColor Cyan
    $systemInfo = [PSCustomObject]@{
        CPU = $null
        Motherboard = $null
        RAM_GB = $null
        GPUs = @()
        Ethernet = @()
        Storage = @()
    }

    # Get CPU Information
    try {
        Write-Verbose "Fetching CPU information..."
        $systemInfo.CPU = Get-WmiObject -Class Win32_Processor | Select-Object -ExpandProperty Name -ErrorAction Stop
        Write-Host "  [+] CPU: $($systemInfo.CPU)"
    }
    catch {
        Write-Warning "Could not retrieve CPU information: $($_.Exception.Message)"
    }

    # Get Motherboard Information
    try {
        Write-Verbose "Fetching Motherboard information..."
        $mbInfo = Get-WmiObject -Class Win32_BaseBoard | Select-Object Manufacturer, Product -ErrorAction Stop
        $systemInfo.Motherboard = "$($mbInfo.Manufacturer) $($mbInfo.Product)"
        Write-Host "  [+] Motherboard: $($systemInfo.Motherboard)"
    }
    catch {
        Write-Warning "Could not retrieve Motherboard information: $($_.Exception.Message)"
    }

    # Get RAM Information
    try {
        Write-Verbose "Fetching RAM information..."
        $totalMemoryBytes = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty TotalPhysicalMemory -ErrorAction Stop
        $systemInfo.RAM_GB = [Math]::Round($totalMemoryBytes / 1GB, 2)
        Write-Host "  [+] RAM: $($systemInfo.RAM_GB) GB"
    }
    catch {
        Write-Warning "Could not retrieve RAM information: $($_.Exception.Message)"
    }

    # Get GPU Information
    try {
        Write-Verbose "Fetching GPU information..."
        $gpus = Get-PnpDevice -Class 'Display' -ErrorAction Stop | Where-Object {$_.Status -eq 'OK' -and $_.ConfigManagerErrorCode -eq 0}
        $gpuList = @()
        foreach ($gpu in $gpus) {
            $instanceId = $gpu.InstanceId
            $vendorId = $null
            $deviceId = $null

            # Attempt to parse VEN_xxxx and DEV_xxxx from InstanceId
            if ($instanceId -match 'VEN_([0-9A-F]{4})') {
                $vendorId = $Matches[1]
            }
            if ($instanceId -match 'DEV_([0-9A-F]{4})') {
                $deviceId = $Matches[1]
            }

            $gpuList += [PSCustomObject]@{
                Name = $gpu.FriendlyName
                VendorID = $vendorId
                DeviceID = $deviceId
                InstanceId = $instanceId # For reference
            }
            Write-Host "  [+] GPU: $($gpu.FriendlyName) (VEN_ $($vendorId), DEV_ $($deviceId))"
        }
        $systemInfo.GPUs = $gpuList
    }
    catch {
        Write-Warning "Could not retrieve GPU information: $($_.Exception.Message)"
        if ($_.Exception.GetType().Name -eq 'CmdletNotFoundException') {
            Write-Warning "  Make sure you are running PowerShell 5.1 or newer for Get-PnpDevice."
        }
    }

    # Get Ethernet Information
    try {
        Write-Verbose "Fetching Ethernet information..."
        $ethernetAdapters = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object {$_.MediaType -eq '802.3'}
        $ethernetList = @()
        foreach ($adapter in $ethernetAdapters) {
            $ethernetList += [PSCustomObject]@{
                Name = $adapter.Name
                Description = $adapter.InterfaceDescription
                MacAddress = $adapter.MacAddress
            }
            Write-Host "  [+] Ethernet: $($adapter.Name) ($($adapter.InterfaceDescription))"
        }
        $systemInfo.Ethernet = $ethernetList
    }
    catch {
        Write-Warning "Could not retrieve Ethernet information: $($_.Exception.Message)"
        if ($_.Exception.GetType().Name -eq 'CmdletNotFoundException') {
            Write-Warning "  Get-NetAdapter is available in PowerShell 3.0 and newer. Ensure your system meets this requirement."
        }
    }

    # Get Storage Information
    try {
        Write-Verbose "Fetching Storage information..."
        $disks = Get-PhysicalDisk -ErrorAction Stop | Select-Object FriendlyName, Manufacturer, Model, @{Name="SizeGB"; Expression={[Math]::Round($_.Size / 1GB, 2)}}
        $storageList = @()
        foreach ($disk in $disks) {
            $storageList += $disk
            Write-Host "  [+] Storage: $($disk.FriendlyName) ($($disk.Model), $([string]$disk.SizeGB) GB)"
        }
        $systemInfo.Storage = $storageList
    }
    catch {
        Write-Warning "Could not retrieve Storage information: $($_.Exception.Message)"
        if ($_.Exception.GetType().Name -eq 'CmdletNotFoundException') {
            Write-Warning "  Get-PhysicalDisk is available in PowerShell 4.0 (Windows 8/Server 2012 R2) and newer."
        }
    }

    return $systemInfo
}

# Function to get available USB drives
function Get-AvailableUsbDrives {
    Write-Host "`nScanning for available USB drives..." -ForegroundColor Cyan
    $usbDrives = @()
    try {
        $disks = Get-Disk | Where-Object { $_.BusType -eq 'USB' -and $_.OperationalStatus -eq 'Online' } -ErrorAction Stop
        if ($null -eq $disks -or $disks.Count -eq 0) {
            Write-Host "  No USB storage devices found."
            return $null
        }

        foreach ($disk in $disks) {
            $driveLetters = (Get-Partition -DiskNumber $disk.DiskNumber | Get-Volume).DriveLetter | Where-Object {$null -ne $_}
            $driveLettersString = ($driveLetters | Sort-Object) -join ', '
            if ([string]::IsNullOrWhiteSpace($driveLettersString)) {
                $driveLettersString = "N/A"
            }
            $isActuallyRemovable = $false 
            try {
                if ($disk.IsRemovable -eq $true) {
                    $isActuallyRemovable = $true
                }
            } catch [System.Management.Automation.PropertyNotFoundException] {
                Write-Verbose "Disk $($disk.DiskNumber) ('$($disk.FriendlyName)') does not have an 'IsRemovable' property. Assuming Fixed (not explicitly removable)."
            } catch {
                Write-Warning "An unexpected error occurred while checking 'IsRemovable' for disk $($disk.DiskNumber) ('$($disk.FriendlyName)'): $($_.Exception.Message)"
            }
            $usbDrives += [PSCustomObject]@{
                DiskNumber = $disk.DiskNumber
                FriendlyName = if ($null -ne $disk.FriendlyName -and $disk.FriendlyName.Trim() -ne "") {$disk.FriendlyName} else {$disk.Model}
                SizeGB = [Math]::Round($disk.Size / 1GB, 2)
                DriveLetters = $driveLettersString
                IsMarkedRemovable = $isActuallyRemovable
            }
            $removableStatus = if ($isActuallyRemovable) { "Removable" } else { "Fixed (External USB Storage)" }
            Write-Host "  [+] Found USB: $($disk.FriendlyName) (Disk $($disk.DiskNumber), $($([Math]::Round($disk.Size / 1GB, 2))) GB, Type: $removableStatus, Letters: $driveLettersString)"
        }
    }
    catch {
        Write-Warning "An error occurred while scanning for USB drives: $($_.Exception.Message)"
        if ($_.Exception.GetType().Name -eq 'CmdletNotFoundException') {
            Write-Warning "  Get-Disk, Get-Partition, or Get-Volume cmdlets might not be available. Ensure PowerShell 4.0+ (Windows 8/Server 2012 R2 or newer)."
        }
        return $null
    }
    if ($usbDrives.Count -eq 0) {
        Write-Host "  No suitable USB storage devices found after processing."
        return $null
    }
    return $usbDrives
}

# Function to allow user to select a USB drive
function Select-UsbDrive {
    param (
        [Parameter(Mandatory=$true)]
        [array]$AvailableDrives,
        [Parameter(Mandatory=$false)]
        [int]$MinimumSizeGB = 16
    )
    if ($null -eq $AvailableDrives -or $AvailableDrives.Count -eq 0) {
        Write-Warning "No USB drives provided to select from."
        return $null
    }
    Write-Host "`nAvailable USB Drives for Installer Creation:" -ForegroundColor Yellow
    for ($i = 0; $i -lt $AvailableDrives.Count; $i++) {
        $drive = $AvailableDrives[$i]
        $typeDisplay = if ($drive.IsMarkedRemovable) { "Removable" } else { "Fixed (External USB Storage)" }
        Write-Host ("{0,3}. Disk {1}: {2} ({3} GB) - Type: {4} - Drive(s): {5}" -f ($i + 1), $drive.DiskNumber, $drive.FriendlyName, $drive.SizeGB, $typeDisplay, $drive.DriveLetters)
    }
    $confirmedSelectedDrive = $null
    while ($null -eq $confirmedSelectedDrive) {
        $candidateDrive = $null
        try {
            $choice = Read-Host -Prompt "Enter the number of the USB drive you want to use (or 'q' to quit)"
            if ($choice -eq 'q') {
                Write-Host "USB drive selection aborted by user." -ForegroundColor Yellow
                return $null
            }
            $choiceIndex = [int]$choice - 1
            if ($choiceIndex -ge 0 -and $choiceIndex -lt $AvailableDrives.Count) {
                $candidateDrive = $AvailableDrives[$choiceIndex]
                if ($candidateDrive.SizeGB -ge $MinimumSizeGB) {
                    if (-not $candidateDrive.IsMarkedRemovable) {
                        Write-Warning "--------------------------------------------------------------------"
                        Write-Warning "CAUTION: The selected drive '$($candidateDrive.FriendlyName)' (Disk $($candidateDrive.DiskNumber))"
                        Write-Warning "is a USB-connected storage device NOT marked as 'Removable' by the OS."
                        Write-Warning "This could be an external hard drive or SSD that contains important data."
                        Write-Warning "Formatting this drive will ERASE ALL DATA ON IT."
                        Write-Warning "It is generally recommended to use a USB flash drive for installers."
                        Write-Warning "--------------------------------------------------------------------"
                        $confirmFixed = Read-Host "To confirm you want to format this non-removable USB storage device, please type its Disk Number '$($candidateDrive.DiskNumber)' and press Enter:"
                        if ($confirmFixed -ne $candidateDrive.DiskNumber.ToString()) {
                            Write-Warning "Confirmation failed. Selection cancelled. Please choose another drive."
                            $candidateDrive = $null 
                            continue 
                        } else {
                            Write-Host "Proceeding with selected non-removable USB storage Disk $($candidateDrive.DiskNumber) after explicit confirmation." -ForegroundColor Green
                            $confirmedSelectedDrive = $candidateDrive 
                        }
                    } else {
                        $confirmedSelectedDrive = $candidateDrive 
                    }
                } else {
                    Write-Warning ("Selected drive '$($candidateDrive.FriendlyName)' is $($candidateDrive.SizeGB)GB. Minimum required size is $($MinimumSizeGB)GB.")
                    Write-Warning "Please choose a different drive or ensure the drive meets the size requirement."
                }
            } else {
                Write-Warning "Invalid selection. Please enter a number from the list."
            }
        }
        catch {
            Write-Warning "Invalid input. Please enter a valid number."
        }
    } 
    if ($confirmedSelectedDrive) {
         Write-Host "You selected: Disk $($confirmedSelectedDrive.DiskNumber) - $($confirmedSelectedDrive.FriendlyName) ($($confirmedSelectedDrive.SizeGB) GB), Type: $(if ($confirmedSelectedDrive.IsMarkedRemovable) {'Removable'} else {'Fixed (External USB Storage)'})" -ForegroundColor Green
    }
    return $confirmedSelectedDrive
}

function Prepare-UsbDrive {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$UsbDrive 
    )
    Write-Host "`nPreparing USB Drive: Disk $($UsbDrive.DiskNumber) - $($UsbDrive.FriendlyName) ($($UsbDrive.SizeGB) GB)" -ForegroundColor Yellow
    Write-Warning "ALL DATA ON DISK $($UsbDrive.DiskNumber) ($($UsbDrive.FriendlyName)) WILL BE ERASED!"
    $confirmation = Read-Host "Are you absolutely sure you want to continue? Type 'YES' to proceed:"
    if ($confirmation -ne 'YES') {
        Write-Host "USB drive preparation aborted by user." -ForegroundColor Red
        return $null
    }
    Write-Host "Proceeding with wiping Disk $($UsbDrive.DiskNumber)..."
    try {
        Write-Host "  Clearing disk $($UsbDrive.DiskNumber)... (This may take a few moments)"
        Clear-Disk -Number $UsbDrive.DiskNumber -RemoveData -RemoveOEM -Confirm:$false -PassThru -ErrorAction Stop
        Write-Host "  Disk cleared successfully." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to clear disk $($UsbDrive.DiskNumber). Error: $($_.Exception.Message)"
        Write-Warning "Make sure no File Explorer windows are open for this drive, and no other processes are using it."
        return $null
    }
    try {
        Write-Host "  Initializing disk $($UsbDrive.DiskNumber) as GPT..."
        Initialize-Disk -Number $UsbDrive.DiskNumber -PartitionStyle GPT -PassThru -ErrorAction Stop | Out-Null
        Write-Host "  Disk initialized as GPT successfully." -ForegroundColor Green
    }
    catch {
        $errorMessage = $_.Exception.Message
        if ($errorMessage -match "The disk has already been initialized." -or $errorMessage -match "MSFT_Disk") {
            Write-Host "  Note: Disk $($UsbDrive.DiskNumber) was already initialized as GPT (which is acceptable)." -ForegroundColor Yellow
        } else {
            Write-Error "Failed to initialize disk $($UsbDrive.DiskNumber) as GPT. Error: $errorMessage"
            return $null
        }
    }
    $efiPartition = $null
    $efiVolume = $null
    try {
        Write-Host "  Creating EFI partition (500MB, FAT32)..."
        $efiPartitionType = '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
        $efiPartition = New-Partition -DiskNumber $UsbDrive.DiskNumber -Size 500MB -GptType $efiPartitionType -ErrorAction Stop
        Start-Sleep -Seconds 5 
        $efiVolume = Format-Volume -Partition $efiPartition -FileSystem FAT32 -NewFileSystemLabel "EFI" -Confirm:$false -Force -ErrorAction Stop
        Write-Host "  EFI partition created and formatted as FAT32 (Label: EFI)." -ForegroundColor Green
        if ($efiVolume.DriveLetter) {
            Write-Host "    EFI Volume assigned Drive Letter: $($efiVolume.DriveLetter)"
        } else {
            Write-Host "    EFI Volume did not automatically get a drive letter. Manual assignment might be needed if issues occur."
        }
    }
    catch {
        Write-Error "Failed to create or format EFI partition on disk $($UsbDrive.DiskNumber). Error: $($_.Exception.Message)"
        return $null
    }
    $macOsPartition = $null
    $macOsVolume = $null
    try {
        Write-Host "  Creating macOS Installer partition (exFAT, remaining space)..."
        $macOsPartition = New-Partition -DiskNumber $UsbDrive.DiskNumber -UseMaximumSize -ErrorAction Stop
        Start-Sleep -Seconds 5
        $macOsVolume = Format-Volume -Partition $macOsPartition -FileSystem exFAT -NewFileSystemLabel "MACOS_INSTALL" -Confirm:$false -Force -ErrorAction Stop
        Write-Host "  macOS Installer partition created and formatted as exFAT (Label: MACOS_INSTALL)." -ForegroundColor Green
         if ($macOsVolume.DriveLetter) {
            Write-Host "    MACOS_INSTALL Volume assigned Drive Letter: $($macOsVolume.DriveLetter)"
        }
    }
    catch {
        Write-Error "Failed to create or format macOS Installer partition on disk $($UsbDrive.DiskNumber). Error: $($_.Exception.Message)"
        return $null
    }
    Write-Host "`n----------------------------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host "IMPORTANT: The 'MACOS_INSTALL' partition (Drive: $($macOsVolume.DriveLetter): if assigned) has been formatted as exFAT." -ForegroundColor Yellow
    Write-Host "You MUST reformat this partition to 'Mac OS Extended (Journaled)' or 'APFS'" -ForegroundColor Yellow
    Write-Host "using Disk Utility from within the macOS Installer environment (or another Mac)" -ForegroundColor Yellow
    Write-Host "BEFORE you copy the macOS installation files to it." -ForegroundColor Yellow
    Write-Host "----------------------------------------------------------------------------------"
    return [PSCustomObject]@{
        Success = $true
        EfiVolume = $efiVolume 
        MacOsInstallVolume = $macOsVolume 
        EfiPartitionNumber = $efiPartition.PartitionNumber
        MacOsInstallPartitionNumber = $macOsPartition.PartitionNumber
    }
}

function Invoke-DownloadFile { param ([Parameter(Mandatory=$true)][string]$Url, [Parameter(Mandatory=$true)][string]$OutfilePath)
    $fileName = Split-Path -Path $OutfilePath -Leaf; Write-Host "Attempting to download '$fileName' from $Url" -ForegroundColor Cyan
    if (Test-Path -Path $OutfilePath -PathType Leaf) { $fileInfo = Get-Item -Path $OutfilePath; if ($fileInfo.Length -gt 0) { Write-Host "  File '$fileName' already exists in '$((Split-Path -Path $OutfilePath -Parent))' and is not empty. Skipping download." -ForegroundColor Green; return $true } else { Write-Warning "  File '$fileName' exists but is empty. Will attempt to re-download."}}
    try { Write-Host "  Downloading... (this may take a moment)"; Invoke-WebRequest -Uri $Url -OutFile $OutfilePath -UseBasicParsing -ErrorAction Stop; Write-Host "  Successfully downloaded '$fileName' to '$((Split-Path -Path $OutfilePath -Parent))'" -ForegroundColor Green; return $true }
    catch { Write-Error "Failed to download '$fileName' from '$Url`. Error: $($_.Exception.Message)"; if (Test-Path -Path $OutfilePath -PathType Leaf) { try { Remove-Item -Path $OutfilePath -Force -ErrorAction SilentlyContinue } catch { Write-Warning "Could not remove incomplete file: $OutfilePath" }}; return $false }
}

function Extract-ZipArchive {
    param (
        [Parameter(Mandatory=$true)][string]$SourcePath,
        [Parameter(Mandatory=$true)][string]$DestinationPath
    )
    $archiveFileName = Split-Path -Path $SourcePath -Leaf
    Write-Host "Extracting archive '$archiveFileName' to '$DestinationPath'..."
    try {
        if (Test-Path -Path $DestinationPath) {
            Write-Verbose "Destination path '$DestinationPath' already exists. Content might be overwritten or merged."
        } else {
            New-Item -ItemType Directory -Path $DestinationPath -Force -ErrorAction Stop | Out-Null
        }
        Expand-Archive -Path $SourcePath -DestinationPath $DestinationPath -Force -ErrorAction Stop
        Write-Host "  Successfully extracted '$archiveFileName' to '$DestinationPath'." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to extract archive '$archiveFileName'. Error: $($_.Exception.Message)"
        return $false
    }
}

function Get-LatestGitHubReleaseAssetUrl { param ([Parameter(Mandatory=$true)][string]$RepoPath, [Parameter(Mandatory=$true)][string]$AssetPattern)
    $apiUrl = "https://api.github.com/repos/$RepoPath/releases/latest"; Write-Host "Querying GitHub API for latest release of '$RepoPath' (Asset: $AssetPattern)..."
    try { $response = Invoke-RestMethod -Uri $apiUrl -Method Get -UseBasicParsing -TimeoutSec 30 -UserAgent "PowerShell-Hackintosh-Installer-Script/1.0" -ErrorAction Stop; if ($null -eq $response) { Write-Warning "  No response or empty response from GitHub API for $RepoPath."; return $null } $assets = $response.assets; if ($null -eq $assets -or $assets.Count -eq 0) { Write-Warning "  No assets found in the latest release of $RepoPath."; return $null } $matchedAsset = $assets | Where-Object { $_.name -like $AssetPattern } | Select-Object -First 1; if ($matchedAsset) { Write-Host "  Found asset: $($matchedAsset.name)" -ForegroundColor Green; return $matchedAsset.browser_download_url } else { Write-Warning "  No asset matching pattern '$AssetPattern' found in the latest release of $RepoPath."; Write-Verbose "  Available assets:"; $assets | ForEach-Object { Write-Verbose "    - $($_.name)" }; return $null }}
    catch { $statusCode = $_.Exception.Response.StatusCode.value__; $statusDescription = $_.Exception.Response.StatusDescription; Write-Warning "Error querying GitHub API for $RepoPath (Status: $statusCode $statusDescription): $($_.Exception.Message)"; if ($statusCode -eq 403) { Write-Warning "  GitHub API rate limit may have been exceeded. Please wait a while or use a GitHub Personal Access Token with Invoke-RestMethod."} elseif ($statusCode -eq 404) { Write-Warning "  Repository '$RepoPath' or its releases not found. Check the path for typos."}; return $null }
}

# Helper function to get USB EFI/OC path, potentially assigning drive letter temporarily
function Get-UsbEfiOcPath {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$PreparedUsbInfo,
        [Parameter(Mandatory=$true)]
        [int]$TargetDiskNumber
    )
    $efiVolume = $PreparedUsbInfo.EfiVolume
    $efiPartitionNumber = $PreparedUsbInfo.EfiPartitionNumber
    $efiMountPoint = $null
    $tempDriveLetterAssigned = $null

    if ($efiVolume -and $efiVolume.DriveLetter) {
        $efiMountPoint = "$($efiVolume.DriveLetter):\"
    } elseif ($efiVolume -and $efiVolume.Path) {
        Write-Warning "EFI partition does not have a drive letter. Attempting to assign one temporarily."
        # Try to get a temporary drive letter
        $efiPart = Get-Partition -DiskNumber $TargetDiskNumber -PartitionNumber $efiPartitionNumber -ErrorAction SilentlyContinue
        if ($efiPart) {
            try {
                $availableLetters = Get-Volume | Select-Object -ExpandProperty DriveLetter | Where-Object { $_ -ne $null }
                $letterToAssign = (69..90 | ForEach-Object {[char]$_}) | Where-Object {$availableLetters -notcontains $_} | Select-Object -First 1
                if ($letterToAssign) {
                    Write-Host "  Assigning temporary drive letter $letterToAssign to EFI partition..."
                    Set-Partition -InputObject $efiPart -NewDriveLetter $letterToAssign -ErrorAction Stop
                    Start-Sleep -Seconds 3 # Give time for letter to be assigned
                    $refreshedVolume = Get-Volume -Partition $efiPart
                    if ($refreshedVolume.DriveLetter) {
                        $efiMountPoint = "$($refreshedVolume.DriveLetter):\"
                        $tempDriveLetterAssigned = $refreshedVolume.DriveLetter
                        Write-Host "    Successfully assigned temporary drive letter $tempDriveLetterAssigned to EFI partition." -ForegroundColor Green
                    } else { Write-Warning "    Failed to confirm drive letter assignment."}
                } else { Write-Warning "    No available drive letters to assign to EFI partition."}
            } catch { Write-Warning "    Failed to assign temporary drive letter to EFI: $($_.Exception.Message)" }
        } else { Write-Warning "    Could not get EFI partition object to assign drive letter."}
    }

    if (-not $efiMountPoint) {
        Write-Error "Could not determine EFI mount point. OpenCore/Kext copy will likely fail."
        return $null
    }
    $ocPath = Join-Path -Path $efiMountPoint -ChildPath "EFI\OC"
    if (-not (Test-Path -Path $ocPath -PathType Container)) {
        try {
            New-Item -ItemType Directory -Path (Join-Path -Path $efiMountPoint -ChildPath "EFI") -ErrorAction Stop -Force | Out-Null
            New-Item -ItemType Directory -Path $ocPath -ErrorAction Stop -Force | Out-Null
            Write-Host "  Created directory structure: $ocPath"
        } catch {
            Write-Error "Failed to create directory structure '$ocPath' on USB. Error: $($_.Exception.Message)"
            return $null
        }
    }
    return [PSCustomObject]@{ Path = $ocPath; TempDriveLetter = $tempDriveLetterAssigned }
}

function ConvertTo-PlistXmlNode {
    param ($InputObject, [int]$IndentLevel = 0)
    $indent = "  " * $IndentLevel
    $xmlOutput = ""

    if ($InputObject -is [System.Collections.Specialized.OrderedDictionary] -or $InputObject -is [hashtable]) { # Dictionary
        $xmlOutput += "$indent<dict>`n"
        foreach ($key in $InputObject.Keys) {
            $xmlOutput += "$indent  <key>$key</key>`n"
            $xmlOutput += ConvertTo-PlistXmlNode -InputObject $InputObject[$key] -IndentLevel ($IndentLevel + 1)
        }
        $xmlOutput += "$indent</dict>`n"
    } elseif ($InputObject -is [array]) { # Array
        $xmlOutput += "$indent<array>`n"
        foreach ($item in $InputObject) {
            $xmlOutput += ConvertTo-PlistXmlNode -InputObject $item -IndentLevel ($IndentLevel + 1)
        }
        $xmlOutput += "$indent</array>`n"
    } elseif ($InputObject -is [bool]) { # Boolean
        $boolStr = ""
        if ($InputObject -eq $true) { # Explicitly compare with $true
            $boolStr = "<true/>"
        } else {
            $boolStr = "<false/>"
        }
        $xmlOutput += "$indent$boolStr`n"
    } elseif ($InputObject -is [int] -or $InputObject -is [long] -or $InputObject -is [double] -or $InputObject -is [float]) { # Integer/Real
        $xmlOutput += "$indent<integer>$($InputObject)</integer>`n"
    } elseif ($InputObject -is [string] -and $InputObject.StartsWith("<data>") -and $InputObject.EndsWith("</data>")) { # Pre-formatted data
        $xmlOutput += "$indent$InputObject`n"
    } elseif ($InputObject -is [datetime]) { # Date
        $xmlOutput += "$indent<date>$($InputObject.ToString("yyyy-MM-ddTHH:mm:ssZ"))</date>`n"
    }
    else { # String (default)
        $escapedString = $InputObject -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&apos;'
        $xmlOutput += "$indent<string>$escapedString</string>`n"
    }
    return $xmlOutput
}

function ConvertTo-PlistXml {
    param(
        [Parameter(Mandatory=$true)]
        [object]$InputObject, 
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    Write-Host "Converting config to XML and saving to: $OutputPath"
    $xmlHeader = @"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
"@
    $xmlContent = ConvertTo-PlistXmlNode -InputObject $InputObject -IndentLevel 0
    $xmlFooter = @"
</plist>
"@
    $finalXml = $xmlHeader + $xmlContent + $xmlFooter
    try {
        Set-Content -Path $OutputPath -Value $finalXml -Encoding UTF8 -ErrorAction Stop
        Write-Host "  Successfully saved config.plist to $OutputPath" -ForegroundColor Green
        return $true
    } catch {
        Write-Error "Failed to save XML to '$OutputPath'. Error: $($_.Exception.Message)"
        return $false
    }
}

function Generate-PlatformInfo {
    param (
        [Parameter(Mandatory=$true)]
        [string]$SMBIOSModel, 
        [Parameter(Mandatory=$true)]
        [string]$MacSerialUtilPath
    )
    Write-Host "Generating PlatformInfo for SMBIOS: $SMBIOSModel using $MacSerialUtilPath"
    $serial = ""; $mlb = ""; $smUuid = ""
    if (-not (Test-Path -Path $MacSerialUtilPath -PathType Leaf)) {
        Write-Warning "  macserial utility not found at '$MacSerialUtilPath'. Generic PlatformInfo values will be placeholders."
        $serial = "GENERATE_ME_SERIAL"; $mlb = "GENERATE_ME_MLB"; $smUuid = "GENERATE_ME_SMUUID"
    } else {
        try {
            $macSerialOutput = & "$MacSerialUtilPath" -m $SMBIOSModel | Out-String
            Write-Verbose "  macserial output: $macSerialOutput"
            $serial = ($macSerialOutput -split '\|')[1].Trim() -replace 'Serial: ', ''
            $mlb = ($macSerialOutput -split '\|')[2].Trim() -replace 'Board Serial: ', ''
            $smUuid = ($macSerialOutput -split '\|')[3].Trim() -replace 'SmUUID: ', ''
            if (-not ($serial -and $mlb -and $smUuid)) { Throw "Failed to parse macserial output." }
            Write-Host "  Successfully generated SMBIOS data." -ForegroundColor Green
        } catch {
            Write-Warning "  Error running macserial or parsing its output: $($_.Exception.Message)"
            Write-Warning "  Generic PlatformInfo values will be placeholders."
            $serial = "SERIAL_ERROR"; $mlb = "MLB_ERROR"; $smUuid = "SMUUID_ERROR"
        }
    }
    $randomBytes = New-Object byte[] 6; (New-Object Random).NextBytes($randomBytes)
    $romHex = ($randomBytes | ForEach-Object { $_.ToString("X2") }) -join ''
    return [ordered]@{
        "Automatic" = $true
        "Generic" = [ordered]@{
            "AdviseFeatures" = $false; "MLB" = $mlb; "MaxBIOSVersion" = $false; "ProcessorType" = 0 
            "ROM" = "<data>$($romHex)</data>"; "SpoofVendor" = $true; "SystemMemoryStatus" = "Auto"
            "SystemProductName" = $SMBIOSModel; "SystemSerialNumber" = $serial; "SystemUUID" = $smUuid
        }
        "UpdateDataHub" = $true; "UpdateNVRAM" = $true; "UpdateSMBIOS" = $true
        "UpdateSMBIOSMode" = "Create"; "UseRawUuidEncoding" = $false
    }
}

function Generate-ConfigPlist {
    param (
        [string]$MacSerialPath,
        [string]$SMBIOS = "iMac20,2"
    )
    Write-Host "Generating config.plist for SMBIOS $SMBIOS..."
    $config = [ordered]@{
        "ACPI" = [ordered]@{
            "Add" = @(
                [ordered]@{ "Comment" = "SSDT-PLUG-ALT - Alternative PLUG for Alder Lake CPU power management"; "Enabled" = $true; "Path" = "SSDT-PLUG-ALT.aml" },
                [ordered]@{ "Comment" = "SSDT-EC-USBX-DESKTOP - Embedded Controller and USBX for Desktops"; "Enabled" = $true; "Path" = "SSDT-EC-USBX-DESKTOP.aml" },
                [ordered]@{ "Comment" = "SSDT-AWAC-DISABLE - Disable AWAC clock, use RTC"; "Enabled" = $true; "Path" = "SSDT-AWAC-DISABLE.aml" },
                [ordered]@{ "Comment" = "SSDT-RHUB - Reset RHUB for USB ports"; "Enabled" = $true; "Path" = "SSDT-RHUB.aml" }
            )
            "Delete" = @(); "Patch" = @()
            "Quirks" = [ordered]@{ "FadtEnableReset" = $false; "NormalizeHeaders" = $false; "RebaseRegions" = $false; "ResetHwSig" = $false; "ResetLogoStatus" = $true; "SyncTableIds" = $false }
        }
        "DeviceProperties" = [ordered]@{
            "Add" = [ordered]@{
                "PciRoot(0x0)/Pci(0x2,0x0)" = [ordered]@{ "AAPL,ig-platform-id" = "<data>CwAAkA==</data>"; "framebuffer-patch-enable" = "<data>AQAAAA==</data>"; "framebuffer-stolenmem" = "<data>AAAABA==</data>" }
                "PciRoot(0x0)/Pci(0x1F,0x3)" = [ordered]@{ "layout-id" = "<data>CwAAAA==</data>" }
            }
            "Delete" = [ordered]@{}
        }
        "Kernel" = [ordered]@{
            "Add" = @(
                [ordered]@{ "Arch" = "Any"; "BundlePath" = "Lilu.kext"; "Comment" = "Lilu kext"; "Enabled" = $true; "ExecutablePath" = "Contents/MacOS/Lilu"; "MaxKernel" = ""; "MinKernel" = ""; "PlistPath" = "Contents/Info.plist" },
                [ordered]@{ "Arch" = "Any"; "BundlePath" = "VirtualSMC.kext"; "Comment" = "VirtualSMC kext"; "Enabled" = $true; "ExecutablePath" = "Contents/MacOS/VirtualSMC"; "MaxKernel" = ""; "MinKernel" = ""; "PlistPath" = "Contents/Info.plist" },
                [ordered]@{ "Arch" = "Any"; "BundlePath" = "WhateverGreen.kext"; "Comment" = "WhateverGreen kext"; "Enabled" = $true; "ExecutablePath" = "Contents/MacOS/WhateverGreen"; "MaxKernel" = ""; "MinKernel" = ""; "PlistPath" = "Contents/Info.plist" },
                [ordered]@{ "Arch" = "Any"; "BundlePath" = "NVMeFix.kext"; "Comment" = "NVMeFix kext"; "Enabled" = $true; "ExecutablePath" = "Contents/MacOS/NVMeFix"; "MaxKernel" = ""; "MinKernel" = ""; "PlistPath" = "Contents/Info.plist" },
                [ordered]@{ "Arch" = "Any"; "BundlePath" = "RealtekRTL8111.kext"; "Comment" = "Realtek RTL8111 Ethernet"; "Enabled" = $true; "ExecutablePath" = "Contents/MacOS/RealtekRTL8111"; "MaxKernel" = ""; "MinKernel" = ""; "PlistPath" = "Contents/Info.plist" }
            )
            "Block" = @(); "Emulate" = [ordered]@{ "Cpuid1Data" = "<data></data>"; "Cpuid1Mask" = "<data></data>"; "DummyPowerManagement" = $false; "MaxKernel" = ""; "MinKernel" = "" }
            "Force" = @(); "Patch" = @()
            "Quirks" = [ordered]@{ "AppleCpuPmCfgLock" = $false; "AppleXcpmCfgLock" = $true; "AppleXcpmExtraMsrs" = $false; "AppleXcpmForceBoost" = $false; "CustomPciSerialDevice" = $false; "CustomSMBIOSGuid" = $false; "DisableIoMapper" = $true; "DisableLinkeditJettison" = $true; "DisableRtcChecksum" = $false; "ExtendBTFeatureFlags" = $false; "ExternalDiskIcons" = $false; "ForceAquantiaEthernet" = $false; "ForceSecureBootScheme" = $false; "IncreasePciBarSize" = $false; "LapicKernelPanic" = $false; "LegacyCommpage" = $false; "PanicNoKextDump" = $true; "PowerTimeoutKernelPanic" = $true; "ProvideCurrentCpuInfo" = $true; "SetApfsTrimTimeout" = -1; "ThirdPartyDrives" = $false; "XhciPortLimit" = $false }
            "Scheme" = [ordered]@{ "CustomKernel" = $false; "FuzzyMatch" = $true; "KernelArch" = "Auto"; "KernelCache" = "Auto" }
        }
        "Misc" = [ordered]@{
            "BlessOverride" = @(); "Boot" = [ordered]@{ "ConsoleAttributes" = 0; "HibernateMode" = "None"; "HibernateSkipsPicker" = $false; "HideAuxiliary" = $false; "InstanceIdentifier" = ""; "LauncherOption" = "Disabled"; "LauncherPath" = "Default"; "PickerAttributes" = 17; "PickerAudioAssist" = $false; "PickerMode" = "External"; "PickerVariant" = "Auto"; "PollAppleHotKeys" = $true; "ShowPicker" = $true; "TakeoffDelay" = 0; "Timeout" = 5 }
            "Debug" = [ordered]@{ "AppleDebug" = $true; "ApplePanic" = $true; "DisableWatchDog" = $true; "DisplayDelay" = 0; "DisplayLevel" = 2147483650; "LogModules" = "*"; "SysReport" = $false; "Target" = 3 }
            "Entries" = @(); "Security" = [ordered]@{ "AllowSetDefault" = $true; "ApECID" = 0; "AuthRestart" = $false; "BlacklistAppleUpdate" = $true; "DmgLoading" = "Signed"; "EnablePassword" = $false; "ExposeSensitiveData" = 6; "HaltLevel" = 2147483648; "PasswordHash" = "<data></data>"; "PasswordSalt" = "<data></data>"; "ScanPolicy" = 0; "SecureBootModel" = "Disabled"; "Vault" = "Optional" }
            "Serial" = [ordered]@{ "Custom" = [ordered]@{ "BaudRate" = 115200; "ClockRate" = 1843200; "DetectCable" = $false; "ExtendedTxFifoSize" = 64; "FifoControl" = 7; "LineControl" = 3; "PciDeviceInfo" = "<data></data>"; "RegisterAccessWidth" = 8; "RegisterBase" = 1016; "RegisterStride" = 1; "UseHardwareFlowControl" = $false; "UseMmio" = $false }; "Init" = $false; "Override" = $false }
            "Tools" = @()
        }
        "NVRAM" = [ordered]@{
            "Add" = [ordered]@{
                "4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14" = [ordered]@{ "DefaultBackgroundColor" = "<data>AAAAAA==</data>"; "csr-active-config" = "<data>5wMAAA==</data>" }
                "7C436110-AB2A-4BBB-A880-FE41995C9F82" = [ordered]@{ "boot-args" = "-v debug=0x100 keepsyms=1 alcid=11 agdpmod=pikera"; "prev-lang:kbd" = "<data>ZW4tVVM6MA==</data>"; "run-efi-updater" = "No" }
            }
            "Delete" = [ordered]@{ "4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14" = @("csr-active-config"); "7C436110-AB2A-4BBB-A880-FE41995C9F82" = @("boot-args", "prev-lang:kbd") }
            "LegacyOverwrite" = $false
            "LegacySchema" = [ordered]@{ "7C436110-AB2A-4BBB-A880-FE41995C9F82" = @("EFILoginHiDPI", "EFIBluetoothDelay", "LocationServicesEnabled", "SystemAudioVolume", "SystemAudioVolumeDB", "SystemAudioVolumeSaved", "bluetoothActiveControllerInfo", "bluetoothInternalControllerInfo", "flagstate", "fmm-computer-name", "fmm-mobileme-token-FMM", "nvda_drv", "prev-lang:kbd"); "8BE4DF61-93CA-11D2-AA0D-00E098032B8C" = @("Boot0080", "Boot0081", "Boot0082", "BootNext", "BootOrder") }
            "WriteFlash" = $true
        }
        "PlatformInfo" = Generate-PlatformInfo -SMBIOSModel $SMBIOS -MacSerialUtilPath $MacSerialPath
        "UEFI" = [ordered]@{
            "APFS" = [ordered]@{ "EnableJumpstart" = $true; "GlobalConnect" = $false; "HideVerbose" = $true; "JumpstartHotPlug" = $false; "MinDate" = 0; "MinVersion" = 0 }
            "AppleInput" = [ordered]@{ "AppleEvent" = "Auto"; "CustomDelays" = $false; "KeyInitialDelay" = 50; "KeySubsequentDelay" = 5; "PointerSpeedDiv" = 1; "PointerSpeedMul" = 1 }
            "Audio" = [ordered]@{ "AudioCodec" = 0; "AudioDevice" = ""; "AudioOutMask" = -1; "AudioSupport" = $false; "DisconnectHda" = $false; "MaximumGain" = -15; "MinimumAssistGain" = -30; "MinimumAudibleGain" = -128; "PlayChime" = "Auto"; "ResetTrafficClass" = $false; "SetupDelay" = 0; "VolumeAmplifier" = 0 }
            "ConnectDrivers" = $true
            "Drivers" = @( "HfsPlus.efi"; "OpenRuntime.efi"; "OpenCanopy.efi" )
            "Input" = [ordered]@{ "KeyFiltering" = $false; "KeyForgetThreshold" = 5; "KeySupport" = $true; "KeySupportMode" = "Auto"; "KeySwap" = $false; "PointerSupport" = $false; "PointerSupportMode" = "ASUS"; "TimerResolution" = 50000 }
            "Output" = [ordered]@{ "ClearScreenOnModeSwitch" = $false; "ConsoleMode" = ""; "DirectGopRendering" = $false; "ForceResolution" = $false; "GopPassThrough" = "Disabled"; "IgnoreTextInGraphics" = $false; "ProvideConsoleGop" = $true; "ReconnectGraphicsOnConnect" = $false; "ReconnectOnResChange" = $false; "ReplaceTabWithSpace" = $false; "Resolution" = ""; "SanitiseClearScreen" = $false; "TextRenderer" = "BuiltinGraphics"; "UIScale" = -1; "UgaPassThrough" = $false }
            "ProtocolOverrides" = [ordered]@{ "AppleAudio" = $false; "AppleBootPolicy" = $false; "AppleDebugLog" = $false; "AppleEg2Info" = $false; "AppleFramebufferInfo" = $false; "AppleImageConversion" = $false; "AppleImg4Verification" = $false; "AppleKeyMap" = $false; "AppleRtcRam" = $false; "AppleSecureBoot" = $false; "AppleSmcIo" = $false; "AppleUserInterfaceTheme" = $false; "DataHub" = $false; "DeviceProperties" = $false; "FirmwareVolume" = $false; "HashServices" = $false; "OSInfo" = $false; "UnicodeCollation" = $false }
            "Quirks" = [ordered]@{ "ActivateHpetSupport" = $false; "DisableSecurityPolicy" = $false; "EnableVectorAcceleration" = $true; "EnableWriteUnprotector" = $false; "ExitBootServicesDelay" = 0; "ForceOcWriteFlash" = $false; "ForgeUefiSupport" = $false; "IgnoreInvalidFlexRatio" = $false; "ReleaseUsbOwnership" = $true; "ReloadOptionRoms" = $false; "RequestBootVarRouting" = $true; "ResizeGpuBars" = -1; "TscSyncTimeout" = 0; "UnblockFsConnect" = $false }
            "ReservedMemory" = @()
        }
    }
    return $config
}

function Find-DownloadedMacOS {
    param (
        [Parameter(Mandatory=$true)]
        [string]$SearchPath, 
        [Parameter(Mandatory=$true)]
        [string]$TargetVersionName 
    )
    <#
    .SYNOPSIS
        Searches for downloaded macOS installer files from gibMacOS.
    .DESCRIPTION
        Looks for a directory containing the target version name and key installer files
        like BaseSystem.dmg within the specified search path.
    .PARAMETER SearchPath
        The base directory where gibMacOS downloads macOS versions (e.g., ".../gibMacOS-master/macOS Downloads/").
    .PARAMETER TargetVersionName
        The name of the macOS version to search for (e.g., "Sequoia", "Monterey").
    .OUTPUTS
        String - Full path to the validated macOS installer directory, or $null if not found.
    .EXAMPLE
        $macOsPath = Find-DownloadedMacOS -SearchPath "C:\downloads\gibMacOS-master\macOS Downloads" -TargetVersionName "Sequoia"
    #>
    Write-Host "Searching for downloaded macOS $TargetVersionName installer files in '$SearchPath'..."
    if (-not (Test-Path -Path $SearchPath -PathType Container)) { Write-Warning "  Search path '$SearchPath' does not exist."; return $null }
    $subFoldersToSearch = @("publicrelease", "developer", ""); foreach ($subFolder in $subFoldersToSearch) { $currentSearchBasePath = Join-Path -Path $SearchPath -ChildPath $subFolder; if (-not (Test-Path -Path $currentSearchBasePath -PathType Container)) { Write-Verbose "  Subfolder '$currentSearchBasePath' not found, skipping."; continue }; Write-Verbose "  Checking in: $currentSearchBasePath"; $candidateDirs = Get-ChildItem -Path $currentSearchBasePath -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $TargetVersionName }; foreach ($dir in $candidateDirs) { Write-Verbose "    Found potential directory: $($dir.FullName)"; if (Test-Path -Path (Join-Path $dir.FullName "BaseSystem.dmg") -PathType Leaf) { Write-Host "  [+] Validated macOS $TargetVersionName found at: $($dir.FullName) (BaseSystem.dmg exists)" -ForegroundColor Green; return $dir.FullName }}}
    Write-Warning "  Could not find a validated macOS $TargetVersionName installer directory containing BaseSystem.dmg under '$SearchPath'."; return $null
}

function Show-FinalGuidance {
    param (
        [string]$UsbEfiOcAcpiPath, 
        [array]$GpuInfos,
        [string]$DownloadDirPath, 
        [PSCustomObject]$SelectedUsbDriveForHint, 
        [PSCustomObject]$PreparationResultForHint 
    )
    Write-Host "`n`n------------------------------------------------------------------" -ForegroundColor Green
    Write-Host "FINAL GUIDANCE & IMPORTANT REMINDERS" -ForegroundColor Green
    Write-Host "------------------------------------------------------------------"
    Write-Host "`n[1] Recommended BIOS Settings (vary by motherboard):" -ForegroundColor Yellow
    Write-Host "  DISABLE:"
    Write-Host "    - Secure Boot"; Write-Host "    - Fast Boot"; Write-Host "    - CSM (Compatibility Support Module)"; Write-Host "    - Intel SGX (Software Guard Extensions)"; Write-Host "    - CFG Lock (MSR 0xE2 Write Protection) - If this option exists, disable it. If not, ensure Kernel->Quirks->AppleXcpmCfgLock is true."; Write-Host "    - Resizable BAR Support (if causing issues with iGPU, can be re-enabled later. Or set ResizeGpuBars = 0 in config)"
    Write-Host "  ENABLE:"
    Write-Host "    - VT-d (Virtualization Technology for Directed I/O) - Can be enabled if `DisableIoMapper` quirk is true (as set by this script)."; Write-Host "    - Above 4G Decoding (Crucial for modern GPUs & some drivers)"; Write-Host "    - EHCI/XHCI Hand-off"; Write-Host "    - OS Type: Windows 8.1/10 UEFI Mode, or 'Other OS' (for UEFI boot)"; Write-Host "    - DVMT Pre-Allocated (for iGPU): Typically 64M or 128M. (UHD 770 often works well with 64M if system RAM is plentiful)."; Write-Host "    - XMP Profile for RAM: Profile 1 (or equivalent)"
    Write-Host "  Note: Consult your motherboard manual and Dortania's guides for specific settings."
    Write-Host "`n[2] Script Automation Summary & Your Manual Steps:" -ForegroundColor Yellow
    Write-Host "  This script has automated:"
    Write-Host "    - Basic hardware information gathering."
    Write-Host "    - Download of OpenCore, essential Kexts, and gibMacOS (including extraction of gibMacOS)."
    if ($usbOcFullPath -or ($UsbEfiOcAcpiPath -and $UsbEfiOcAcpiPath -ne "your_USB_EFI_OC_ACPI_path_here")) { 
        Write-Host "    - USB drive preparation (EFI partition, exFAT for macOS installer data)."
        Write-Host "    - Generation of a baseline OpenCore config.plist (copied to USB)."
        Write-Host "    - Copying of Kexts and the generated config.plist to the USB's EFI partition."
    } else {
        Write-Host "    - Generation of a baseline OpenCore config.plist (saved to '$($DownloadDirPath)\config.plist')."
        Write-Host "    (USB-specific operations like drive preparation and copying files to USB were skipped or failed)."
    }
    Write-Host "  Your crucial MANUAL steps remaining:"
    if ($usbOcFullPath -or ($UsbEfiOcAcpiPath -and $UsbEfiOcAcpiPath -ne "your_USB_EFI_OC_ACPI_path_here")) { 
        Write-Host "    a. Download SSDT .aml files: As previously instructed, download the required .aml files for Alder Lake"
        Write-Host "       (SSDT-PLUG-ALT, SSDT-EC-USBX-DESKTOP, SSDT-AWAC-DISABLE, SSDT-RHUB) from Dortania's Prebuilt SSDTs page"
        Write-Host "       (https://dortania.github.io/Getting-Started-with-ACPI/SSDTs/prebuilt.html#desktop-alder-lake)"
        Write-Host "       and place them into: '$UsbEfiOcAcpiPath'"
        $macOsInstallDriveLetterHintLocal = ""; if ($null -ne $PreparationResultForHint -and $null -ne $PreparationResultForHint.MacOsInstallVolume -and $PreparationResultForHint.MacOsInstallVolume.DriveLetter) { $macOsInstallDriveLetterHintLocal = "(e.g., Drive '$($PreparationResultForHint.MacOsInstallVolume.DriveLetter):')" } elseif ($null -ne $SelectedUsbDriveForHint) { $macOsInstallDriveLetterHintLocal = "(on Disk $($SelectedUsbDriveForHint.DiskNumber))" }
        Write-Host "    b. Reformat 'MACOS_INSTALL' Partition: Boot from the USB, open Disk Utility (from Utilities menu),"
        Write-Host "       select the 'MACOS_INSTALL' partition $macOsInstallDriveLetterHintLocal, erase it, and format as 'APFS' (recommended) or 'Mac OS Extended (Journaled)'."
        Write-Host "    c. Copy macOS Installer Files: After formatting, quit Disk Utility. If the 'Install macOS' app doesn't start automatically,"
        Write-Host "       refer to the path of your downloaded macOS (e.g., Monterey/Ventura) files within"
        Write-Host "       '$($DownloadDirPath)\gibMacOS-master\macOS Downloads\publicrelease\*version_name*'."
        Write-Host "       Copy the *contents* of that folder (BaseSystem.dmg, etc.) to the root of your newly formatted 'MACOS_INSTALL' partition."
        Write-Host "       (This step is often done from within the macOS Installer environment if you use the 'Reinstall macOS' option after partitioning)."
        Write-Host "       Alternatively, some prefer to make the full installer app on another Mac and copy that."
        Write-Host "    d. Initial Boot & Troubleshooting: Attempt to boot from the USB. Be prepared to troubleshoot."
        Write-Host "       Review the generated config.plist on the USB. You may need to adjust DeviceProperties (especially iGPU settings if issues arise),"
        Write-Host "       kexts, or boot arguments based on your specific hardware and boot results."
    } else { 
        Write-Host "    a. Manually prepare a USB drive with an EFI partition."
        Write-Host "    b. Copy the generated config.plist (from '$($DownloadDirPath)\config.plist') to the USB's EFI/OC/ directory."
        Write-Host "    c. Copy the downloaded kexts (from '$DownloadDirPath' after extracting them) to the USB's EFI/OC/Kexts/ directory."
        Write-Host "    d. Download SSDT .aml files for Alder Lake (see Dortania's guides for recommended SSDTs) and place them in EFI/OC/ACPI/ on the USB."
        Write-Host "    e. Create a macOS installer partition on the USB, reformat it to APFS or HFS+ from macOS, and copy installer files (from '$($DownloadDirPath)\gibMacOS-master\macOS Downloads\...') to it."
        Write-Host "    f. Initial Boot & Troubleshooting."
    }
    if ($GpuInfos | Where-Object {$_.Name -match "GTX 970" -or $_.DeviceID -match "13C2"}) {
        Write-Host "`n[3] Nvidia GTX 970 (Maxwell) GPU Note:" -ForegroundColor Yellow
        Write-Host "  macOS Sequoia (and recent macOS versions) DO NOT have drivers for Nvidia Maxwell (GTX 9xx) GPUs like the GTX 970."
        Write-Host "  This script has configured the system to primarily use the Intel iGPU (UHD 770) for graphics acceleration."
        Write-Host "  - If your monitor is connected to the iGPU (motherboard video output), you should get full graphics acceleration."
        Write-Host "  - If your monitor is connected to the GTX 970, you will likely experience NO graphics acceleration in macOS."
        Write-Host "    It's recommended to use the iGPU for display output for the best experience."
        Write-Host "    The `agdpmod=pikera` boot-arg is included, which helps with display output on some GPUs, but does not enable acceleration for Maxwell."
        Write-Host "    Consider removing or disabling the GTX 970 if not needed, or ensure displays are connected to the motherboard for iGPU output."
    }
    Write-Host "`n[4] Troubleshooting Resources:" -ForegroundColor Cyan
    Write-Host "  - Dortania's OpenCore Install Guide: https://dortania.github.io/OpenCore-Install-Guide/"
    Write-Host "  - Dortania's OpenCore Post-Install Guide: https://dortania.github.io/OpenCore-Post-Install/"
    Write-Host "  - Dortania's Troubleshooting: https://dortania.github.io/OpenCore-Install-Guide/troubleshooting/troubleshooting.html"
    Write-Host "  - Relevant online communities (e.g., r/hackintosh, InsanelyMac) can also be helpful, but always check Dortania's guides first."
    Write-Host "`n[5] Disclaimer:" -ForegroundColor Red
    Write-Host "  This script automates many setup steps for creating a Hackintosh installer."
    Write-Host "  However, building a fully functional and stable Hackintosh can be a complex process"
    Write-Host "  that may require significant manual configuration, patience, and troubleshooting."
    Write-Host "  Hardware incompatibilities can arise. Success is NOT guaranteed."
    Write-Host "  PROCEED AT YOUR OWN RISK. The authors/contributors of this script are not responsible"
    Write-Host "  for any data loss, hardware damage, or other issues that may occur."
    Write-Host "------------------------------------------------------------------"
    Write-Host "Good luck!" -ForegroundColor Green
    Write-Host "------------------------------------------------------------------"
}


# --- Main Script Execution Starts Here ---
Test-IsAdmin

$hardware = Get-SystemInfo
if ($null -ne $hardware) {
    Write-Host "`n-------------------------------------" -ForegroundColor Yellow
    Write-Host "Collected Hardware Information:" -ForegroundColor Yellow
    Write-Host "-------------------------------------"
    Write-Host "`n[CPU]" -ForegroundColor Green; Write-Host $hardware.CPU
    Write-Host "`n[Motherboard]" -ForegroundColor Green; Write-Host $hardware.Motherboard
    Write-Host "`n[RAM]" -ForegroundColor Green; Write-Host "$($hardware.RAM_GB) GB"
    Write-Host "`n[Graphics Processing Units (GPUs)]" -ForegroundColor Green
    if ($hardware.GPUs.Count -gt 0) { foreach ($gpu in $hardware.GPUs) { Write-Host "  - Name: $($gpu.Name)"; Write-Host "    Vendor ID: $($gpu.VendorID)"; Write-Host "    Device ID: $($gpu.DeviceID)"; Write-Host "    Instance ID: $($gpu.InstanceId)"} }
    else { Write-Host "  No GPUs found or error in retrieval." }
    Write-Host "`n[Ethernet Controllers]" -ForegroundColor Green
    if ($hardware.Ethernet.Count -gt 0) { foreach ($eth in $hardware.Ethernet) { Write-Host "  - Name: $($eth.Name)"; Write-Host "    Description: $($eth.Description)"; Write-Host "    MAC Address: $($eth.MacAddress)"} }
    else { Write-Host "  No active Ethernet controllers found or error in retrieval." }
    Write-Host "`n[Storage Devices]" -ForegroundColor Green
    if ($hardware.Storage.Count -gt 0) { foreach ($disk in $hardware.Storage) { Write-Host "  - Name: $($disk.FriendlyName)"; Write-Host "    Manufacturer: $($disk.Manufacturer)"; Write-Host "    Model: $($disk.Model)"; Write-Host "    Size: $($disk.SizeGB) GB"} }
    else { Write-Host "  No storage devices found or error in retrieval." }
    Write-Host "`n-------------------------------------" -ForegroundColor Yellow
} else { Write-Warning "Hardware information could not be retrieved. Exiting."; Exit 1 }

Write-Host "`n-------------------------------------" -ForegroundColor Yellow
Write-Host "USB Drive Selection Stage" -ForegroundColor Yellow
Write-Host "-------------------------------------"
$availableUsbDrives = Get-AvailableUsbDrives
if ($null -eq $availableUsbDrives -or $availableUsbDrives.Count -eq 0) {
    Write-Warning "No suitable USB drives found. The script cannot continue without a target USB drive."
    Write-Host "Please connect a removable USB drive (at least 16GB) and re-run the script."
    Write-Host "`nScript execution finished."; Exit 1
}
$selectedUsbDrive = Select-UsbDrive -AvailableDrives $availableUsbDrives -MinimumSizeGB 16
if ($null -ne $selectedUsbDrive) {
    Write-Host "`n-------------------------------------" -ForegroundColor Yellow
    Write-Host "Selected USB Drive for macOS Installer:" -ForegroundColor Yellow
    Write-Host "-------------------------------------"
    Write-Host "Disk Number: $($selectedUsbDrive.DiskNumber)"; Write-Host "Name: $($selectedUsbDrive.FriendlyName)"; Write-Host "Size: $($selectedUsbDrive.SizeGB) GB"; Write-Host "Drive Letter(s): $($selectedUsbDrive.DriveLetters)"
} else {
    Write-Warning "No USB drive was selected, or the selected drive did not meet the criteria. USB-dependent operations will be skipped."
    Write-Host "You can re-run the script if you wish to prepare a USB drive."
}

$prepResult = $null
$usbOcFullPath = $null # Will store the path to EFI/OC on USB
$usbAcpiDir = $null  # Will store path to EFI/OC/ACPI on USB

Write-Host "`n-------------------------------------" -ForegroundColor Yellow
Write-Host "Software Download Stage" -ForegroundColor Yellow
Write-Host "-------------------------------------"
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$downloadDir = Join-Path -Path $scriptRoot -ChildPath "downloads"
if (-not (Test-Path -Path $downloadDir -PathType Container)) {
    try { Write-Host "Creating downloads directory at: $downloadDir"; New-Item -ItemType Directory -Path $downloadDir -ErrorAction Stop | Out-Null }
    catch { Write-Error "Failed to create downloads directory: $($_.Exception.Message)"; Write-Host "`nScript execution finished due to error."; Exit 1 }
} else { Write-Host "Downloads directory already exists: $downloadDir" }

$openCoreRepo = "acidanthera/OpenCorePkg"; $openCoreAssetPattern = "*RELEASE.zip"; Write-Host "`nStarting OpenCore download..."; 
$openCoreUrl = Get-LatestGitHubReleaseAssetUrl -RepoPath $openCoreRepo -AssetPattern $openCoreAssetPattern
if ($openCoreUrl) { 
    $ocFileName = Split-Path -Path $openCoreUrl -Leaf
    $ocOutFilePath = Join-Path -Path $downloadDir -ChildPath $ocFileName
    Invoke-DownloadFile -Url $openCoreUrl -OutfilePath $ocOutFilePath 
} else { Write-Warning "Could not determine OpenCore download URL. OpenCore will not be downloaded."}

$gibMacOSUrl = "https://github.com/corpnewt/gibMacOS/archive/refs/heads/master.zip"; $gibMacOSFileName = "gibMacOS-master.zip"; 
$gibMacOSZipOutFilePath = Join-Path -Path $downloadDir -ChildPath $gibMacOSFileName; 
$gibMacOSExtractPath = Join-Path -Path $downloadDir -ChildPath "gibMacOS-master" # Define path for extracted content
$gibMacOSBatPath = Join-Path -Path $gibMacOSExtractPath -ChildPath "gibMacOS.bat"

Write-Host "`nProcessing gibMacOS..."
# Check if gibMacOS is already extracted
if (Test-Path -Path $gibMacOSBatPath -PathType Leaf) {
    Write-Host "  gibMacOS appears to be already extracted at '$gibMacOSExtractPath'." -ForegroundColor Green
} else {
    Write-Host "  gibMacOS not found extracted. Attempting download and extraction..."
    # Download gibMacOS zip if it doesn't exist or is empty
    if (Invoke-DownloadFile -Url $gibMacOSUrl -OutfilePath $gibMacOSZipOutFilePath) {
        Write-Host "  Attempting to extract gibMacOS..."
        if (Test-Path $gibMacOSExtractPath) {
            Write-Host "    An existing directory at '$gibMacOSExtractPath' will be removed to ensure clean extraction."
            try { Remove-Item -Path $gibMacOSExtractPath -Recurse -Force -ErrorAction Stop }
            catch { 
                Write-Warning "    Failed to remove existing gibMacOS directory at '$gibMacOSExtractPath'. Extraction might fail or be incomplete. Error: $($_.Exception.Message)"
                # Continue to extraction attempt anyway, it might work if the folder is empty or can be overwritten by Expand-Archive
            }
        }
        # Extract-ZipArchive extracts the contents of the zip into the DestinationPath.
        # If gibMacOS-master.zip has a root folder "gibMacOS-master", it will create $downloadDir\gibMacOS-master
        if (Extract-ZipArchive -SourcePath $gibMacOSZipOutFilePath -DestinationPath $downloadDir) { 
            if (Test-Path -Path $gibMacOSBatPath -PathType Leaf) {
                 Write-Host "    gibMacOS extracted successfully, and gibMacOS.bat found at '$gibMacOSBatPath'." -ForegroundColor Green
            } else {
                Write-Warning "    gibMacOS archive was extracted, but gibMacOS.bat was NOT found at the expected path: '$gibMacOSBatPath'."
                Write-Warning "    Please check the '$downloadDir' for the extracted contents and ensure 'gibMacOS-master' folder is structured correctly."
            }
        } else {
            Write-Warning "    Failed to extract gibMacOS from '$gibMacOSZipOutFilePath'."
            Write-Warning "    You may need to extract it manually to '$gibMacOSExtractPath'."
        }
    } else {
        Write-Warning "  gibMacOS ZIP file ('$gibMacOSFileName') could not be downloaded and is not present. gibMacOS steps will be skipped."
    }
}

Write-Host "`nStarting Essential Kexts download..."
$kextsToDownload = @( 
    @{ RepoPath = "acidanthera/Lilu"; AssetPattern = "*RELEASE.zip"; Name = "Lilu" }, 
    @{ RepoPath = "acidanthera/WhateverGreen"; AssetPattern = "*RELEASE.zip"; Name = "WhateverGreen" }, 
    @{ RepoPath = "acidanthera/VirtualSMC"; AssetPattern = "*RELEASE.zip"; Name = "VirtualSMC" }, 
    @{ RepoPath = "Mieze/RTL8111_driver_for_OS_X"; AssetPattern = "*RELEASE.zip"; FallbackAssetPattern = "*.zip"; Name = "RealtekRTL8111" }, 
    @{ RepoPath = "acidanthera/NVMeFix"; AssetPattern = "*RELEASE.zip"; Name = "NVMeFix" }
)
foreach ($kextEntry in $kextsToDownload) { 
    $kextName = $kextEntry.Name; Write-Host "`nProcessing $kextName (from $($kextEntry.RepoPath))..."; 
    $kextUrl = Get-LatestGitHubReleaseAssetUrl -RepoPath $kextEntry.RepoPath -AssetPattern $kextEntry.AssetPattern; 
    if (-not $kextUrl -and $kextEntry.FallbackAssetPattern) { 
        Write-Warning "  Initial asset pattern '$($kextEntry.AssetPattern)' failed for $kextName. Trying fallback '$($kextEntry.FallbackAssetPattern)'."; 
        $kextUrl = Get-LatestGitHubReleaseAssetUrl -RepoPath $kextEntry.RepoPath -AssetPattern $kextEntry.FallbackAssetPattern 
    }; 
    if ($kextUrl) { 
        $kextFileName = Split-Path -Path $kextUrl -Leaf; 
        $kextOutFilePath = Join-Path -Path $downloadDir -ChildPath $kextFileName; 
        if (Invoke-DownloadFile -Url $kextUrl -OutfilePath $kextOutFilePath) { 
            $kextEntry.PSObject.Properties.Add([PSNoteProperty]::new("DownloadedZipPath", $kextOutFilePath)); 
            $kextEntry.PSObject.Properties.Add([PSNoteProperty]::new("DownloadedZipFileName", $kextFileName)); 
            Write-Host "  Stored DownloadedZipPath: $($kextEntry.DownloadedZipPath)" -ForegroundColor DarkGray 
        } else { Write-Warning "Failed to download $kextName."}
    } else { Write-Warning "Could not determine download URL for $kextName (Repo: $($kextEntry.RepoPath), Pattern: $($kextEntry.AssetPattern)). It will not be downloaded."}
}
Write-Host "`nSoftware download stage complete."

# --- config.plist Generation (Always occurs to $downloadDir) ---
Write-Host "`n-------------------------------------" -ForegroundColor Yellow
Write-Host "config.plist Generation Stage (to downloads folder)" -ForegroundColor Yellow
Write-Host "-------------------------------------"
$ocDownloadFolderForMacSerial = Get-ChildItem -Path $downloadDir -Directory -Filter "OpenCore-*-RELEASE" | Sort-Object CreationTime -Descending | Select-Object -First 1
$macSerialPathForConfig = ""
if ($ocDownloadFolderForMacSerial) {
    $macSerialPathForConfig = Join-Path -Path $ocDownloadFolderForMacSerial.FullName -ChildPath "Utilities\macserial\macserial.exe"
    if (-not (Test-Path -Path $macSerialPathForConfig -PathType Leaf)) {
        $macSerialPathForConfig = Join-Path -Path $ocDownloadFolderForMacSerial.FullName -ChildPath "Utilities\macserial\macserial" 
    }
}
if ([string]::IsNullOrWhiteSpace($macSerialPathForConfig) -or (-not (Test-Path -Path $macSerialPathForConfig -PathType Leaf))) {
    Write-Warning "macserial utility not found. PlatformInfo in config.plist will contain placeholder values."
    $macSerialPathForConfig = "NOT_FOUND_macserial"
} else {
    Write-Host "macserial utility for config.plist found at: $macSerialPathForConfig" -ForegroundColor Green
}
$generatedConfig = Generate-ConfigPlist -MacSerialPath $macSerialPathForConfig -SMBIOS "iMac20,2"
$configPlistOutputPathForDownloadDir = Join-Path -Path $downloadDir -ChildPath "config.plist" 
if (ConvertTo-PlistXml -InputObject $generatedConfig -OutputPath $configPlistOutputPathForDownloadDir) {
    Write-Host "Generated config.plist has been saved to: $configPlistOutputPathForDownloadDir" -ForegroundColor Cyan
    Write-Host "IMPORTANT: Review this generated config.plist carefully against Dortania guides for Alder Lake." -ForegroundColor Yellow
} else {
    Write-Error "Failed to generate or save config.plist to $downloadDir."
}


# --- USB Operations (Only if a USB drive was selected) ---
if ($null -ne $selectedUsbDrive) {
    Write-Host "`n-------------------------------------" -ForegroundColor Yellow
    Write-Host "USB Drive Preparation & File Copy Stage" -ForegroundColor Yellow
    Write-Host "-------------------------------------"
    $prepResult = Prepare-UsbDrive -UsbDrive $selectedUsbDrive
    if ($null -ne $prepResult -and $prepResult.Success) {
        Write-Host "`nUSB Drive preparation successful." -ForegroundColor Green
        if ($prepResult.EfiVolume) { Write-Host "  EFI Volume: Label '$($prepResult.EfiVolume.FileSystemLabel)', Letter '$($prepResult.EfiVolume.DriveLetter)', Path '$($prepResult.EfiVolume.Path)'"}
        if ($prepResult.MacOsInstallVolume) { Write-Host "  MACOS_INSTALL Volume: Label '$($prepResult.MacOsInstallVolume.FileSystemLabel)', Letter '$($prepResult.MacOsInstallVolume.DriveLetter)', Path '$($prepResult.MacOsInstallVolume.Path)'"}
        
        $usbEFIOCPathsInfo = Get-UsbEfiOcPath -PreparedUsbInfo $prepResult -TargetDiskNumber $selectedUsbDrive.DiskNumber
        if ($usbEFIOCPathsInfo -and $usbEFIOCPathsInfo.Path) {
            $usbOcFullPath = $usbEFIOCPathsInfo.Path # Set global var for EFI/OC
            Write-Host "Target USB EFI/OC path: $usbOcFullPath" -ForegroundColor Green

            # Copy OpenCore EFI folder to USB EFI (root)
            $ocEfiSourceToCopy = $null
            $tempOcExtractDirForUsb = $null # To track if we extracted to a temp dir

            # Try to find a pre-unzipped OpenCore folder first
            $ocZipFilePattern = "OpenCore-*-RELEASE.zip"
            $latestOcZip = Get-ChildItem -Path $downloadDir -Filter $ocZipFilePattern | Sort-Object CreationTime -Descending | Select-Object -First 1
            
            if ($latestOcZip) {
                $ocUnzippedDirName = $latestOcZip.Name.Replace(".zip", "")
                $expectedOcFolderPath = Join-Path -Path $downloadDir -ChildPath $ocUnzippedDirName
                
                if (Test-Path -Path $expectedOcFolderPath -PathType Container) {
                    Write-Host "Using pre-existing unzipped OpenCore folder: $expectedOcFolderPath" -ForegroundColor Cyan
                    # Determine EFI path within this unzipped folder (common patterns: X64/EFI or just EFI)
                    if (Test-Path -Path (Join-Path $expectedOcFolderPath "X64\EFI") -PathType Container) {
                        $ocEfiSourceToCopy = Join-Path $expectedOcFolderPath "X64\EFI"
                    } elseif (Test-Path -Path (Join-Path $expectedOcFolderPath "EFI") -PathType Container) {
                        $ocEfiSourceToCopy = Join-Path $expectedOcFolderPath "EFI"
                    } else {
                        Write-Warning "  Could not find EFI folder within pre-existing OpenCore directory: $expectedOcFolderPath"
                    }
                }
            }

            # If not found pre-unzipped, try extracting from ZIP
            if (-not $ocEfiSourceToCopy -and $latestOcZip) {
                Write-Host "Pre-unzipped OpenCore folder not found or EFI missing. Attempting to extract from $($latestOcZip.FullName)"
                $tempOcExtractDirForUsb = Join-Path -Path $scriptRoot -ChildPath "temp_oc_extract_usb_$(Get-Random)"
                if (Extract-ZipArchive -SourcePath $latestOcZip.FullName -DestinationPath $tempOcExtractDirForUsb) {
                    # Check common locations for EFI folder within the extracted archive
                    $extractedEFIPathAttempt = Join-Path $tempOcExtractDirForUsb "EFI" # Direct EFI
                    if (Test-Path -Path $extractedEFIPathAttempt -PathType Container) {
                        $ocEfiSourceToCopy = $extractedEFIPathAttempt
                    } else {
                        $nestedOcDirName = Get-ChildItem -Path $tempOcExtractDirForUsb -Directory -Filter "OpenCore-*-RELEASE" | Select-Object -First 1
                        if ($nestedOcDirName) {
                            if (Test-Path -Path (Join-Path $nestedOcDirName.FullName "X64\EFI") -PathType Container) {
                                $ocEfiSourceToCopy = Join-Path $nestedOcDirName.FullName "X64\EFI"
                            } elseif (Test-Path -Path (Join-Path $nestedOcDirName.FullName "EFI") -PathType Container) {
                                $ocEfiSourceToCopy = Join-Path $nestedOcDirName.FullName "EFI"
                            }
                        }
                    }
                    if (-not $ocEfiSourceToCopy) {
                        Write-Warning "  Could not find EFI folder within extracted OpenCore ZIP archive at $tempOcExtractDirForUsb"
                    }
                } else {
                    Write-Warning "  Failed to extract OpenCore ZIP: $($latestOcZip.FullName)"
                }
            } elseif (-not $latestOcZip -and -not $ocEfiSourceToCopy) { # Added this condition
                 Write-Warning "OpenCore ZIP not found in '$downloadDir' and no pre-unzipped folder identified. Skipping OpenCore copy to USB."
            }

            if ($ocEfiSourceToCopy -and (Test-Path -Path $ocEfiSourceToCopy -PathType Container)) {
                $usbEfiRoot = Split-Path -Path $usbOcFullPath # This should be like X:\EFI
                $usbEfiRoot = Split-Path -Path $usbEfiRoot    # This should be like X:\
                $targetEfiOnUsb = Join-Path $usbEfiRoot "EFI"
                Write-Host "Copying OpenCore EFI from '$ocEfiSourceToCopy' to '$targetEfiOnUsb'..."
                try {
                    if (Test-Path -Path $targetEfiOnUsb) { 
                        Write-Host "  Removing existing EFI folder at '$targetEfiOnUsb' before copying."
                        Remove-Item -Path $targetEfiOnUsb -Recurse -Force -ErrorAction Stop 
                    }
                    Copy-Item -Path $ocEfiSourceToCopy -Destination $targetEfiOnUsb -Recurse -Force -ErrorAction Stop
                    Write-Host "Successfully copied OpenCore EFI folder to USB." -ForegroundColor Green
                } catch { Write-Error "Failed to copy OpenCore EFI folder to USB. Error: $($_.Exception.Message)" }
            } else {
                Write-Warning "No valid OpenCore EFI source found to copy to USB."
            }

            # Clean up temp extraction directory if it was used
            if ($tempOcExtractDirForUsb -and (Test-Path -Path $tempOcExtractDirForUsb -PathType Container)) {
                Write-Host "Cleaning up temporary OpenCore extraction directory for USB: $tempOcExtractDirForUsb"
                Remove-Item -Path $tempOcExtractDirForUsb -Recurse -Force -ErrorAction SilentlyContinue
            }
            
            # Copy Kexts to USB EFI/OC/Kexts
            $usbKextsDir = Join-Path -Path $usbOcFullPath -ChildPath "Kexts"
            if (-not (Test-Path -Path $usbKextsDir -PathType Container)) {
                try { New-Item -ItemType Directory -Path $usbKextsDir -ErrorAction Stop | Out-Null; Write-Host "  Created Kexts directory on USB: $usbKextsDir" } 
                catch { Write-Error "Failed to create Kexts directory '$usbKextsDir' on USB. Error: $($_.Exception.Message)" }
            }
            if (Test-Path -Path $usbKextsDir -PathType Container) {
                Write-Host "`nCopying kexts to USB..."
                $genericKextNames = @{ "acidanthera/Lilu" = "Lilu.kext"; "acidanthera/WhateverGreen" = "WhateverGreen.kext"; "acidanthera/VirtualSMC" = "VirtualSMC.kext"; "Mieze/RTL8111_driver_for_OS_X" = "RealtekRTL8111.kext"; "acidanthera/NVMeFix" = "NVMeFix.kext" }
                if ($kextsToDownload.Count -eq 0) { Write-Warning "  Kext download list is empty." }
                
                foreach ($kextEntry in $kextsToDownload) {
                    $kextSourceSearchPath = $null
                    $tempKextExtractDirForUsb = $null # To track if temp extraction was used for this kext
                    
                    # Determine expected unzipped kext directory name (use kext name as folder name)
                    $kextUnzippedDirName = $kextEntry.Name 
                    $expectedKextFolderPath = Join-Path -Path $downloadDir -ChildPath $kextUnzippedDirName

                    if (Test-Path -Path $expectedKextFolderPath -PathType Container) {
                        Write-Host "  Using pre-existing unzipped folder for $($kextEntry.Name): $expectedKextFolderPath" -ForegroundColor Cyan
                        $kextSourceSearchPath = $expectedKextFolderPath
                    } elseif ($kextEntry.PSObject.Properties['DownloadedZipPath'] -and $kextEntry.DownloadedZipPath -and (Test-Path -Path $kextEntry.DownloadedZipPath -PathType Leaf)) {
                        Write-Host "  Extracting $($kextEntry.DownloadedZipFileName) for $($kextEntry.Name)..."
                        $tempKextExtractDirForUsb = Join-Path -Path $scriptRoot -ChildPath "temp_kext_extract_usb_$(Get-Random)"
                        if (Extract-ZipArchive -SourcePath $kextEntry.DownloadedZipPath -DestinationPath $tempKextExtractDirForUsb) {
                            $kextSourceSearchPath = $tempKextExtractDirForUsb
                        } else {
                            Write-Warning "    Failed to extract $($kextEntry.DownloadedZipFileName). Skipping this kext."
                            if (Test-Path -Path $tempKextExtractDirForUsb) { Remove-Item -Path $tempKextExtractDirForUsb -Recurse -Force -ErrorAction SilentlyContinue }
                            continue # Next kext
                        }
                    } else {
                        Write-Warning "  No ZIP or pre-extracted folder found for $($kextEntry.Name) (expected '$expectedKextFolderPath' or valid ZIP path). Skipping this kext."
                        continue # Next kext
                    }

                    if ($kextSourceSearchPath) {
                        $foundKextBundles = Get-ChildItem -Path $kextSourceSearchPath -Recurse -Directory -Filter "*.kext" -ErrorAction SilentlyContinue
                        if ($foundKextBundles.Count -gt 0) {
                            foreach ($kextBundle in $foundKextBundles) {
                                $targetKextNameOnUsb = $kextBundle.Name
                                if ($genericKextNames.ContainsKey($kextEntry.RepoPath)) {
                                    $genericName = $genericKextNames[$kextEntry.RepoPath]; $baseGenericName = $genericName.Replace(".kext", "")
                                    if ($kextBundle.Name -match $baseGenericName -and $kextEntry.RepoPath -ne "acidanthera/VirtualSMC") { $targetKextNameOnUsb = $genericName } 
                                    elseif ($kextEntry.RepoPath -eq "acidanthera/VirtualSMC" -and ($kextBundle.Name -match "VirtualSMC" -or $kextBundle.Name -match "SMC")) { # Be more inclusive for VirtualSMC plugins
                                        # For VirtualSMC itself, name it VirtualSMC.kext. For plugins, keep original name.
                                        if ($kextBundle.Name -eq "VirtualSMC.kext") { $targetKextNameOnUsb = "VirtualSMC.kext" }
                                        # else, plugin names like SMCProcessor.kext, SMCSuperIO.kext stay as is.
                                    }
                                }
                                # Check depth and avoid __MACOSX, also ensure it's a primary kext for VirtualSMC if renaming
                                $pathDepth = ($kextBundle.FullName.Split([IO.Path]::DirectorySeparatorChar).Length - $kextSourceSearchPath.Split([IO.Path]::DirectorySeparatorChar).Length)
                                $isPrimaryVirtualSMC = ($kextEntry.RepoPath -eq "acidanthera/VirtualSMC" -and $targetKextNameOnUsb -eq "VirtualSMC.kext")
                                $isVirtualSMCPlugin = ($kextEntry.RepoPath -eq "acidanthera/VirtualSMC" -and $targetKextNameOnUsb -ne "VirtualSMC.kext")

                                if (($pathDepth -lt 3 -or $isVirtualSMCPlugin) -and $kextBundle.FullName -notmatch "__MACOSX") { # Allow plugins to be slightly deeper if needed
                                    Write-Host "    Copying '$($kextBundle.Name)' as '$targetKextNameOnUsb' to $usbKextsDir"
                                    try { Copy-Item -Path $kextBundle.FullName -Destination (Join-Path $usbKextsDir $targetKextNameOnUsb) -Recurse -Force -ErrorAction Stop } 
                                    catch { Write-Error "    Failed to copy $($kextBundle.Name). Error: $($_.Exception.Message)" }
                                } else { Write-Verbose "    Skipping '$($kextBundle.Name)' as it appears to be a non-essential/nested item or non-primary for this entry." }
                            }
                        } else { Write-Warning "    No .kext bundles found in '$kextSourceSearchPath' for $($kextEntry.Name)." }
                    }
                    
                    # Clean up temp extraction directory if it was used for this kext
                    if ($tempKextExtractDirForUsb -and (Test-Path -Path $tempKextExtractDirForUsb)) { 
                        Remove-Item -Path $tempKextExtractDirForUsb -Recurse -Force -ErrorAction SilentlyContinue 
                    }
                }
                Write-Host "Kext copying process complete." -ForegroundColor Green
            }

            # Copy config.plist to USB EFI/OC/
            if (Test-Path -Path $configPlistOutputPathForDownloadDir -PathType Leaf) { 
                $destinationConfigPlistOnUsb = Join-Path -Path $usbOcFullPath -ChildPath "config.plist"; 
                Write-Host "`nCopying generated config.plist to USB: $destinationConfigPlistOnUsb"; 
                try { Copy-Item -Path $configPlistOutputPathForDownloadDir -Destination $destinationConfigPlistOnUsb -Force -ErrorAction Stop; Write-Host "  Successfully copied config.plist to USB." -ForegroundColor Green } 
                catch { Write-Error "Failed to copy config.plist to USB. Error: $($_.Exception.Message)" }
            } else { Write-Warning "Generated config.plist not found at '$configPlistOutputPathForDownloadDir'. Skipping copy to USB." }
            
            $usbAcpiDir = Join-Path -Path $usbOcFullPath -ChildPath "ACPI"; # Set global var
            if (-not (Test-Path -Path $usbAcpiDir -PathType Container)) { 
                try { New-Item -ItemType Directory -Path $usbAcpiDir -ErrorAction Stop | Out-Null; Write-Host "  Created ACPI directory on USB: $usbAcpiDir" } 
                catch { Write-Warning "Failed to create ACPI directory '$usbAcpiDir' on USB. Error: $($_.Exception.Message)" }
            }

            if ($usbEFIOCPathsInfo.TempDriveLetter) { 
                Write-Host "`n  Attempting to remove temporary drive letter $($usbEFIOCPathsInfo.TempDriveLetter) from EFI partition..."; 
                try { 
                    $efiPartForCleanup = Get-Partition | Where-Object {$_.DiskNumber -eq $selectedUsbDrive.DiskNumber -and $_.PartitionNumber -eq $prepResult.EfiPartitionNumber}; 
                    if ($efiPartForCleanup) { Set-Partition -InputObject $efiPartForCleanup -NoDefaultDriveLetter -ErrorAction Stop; Write-Host "    Successfully removed temporary drive letter." -ForegroundColor Green } 
                    else { Write-Warning "    Could not re-fetch EFI partition details for cleanup. Manual check might be needed."}
                } catch { Write-Warning "    Failed to remove temporary drive letter automatically: $($_.Exception.Message). You may ignore this or remove it manually via Disk Management." }
            }
        } else { Write-Error "Halting file copy to USB as EFI/OC path could not be determined or accessed."}
    } else { Write-Warning "`nUSB Drive preparation failed or was aborted. Dependent operations (OpenCore/Kext copy to USB) will be skipped."}
} 

# --- macOS Download Guidance (via gibMacOS) ---
Write-Host "`n-------------------------------------" -ForegroundColor Yellow
Write-Host "macOS Download Stage (using gibMacOS)" -ForegroundColor Yellow
Write-Host "-------------------------------------"
$gibMacOSBatchFilePath = Join-Path -Path $gibMacOSExtractPath -ChildPath "gibMacOS.bat" 

if (-not (Test-Path -Path $gibMacOSExtractPath -PathType Container) -or -not (Test-Path -Path $gibMacOSBatchFilePath -PathType Leaf)) {
    Write-Error "gibMacOS was not found at expected location: $gibMacOSExtractPath"
    Write-Warning "This might be due to a failed download or extraction of gibMacOS."
    Write-Warning "Please check the '$downloadDir' directory. You may need to download and extract it manually from $($gibMacOSUrl)."
    Write-Host "`nmacOS Download guidance cannot proceed without gibMacOS. You will need to handle macOS download manually."
} else {
    Write-Host "gibMacOS found at: $gibMacOSExtractPath" -ForegroundColor Green
    Write-Host "`nAction Required for macOS Download:" -ForegroundColor Cyan
    Write-Host "1. gibMacOS has been downloaded and extracted to: '$gibMacOSExtractPath'"
    Write-Host "2. You will need Python installed on your system for gibMacOS.bat to function correctly."
    Write-Host "   (Download Python from python.org if you don't have it)."
    Write-Host "3. Open a new Command Prompt or PowerShell window."
    Write-Host "4. Navigate to the gibMacOS directory: cd '$gibMacOSExtractPath'"
    Write-Host "5. Run the script: .\gibMacOS.bat"
    Write-Host "6. When prompted by gibMacOS, choose a suitable macOS version."
    Write-Host "   Recommended for Alder Lake (iMac20,2 SMBIOS):"
    Write-Host "     - macOS Monterey (e.g., 12.x)"
    Write-Host "     - macOS Ventura (e.g., 13.x)"
    Write-Host "   (These should be listed under 'publicrelease' or similar within gibMacOS)."
    Write-Host "7. Allow the download to complete fully. This will download macOS installer files into a"
    Write-Host "   subfolder typically within: '$gibMacOSExtractPath\macOS Downloads\'"
    Write-Host "   Recommended for Alder Lake (iMac20,2 SMBIOS):"
    Write-Host "     - macOS Monterey (e.g., 12.x)" # Updated Recommendation
    Write-Host "     - macOS Ventura (e.g., 13.x)"  # Updated Recommendation
    Write-Host "   (These should be listed under 'publicrelease' or similar within gibMacOS)."
    Write-Host "7. Allow the download to complete fully. This will download macOS installer files into a"
    Write-Host "   subfolder typically within: '$gibMacOSExtractPath\macOS Downloads\'"
    Write-Host "`n----------------------------------------------------------------------------------" -ForegroundColor Yellow
    Read-Host -Prompt "Press Enter here ONLY AFTER you have successfully downloaded your chosen macOS version (e.g., Monterey or Ventura) using gibMacOS.bat" # Updated prompt
    Write-Host "`n----------------------------------------------------------------------------------" -ForegroundColor Yellow
    
    # Attempt to find downloaded macOS files
    $macOsInstallerSourcePath = $null
    $macOsSearchBaseDir = Join-Path -Path $gibMacOSExtractPath -ChildPath "macOS Downloads" 
    $preferredMacOsVersionToSearch = "Monterey" # Explicitly define for search
    $alternativeMacOsVersionToSearch = "Ventura" # Explicitly define for search

    Write-Host "Attempting to locate macOS $preferredMacOsVersionToSearch files..."
    $macOsInstallerSourcePath = Find-DownloadedMacOS -SearchPath $macOsSearchBaseDir -TargetVersionName $preferredMacOsVersionToSearch
    if (-not $macOsInstallerSourcePath) {
        Write-Warning "Could not locate macOS $preferredMacOsVersionToSearch. Attempting to locate macOS $alternativeMacOsVersionToSearch files..."
        $macOsInstallerSourcePath = Find-DownloadedMacOS -SearchPath $macOsSearchBaseDir -TargetVersionName $alternativeMacOsVersionToSearch
    }

    if ($macOsInstallerSourcePath) {
        $locatedVersion = ""
        if ($macOsInstallerSourcePath -match $preferredMacOsVersionToSearch) { $locatedVersion = $preferredMacOsVersionToSearch }
        elseif ($macOsInstallerSourcePath -match $alternativeMacOsVersionToSearch) { $locatedVersion = $alternativeMacOsVersionToSearch }
        else { $locatedVersion = "detected version" }
        Write-Host "Successfully located macOS $locatedVersion installer files: $macOsInstallerSourcePath" -ForegroundColor Green
        # Guidance for using these files is now in Show-FinalGuidance
    } else {
        Write-Error "Could not automatically locate the downloaded macOS files (tried $preferredMacOsVersionToSearch and $alternativeMacOsVersionToSearch) in '$macOsSearchBaseDir'."
        Write-Warning "Please ensure you ran gibMacOS.bat, downloaded a recommended macOS version (Monterey or Ventura), and that the files are in a subdirectory" # Updated
        Write-Warning "like '$($macOsSearchBaseDir)\publicrelease\*$($preferredMacOsVersionToSearch)*' or '$($macOsSearchBaseDir)\publicrelease\*$($alternativeMacOsVersionToSearch)*'." # Updated
        Write-Warning "You will need to manually identify this location for the next steps of creating the installer."
    }
}

# --- Final Guidance ---
$finalUsbAcpiPathForGuidance = "your_USB_EFI_OC_ACPI_path_here" 
if ($usbAcpiDir -and (Test-Path -Path $usbAcpiDir)) { 
    $finalUsbAcpiPathForGuidance = $usbAcpiDir
} elseif ($usbOcFullPath -and (Test-Path -Path $usbOcFullPath)) { 
     $finalUsbAcpiPathForGuidance = Join-Path -Path $usbOcFullPath -ChildPath "ACPI"
     # Do not create it here, Show-FinalGuidance is for display only.
}

Show-FinalGuidance -UsbEfiOcAcpiPath $finalUsbAcpiPathForGuidance -GpuInfos $hardware.GPUs -DownloadDirPath $downloadDir -SelectedUsbDriveForHint $selectedUsbDrive -PreparationResultForHint $prepResult

Write-Host "`nScript execution fully completed. Please review all outputs and guidance above." -ForegroundColor Magenta
Write-Host "Remember to manually download SSDTs and prepare the macOS installer partition as instructed if you created a USB installer." -ForegroundColor Magenta
