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
        # Add more specific error handling if Get-PnpDevice is not available or fails for other reasons
        if ($_.Exception.GetType().Name -eq 'CmdletNotFoundException') {
            Write-Warning "  Make sure you are running PowerShell 5.1 or newer for Get-PnpDevice."
        }
    }

    # Get Ethernet Information
    try {
        Write-Verbose "Fetching Ethernet information..."
        $ethernetAdapters = Get-NetAdapter -Physical -ErrorAction Stop | Where-Object {$_.MediaType -eq '802.3' -and $_.Status -eq 'Up'} # Only 'Up' adapters, can be adjusted
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
    <#
    .SYNOPSIS
        Retrieves a list of available removable USB drives.
    .DESCRIPTION
        Filters disks to find those connected via USB and are removable.
        Gathers details like disk number, friendly name, size, and assigned drive letters.
    .OUTPUTS
        Array of PSCustomObjects, each representing a USB drive. Returns $null if no drives are found.
    .EXAMPLE
        $usbDrives = Get-AvailableUsbDrives
        if ($usbDrives) { $usbDrives | Format-Table }
    #>
    Write-Host "`nScanning for available USB drives..." -ForegroundColor Cyan
    $usbDrives = @()
    try {
        # Get removable disks connected via USB
        $disks = Get-Disk | Where-Object {$_.BusType -eq 'USB' -and $_.IsRemovable -eq $true -and $_.OperationalStatus -eq 'Online'} -ErrorAction Stop

        if ($null -eq $disks -or $disks.Count -eq 0) {
            Write-Host "  No removable USB drives found."
            return $null
        }

        foreach ($disk in $disks) {
            $driveLetters = (Get-Partition -DiskNumber $disk.DiskNumber | Get-Volume).DriveLetter | Where-Object {$null -ne $_}
            $driveLettersString = ($driveLetters | Sort-Object) -join ', '
            if ([string]::IsNullOrWhiteSpace($driveLettersString)) {
                $driveLettersString = "N/A"
            }

            $usbDrives += [PSCustomObject]@{
                DiskNumber = $disk.DiskNumber
                FriendlyName = if ($null -ne $disk.FriendlyName -and $disk.FriendlyName.Trim() -ne "") {$disk.FriendlyName} else {$disk.Model}
                SizeGB = [Math]::Round($disk.Size / 1GB, 2)
                DriveLetters = $driveLettersString
            }
            Write-Host "  [+] Found USB: $($disk.FriendlyName) (Disk $($disk.DiskNumber), $($([Math]::Round($disk.Size / 1GB, 2)) GB), Letters: $driveLettersString)"
        }
    }
    catch {
        Write-Warning "An error occurred while scanning for USB drives: $($_.Exception.Message)"
        if ($_.Exception.GetType().Name -eq 'CmdletNotFoundException') {
            Write-Warning "  Get-Disk, Get-Partition, or Get-Volume cmdlets might not be available. Ensure PowerShell 4.0+ (Windows 8/Server 2012 R2 or newer)."
        }
        return $null # Return null on error to indicate failure
    }

    if ($usbDrives.Count -eq 0) {
        Write-Host "  No suitable USB drives found after processing." # Should have been caught by the first check, but as a safeguard.
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

    <#
    .SYNOPSIS
        Prompts the user to select a USB drive from a list.
    .DESCRIPTION
        Displays a numbered list of USB drives and asks the user to choose one.
        Validates the input and checks if the selected drive meets the minimum size requirement.
    .PARAMETER AvailableDrives
        An array of USB drive objects (from Get-AvailableUsbDrives).
    .PARAMETER MinimumSizeGB
        The minimum required size for the USB drive in GB. Defaults to 16GB.
    .OUTPUTS
        PSCustomObject - The selected USB drive object, or $null if no valid selection is made or criteria not met.
    .EXAMPLE
        $selectedDrive = Select-UsbDrive -AvailableDrives $usbDrives -MinimumSizeGB 32
        if ($selectedDrive) { Write-Host "Selected: $($selectedDrive.FriendlyName)" }
    #>

    if ($null -eq $AvailableDrives -or $AvailableDrives.Count -eq 0) {
        Write-Warning "No USB drives provided to select from."
        return $null
    }

    Write-Host "`nAvailable USB Drives for Installer Creation:" -ForegroundColor Yellow
    for ($i = 0; $i -lt $AvailableDrives.Count; $i++) {
        $drive = $AvailableDrives[$i]
        Write-Host ("{0,3}. Disk {1}: {2} ({3} GB) - Drive(s): {4}" -f ($i + 1), $drive.DiskNumber, $drive.FriendlyName, $drive.SizeGB, $drive.DriveLetters)
    }

    $selectedDrive = $null
    while ($null -eq $selectedDrive) {
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
                    $selectedDrive = $candidateDrive
                    Write-Host "You selected: Disk $($selectedDrive.DiskNumber) - $($selectedDrive.FriendlyName) ($($selectedDrive.SizeGB) GB)" -ForegroundColor Green
                } else {
                    Write-Warning ("Selected drive '$($candidateDrive.FriendlyName)' is $($candidateDrive.SizeGB)GB. Minimum required size is $($MinimumSizeGB)GB.")
                    Write-Warning "Please choose a different drive or ensure the drive meets the size requirement."
                    # Continue loop to allow another selection
                }
            } else {
                Write-Warning "Invalid selection. Please enter a number from the list."
            }
        }
        catch {
            Write-Warning "Invalid input. Please enter a valid number."
        }
    }
    return $selectedDrive
}

# Main script logic
Test-IsAdmin

# If admin, gather and display hardware info
$hardware = Get-SystemInfo

# Display collected information
if ($null -ne $hardware) {
    Write-Host "`n-------------------------------------" -ForegroundColor Yellow
    Write-Host "Collected Hardware Information:" -ForegroundColor Yellow
    Write-Host "-------------------------------------"

    Write-Host "`n[CPU]" -ForegroundColor Green
    Write-Host $hardware.CPU

    Write-Host "`n[Motherboard]" -ForegroundColor Green
    Write-Host $hardware.Motherboard

    Write-Host "`n[RAM]" -ForegroundColor Green
    Write-Host "$($hardware.RAM_GB) GB"

    Write-Host "`n[Graphics Processing Units (GPUs)]" -ForegroundColor Green
    if ($hardware.GPUs.Count -gt 0) {
        foreach ($gpu in $hardware.GPUs) {
            Write-Host "  - Name: $($gpu.Name)"
            Write-Host "    Vendor ID: $($gpu.VendorID)"
            Write-Host "    Device ID: $($gpu.DeviceID)"
            Write-Host "    Instance ID: $($gpu.InstanceId)" # Useful for debugging
        }
    } else {
        Write-Host "  No GPUs found or error in retrieval."
    }

    Write-Host "`n[Ethernet Controllers]" -ForegroundColor Green
    if ($hardware.Ethernet.Count -gt 0) {
        foreach ($eth in $hardware.Ethernet) {
            Write-Host "  - Name: $($eth.Name)"
            Write-Host "    Description: $($eth.Description)"
            Write-Host "    MAC Address: $($eth.MacAddress)"
        }
    } else {
        Write-Host "  No active Ethernet controllers found or error in retrieval."
    }

    Write-Host "`n[Storage Devices]" -ForegroundColor Green
    if ($hardware.Storage.Count -gt 0) {
        foreach ($disk in $hardware.Storage) {
            Write-Host "  - Name: $($disk.FriendlyName)"
            Write-Host "    Manufacturer: $($disk.Manufacturer)"
            Write-Host "    Model: $($disk.Model)"
            Write-Host "    Size: $($disk.SizeGB) GB"
        }
    } else {
        Write-Host "  No storage devices found or error in retrieval."
    }
    Write-Host "`n-------------------------------------" -ForegroundColor Yellow
}
else {
    Write-Warning "Hardware information could not be retrieved. Exiting."
    Exit 1
}

# USB Drive Selection
Write-Host "`n-------------------------------------" -ForegroundColor Yellow
Write-Host "USB Drive Selection Stage" -ForegroundColor Yellow
Write-Host "-------------------------------------"
$availableUsbDrives = Get-AvailableUsbDrives

if ($null -eq $availableUsbDrives -or $availableUsbDrives.Count -eq 0) {
    Write-Warning "No suitable USB drives found. The script cannot continue without a target USB drive."
    Write-Host "Please connect a removable USB drive (at least 16GB) and re-run the script."
    Write-Host "`nScript execution finished."
    Exit 1
}

$selectedUsbDrive = Select-UsbDrive -AvailableDrives $availableUsbDrives -MinimumSizeGB 16 # Minimum size set to 16GB

if ($null -ne $selectedUsbDrive) {
    Write-Host "`n-------------------------------------" -ForegroundColor Yellow
    Write-Host "Selected USB Drive for macOS Installer:" -ForegroundColor Yellow
    Write-Host "-------------------------------------"
    Write-Host "Disk Number: $($selectedUsbDrive.DiskNumber)"
    Write-Host "Name: $($selectedUsbDrive.FriendlyName)"
    Write-Host "Size: $($selectedUsbDrive.SizeGB) GB"
    Write-Host "Drive Letter(s): $($selectedUsbDrive.DriveLetters)"
    # Future steps would involve using this $selectedUsbDrive for partitioning and copying files.
} else {
    Write-Warning "No USB drive was selected, or the selected drive did not meet the criteria."
    Write-Host "Please re-run the script if you wish to select a USB drive."
}

# --- Download Stage ---
Write-Host "`n-------------------------------------" -ForegroundColor Yellow
Write-Host "Software Download Stage" -ForegroundColor Yellow
Write-Host "-------------------------------------"

# Create downloads directory
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$downloadDir = Join-Path -Path $scriptRoot -ChildPath "downloads"
if (-not (Test-Path -Path $downloadDir -PathType Container)) {
    try {
        Write-Host "Creating downloads directory at: $downloadDir"
        New-Item -ItemType Directory -Path $downloadDir -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Error "Failed to create downloads directory: $($_.Exception.Message)"
        Write-Host "`nScript execution finished due to error."
        Exit 1
    }
} else {
    Write-Host "Downloads directory already exists: $downloadDir"
}

# Function to download a file
function Invoke-DownloadFile {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Url,
        [Parameter(Mandatory=$true)]
        [string]$OutfilePath
    )
    <#
    .SYNOPSIS
        Downloads a file from a given URL.
    .DESCRIPTION
        Uses Invoke-WebRequest to download a file. Includes basic error handling
        and skips download if the file already exists and is not empty.
    .PARAMETER Url
        The URL of the file to download.
    .PARAMETER OutfilePath
        The full path where the file should be saved.
    .EXAMPLE
        Invoke-DownloadFile -Url "http://example.com/file.zip" -OutfilePath "C:\downloads\file.zip"
    #>
    $fileName = Split-Path -Path $OutfilePath -Leaf
    Write-Host "Attempting to download '$fileName' from $Url" -ForegroundColor Cyan

    if (Test-Path -Path $OutfilePath -PathType Leaf) {
        $fileInfo = Get-Item -Path $OutfilePath
        if ($fileInfo.Length -gt 0) {
            Write-Host "  File '$fileName' already exists in '$((Split-Path -Path $OutfilePath -Parent))' and is not empty. Skipping download." -ForegroundColor Green
            return $true # Indicate success (or skip)
        } else {
            Write-Warning "  File '$fileName' exists but is empty. Will attempt to re-download."
        }
    }

    try {
        # Progress bar can be slow for many small files, using simple message for now.
        # Consider Start-BitsTransfer for more advanced scenarios if needed.
        Write-Host "  Downloading... (this may take a moment)"
        Invoke-WebRequest -Uri $Url -OutFile $OutfilePath -UseBasicParsing -ErrorAction Stop
        Write-Host "  Successfully downloaded '$fileName' to '$((Split-Path -Path $OutfilePath -Parent))'" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to download '$fileName' from '$Url`. Error: $($_.Exception.Message)"
        # Clean up potentially incomplete file
        if (Test-Path -Path $OutfilePath -PathType Leaf) {
            try {
                Remove-Item -Path $OutfilePath -Force -ErrorAction SilentlyContinue
            } catch { Write-Warning "Could not remove incomplete file: $OutfilePath" }
        }
        return $false
    }
}

# Function to get the latest GitHub release asset URL
function Get-LatestGitHubReleaseAssetUrl {
    param (
        [Parameter(Mandatory=$true)]
        [string]$RepoPath, # e.g., "acidanthera/OpenCorePkg"
        [Parameter(Mandatory=$true)]
        [string]$AssetPattern # e.g., "*RELEASE.zip"
    )
    <#
    .SYNOPSIS
        Fetches the download URL for a specific asset from the latest GitHub release of a repository.
    .DESCRIPTION
        Queries the GitHub API for the latest release of the specified repository,
        then searches for an asset matching the given pattern in the release's assets.
    .PARAMETER RepoPath
        The GitHub repository path in the format "owner/repository".
    .PARAMETER AssetPattern
        A wildcard pattern to match the desired asset name (e.g., "*RELEASE.zip", "WhateverGreen*.zip").
    .OUTPUTS
        String - The download URL of the matched asset, or $null if not found or an error occurs.
    .EXAMPLE
        $ocUrl = Get-LatestGitHubReleaseAssetUrl -RepoPath "acidanthera/OpenCorePkg" -AssetPattern "*RELEASE.zip"
        if ($ocUrl) { Write-Host "OpenCore download URL: $ocUrl" }
    #>
    $apiUrl = "https://api.github.com/repos/$RepoPath/releases/latest"
    Write-Host "Querying GitHub API for latest release of '$RepoPath' (Asset: $AssetPattern)..."

    try {
        $response = Invoke-RestMethod -Uri $apiUrl -Method Get -UseBasicParsing -ErrorAction Stop
        if ($null -eq $response) {
            Write-Warning "  No response or empty response from GitHub API for $RepoPath."
            return $null
        }

        $assets = $response.assets
        if ($null -eq $assets -or $assets.Count -eq 0) {
            Write-Warning "  No assets found in the latest release of $RepoPath."
            return $null
        }

        $matchedAsset = $assets | Where-Object { $_.name -like $AssetPattern } | Select-Object -First 1
        
        if ($matchedAsset) {
            Write-Host "  Found asset: $($matchedAsset.name)" -ForegroundColor Green
            return $matchedAsset.browser_download_url
        } else {
            Write-Warning "  No asset matching pattern '$AssetPattern' found in the latest release of $RepoPath."
            Write-Verbose "  Available assets:"
            $assets | ForEach-Object { Write-Verbose "    - $($_.name)" }
            return $null
        }
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $statusDescription = $_.Exception.Response.StatusDescription
        Write-Warning "Error querying GitHub API for $RepoPath (Status: $statusCode $statusDescription): $($_.Exception.Message)"
        if ($statusCode -eq 403) { # Rate limit likely
            Write-Warning "  GitHub API rate limit may have been exceeded. Please wait a while or use a GitHub Personal Access Token with Invoke-RestMethod."
        } elseif ($statusCode -eq 404) { # Not found
             Write-Warning "  Repository '$RepoPath' or its releases not found. Check the path for typos."
        }
        return $null
    }
}

# --- Download OpenCore ---
$openCoreRepo = "acidanthera/OpenCorePkg"
$openCoreAssetPattern = "*RELEASE.zip" # Matches files like OpenCore-0.7.9-RELEASE.zip
Write-Host "`nStarting OpenCore download..."
$openCoreUrl = Get-LatestGitHubReleaseAssetUrl -RepoPath $openCoreRepo -AssetPattern $openCoreAssetPattern

if ($openCoreUrl) {
    $fileName = Split-Path -Path $openCoreUrl -Leaf
    $outFilePath = Join-Path -Path $downloadDir -ChildPath $fileName
    Invoke-DownloadFile -Url $openCoreUrl -OutfilePath $outFilePath
} else {
    Write-Warning "Could not determine OpenCore download URL. OpenCore will not be downloaded."
}

# --- Download gibMacOS ---
$gibMacOSUrl = "https://github.com/corpnewt/gibMacOS/archive/refs/heads/master.zip"
$gibMacOSFileName = "gibMacOS-master.zip" # Explicit filename for clarity
$gibMacOSOutFilePath = Join-Path -Path $downloadDir -ChildPath $gibMacOSFileName
Write-Host "`nStarting gibMacOS download..."
Invoke-DownloadFile -Url $gibMacOSUrl -OutfilePath $gibMacOSOutFilePath

# --- Download Essential Kexts ---
Write-Host "`nStarting Essential Kexts download..."
$kextsToDownload = @(
    @{ RepoPath = "acidanthera/Lilu"; AssetPattern = "*RELEASE.zip" },
    @{ RepoPath = "acidanthera/WhateverGreen"; AssetPattern = "*RELEASE.zip" },
    @{ RepoPath = "acidanthera/VirtualSMC"; AssetPattern = "*RELEASE.zip" },
    # Using Mieze fork for RTL8111 as it's a common choice.
    # Note: Release patterns can vary. If "*RELEASE.zip" fails, manual check of repo needed.
    @{ RepoPath = "Mieze/RTL8111_driver_for_OS_X"; AssetPattern = "*RELEASE.zip"; FallbackAssetPattern = "*.zip" }, 
    @{ RepoPath = "acidanthera/NVMeFix"; AssetPattern = "*RELEASE.zip" }
    # Add other kexts like AppleALC, USBMap, etc. here as needed by the user's hardware
)

foreach ($kext in $kextsToDownload) {
    $kextName = $kext.RepoPath.Split('/')[-1] # Get kext name from RepoPath for messages
    Write-Host "`nProcessing $kextName..."
    $kextUrl = Get-LatestGitHubReleaseAssetUrl -RepoPath $kext.RepoPath -AssetPattern $kext.AssetPattern
    
    # Fallback mechanism for asset pattern - useful for repos with inconsistent naming
    if (-not $kextUrl -and $kext.FallbackAssetPattern) {
        Write-Warning "  Initial asset pattern '$($kext.AssetPattern)' failed for $kextName. Trying fallback '$($kext.FallbackAssetPattern)'."
        $kextUrl = Get-LatestGitHubReleaseAssetUrl -RepoPath $kext.RepoPath -AssetPattern $kext.FallbackAssetPattern
    }

    if ($kextUrl) {
        $fileName = Split-Path -Path $kextUrl -Leaf
        $outFilePath = Join-Path -Path $downloadDir -ChildPath $fileName
        Invoke-DownloadFile -Url $kextUrl -OutfilePath $outFilePath
    } else {
        Write-Warning "Could not determine download URL for $kextName (Repo: $($kext.RepoPath), Pattern: $($kext.AssetPattern)). It will not be downloaded."
    }
}

Write-Host "`nSoftware download stage complete."

# --- USB Drive Preparation Stage ---
Write-Host "`n-------------------------------------" -ForegroundColor Yellow
Write-Host "USB Drive Preparation Stage" -ForegroundColor Yellow
Write-Host "-------------------------------------"

# Utility function to extract Zip archives
function Extract-ZipArchive {
    param (
        [Parameter(Mandatory=$true)]
        [string]$SourcePath,
        [Parameter(Mandatory=$true)]
        [string]$DestinationPath
    )
    <#
    .SYNOPSIS
        Extracts a zip archive to a specified destination.
    .DESCRIPTION
        Uses Expand-Archive for extraction. Creates the destination directory if it doesn't exist.
    .PARAMETER SourcePath
        The full path to the source .zip file.
    .PARAMETER DestinationPath
        The directory where the contents should be extracted.
    .EXAMPLE
        Extract-ZipArchive -SourcePath "C:\downloads\myarchive.zip" -DestinationPath "C:\temp\extracted_files"
    #>
    Write-Host "Extracting '$((Split-Path -Path $SourcePath -Leaf))' to '$DestinationPath'..."
    if (-not (Test-Path -Path $DestinationPath -PathType Container)) {
        try {
            Write-Verbose "Destination directory '$DestinationPath' does not exist. Creating..."
            New-Item -ItemType Directory -Path $DestinationPath -Force -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Error "Failed to create destination directory '$DestinationPath'. Error: $($_.Exception.Message)"
            return $false
        }
    }

    try {
        Expand-Archive -Path $SourcePath -DestinationPath $DestinationPath -Force -ErrorAction Stop
        Write-Host "  Successfully extracted to '$DestinationPath'." -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Failed to extract archive '$SourcePath'. Error: $($_.Exception.Message)"
        # Check if Expand-Archive cmdlet is available (PowerShell 5.0+)
        if ($_.Exception.GetType().Name -eq 'CommandNotFoundException' -and $_.Exception.CommandName -eq 'Expand-Archive') {
            Write-Warning "  The 'Expand-Archive' cmdlet is not available. This script requires PowerShell 5.0 or newer."
        }
        return $false
    }
}

# --- config.plist Generation Stage ---
Write-Host "`n-------------------------------------" -ForegroundColor Yellow
Write-Host "config.plist Generation Stage" -ForegroundColor Yellow
Write-Host "-------------------------------------"

# Helper function to convert PowerShell hashtable/array to Plist XML
function ConvertTo-PlistXmlNode {
    param ($InputObject, [int]$IndentLevel = 0)
    $indent = "  " * $IndentLevel
    $xmlOutput = ""

    if ($InputObject -is [ordered] -or $InputObject -is [hashtable]) { # Dictionary
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
        $xmlOutput += "$indent$((if ($InputObject) { "<true/>" } else { "<false/>" }))`n"
    } elseif ($InputObject -is [int] -or $InputObject -is [long] -or $InputObject -is [double] -or $InputObject -is [float]) { # Integer/Real
        # OpenCore seems to prefer <integer> for most numerical values unless specifically real.
        # For simplicity, all numbers are treated as integers here. Adjust if <real> is needed.
        $xmlOutput += "$indent<integer>$($InputObject)</integer>`n"
    } elseif ($InputObject -is [string] -and $InputObject.StartsWith("<data>") -and $InputObject.EndsWith("</data>")) { # Pre-formatted data
        $xmlOutput += "$indent$InputObject`n"
    } elseif ($InputObject -is [datetime]) { # Date
        $xmlOutput += "$indent<date>$($InputObject.ToString("yyyy-MM-ddTHH:mm:ssZ"))</date>`n"
    }
    else { # String (default)
        # Basic XML escaping for strings
        $escapedString = $InputObject -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' -replace "'", '&apos;'
        $xmlOutput += "$indent<string>$escapedString</string>`n"
    }
    return $xmlOutput
}

function ConvertTo-PlistXml {
    param(
        [Parameter(Mandatory=$true)]
        [object]$InputObject, # Should be the root dictionary
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
        [string]$SMBIOSModel, # e.g., "iMac20,2"
        [Parameter(Mandatory=$true)]
        [string]$MacSerialUtilPath
    )

    Write-Host "Generating PlatformInfo for SMBIOS: $SMBIOSModel using $MacSerialUtilPath"
    
    $serial = ""
    $mlb = ""
    $smUuid = ""

    if (-not (Test-Path -Path $MacSerialUtilPath -PathType Leaf)) {
        Write-Warning "  macserial utility not found at '$MacSerialUtilPath'. Generic PlatformInfo values will be placeholders."
        $serial = "GENERATE_ME_SERIAL"
        $mlb = "GENERATE_ME_MLB"
        $smUuid = "GENERATE_ME_SMUUID"
    } else {
        try {
            # macserial returns: iMac20,2 | Serial: C02XXXXXYYYY | Board Serial: C02YYYYYXXXXZ | SmUUID: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
            $macSerialOutput = Invoke-Expression "$MacSerialUtilPath -m $SMBIOSModel" | Out-String
            Write-Verbose "  macserial output: $macSerialOutput"

            $serial = ($macSerialOutput -split '\|')[1].Trim() -replace 'Serial: ', ''
            $mlb = ($macSerialOutput -split '\|')[2].Trim() -replace 'Board Serial: ', ''
            $smUuid = ($macSerialOutput -split '\|')[3].Trim() -replace 'SmUUID: ', ''
            
            if (-not ($serial -and $mlb -and $smUuid)) {
                Throw "Failed to parse macserial output."
            }
            Write-Host "  Successfully generated SMBIOS data." -ForegroundColor Green
        } catch {
            Write-Warning "  Error running macserial or parsing its output: $($_.Exception.Message)"
            Write-Warning "  Generic PlatformInfo values will be placeholders."
            $serial = "SERIAL_ERROR"
            $mlb = "MLB_ERROR"
            $smUuid = "SMUUID_ERROR"
        }
    }

    # Generate random MAC address for ROM (6 bytes as hex string)
    $randomBytes = New-Object byte[] 6
    (New-Object Random).NextBytes($randomBytes)
    $romHex = ($randomBytes | ForEach-Object { $_.ToString("X2") }) -join ''

    return [ordered]@{
        "Automatic" = $true
        "Generic" = [ordered]@{
            "AdviseFeatures" = $false # Set to true if using VMM flag for some Windows VM scenarios, false for typical Hackintosh
            "MLB" = $mlb
            "MaxBIOSVersion" = $false 
            "ProcessorType" = 0 
            "ROM" = "<data>$($romHex)</data>" # Needs to be data type
            "SpoofVendor" = $true
            "SystemMemoryStatus" = "Auto"
            "SystemProductName" = $SMBIOSModel
            "SystemSerialNumber" = $serial
            "SystemUUID" = $smUuid
        }
        "UpdateDataHub" = $true
        "UpdateNVRAM" = $true
        "UpdateSMBIOS" = $true
        "UpdateSMBIOSMode" = "Create" 
        "UseRawUuidEncoding" = $false
    }
}

# --- Final USB File Copy & Guidance ---
Write-Host "`n-------------------------------------" -ForegroundColor Yellow
Write-Host "Final USB File Copy & Guidance Stage" -ForegroundColor Yellow
Write-Host "-------------------------------------"

function Get-UsbEfiOcPath {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$PreparedUsbInfo, # Result from Prepare-UsbDrive
        [Parameter(Mandatory=$true)]
        [int]$TargetDiskNumber # The disk number of the USB drive
    )
    <#
    .SYNOPSIS
        Ensures the EFI partition of the prepared USB drive is accessible and returns the EFI/OC path.
    .DESCRIPTION
        Checks if the EFI partition has a drive letter or mount point. If not, it attempts
        to assign a temporary drive letter. It then constructs the path to the EFI/OC directory.
    .PARAMETER PreparedUsbInfo
        The PSCustomObject returned by Prepare-UsbDrive, containing EfiVolume and EfiPartitionNumber.
    .PARAMETER TargetDiskNumber
        The disk number of the USB drive being worked on.
    .OUTPUTS
        String - The full path to the EFI/OC directory on the USB drive (e.g., E:\EFI\OC), or $null on failure.
                 It also outputs a 'TempDriveLetter' property if a letter was assigned by this function.
    #>
    Write-Host "Attempting to access EFI partition on Disk $TargetDiskNumber..."
    $efiMountPoint = $null
    $tempDriveLetterAssigned = $null

    # Check if EfiVolume info is present and has a drive letter or usable path
    if ($PreparedUsbInfo.EfiVolume) {
        if ($PreparedUsbInfo.EfiVolume.DriveLetter) {
            $efiMountPoint = "$($PreparedUsbInfo.EfiVolume.DriveLetter):\"
            Write-Host "  EFI partition already accessible via drive letter: $efiMountPoint"
        } elseif ($PreparedUsbInfo.EfiVolume.Path -and ($PreparedUsbInfo.EfiVolume.Path -notlike "\\?\Volume*")) {
            # Path is something like a mounted folder, which might be usable
            $efiMountPoint = $PreparedUsbInfo.EfiVolume.Path
             Write-Host "  EFI partition accessible via path: $efiMountPoint"
        }
    }

    # If not found via existing info, try to get it by partition number and assign a letter
    if (-not $efiMountPoint -and $PreparedUsbInfo.EfiPartitionNumber) {
        Write-Host "  EFI partition not readily accessible. Attempting to find and assign temporary drive letter..."
        try {
            $efiPart = Get-Partition -DiskNumber $TargetDiskNumber -PartitionNumber $PreparedUsbInfo.EfiPartitionNumber -ErrorAction Stop
            if ($efiPart) {
                # Check if it already gained a drive letter somehow
                $currentVolume = Get-Volume -Partition $efiPart -ErrorAction SilentlyContinue
                if ($currentVolume.DriveLetter) {
                    $efiMountPoint = "$($currentVolume.DriveLetter):\"
                    Write-Host "  Found existing drive letter for EFI partition: $efiMountPoint"
                } else {
                    $availableLetters = Get-Volume | Select-Object -ExpandProperty DriveLetter | Where-Object { $_ -ne $null }
                    $letterToAssign = (69..90 | ForEach-Object {[char]$_}) | Where-Object {$availableLetters -notcontains $_} | Select-Object -First 1
                    
                    if ($letterToAssign) {
                        Write-Host "    Assigning temporary drive letter '$letterToAssign' to EFI partition..."
                        Set-Partition -InputObject $efiPart -NewDriveLetter $letterToAssign -ErrorAction Stop
                        Start-Sleep -Seconds 3 # Allow time for the system to recognize the new drive letter
                        $refreshedVolume = Get-Volume -Partition $efiPart -ErrorAction Stop
                        if ($refreshedVolume.DriveLetter) {
                            $efiMountPoint = "$($refreshedVolume.DriveLetter):\"
                            $tempDriveLetterAssigned = $refreshedVolume.DriveLetter
                            Write-Host "    Successfully assigned temporary drive letter '$($tempDriveLetterAssigned)'." -ForegroundColor Green
                        } else {
                            Write-Warning "    Assigned letter '$letterToAssign', but could not confirm volume access via drive letter."
                        }
                    } else {
                        Write-Warning "    No available drive letters to assign to the EFI partition."
                    }
                }
            } else {
                Write-Warning "    Could not find EFI partition (Number $($PreparedUsbInfo.EfiPartitionNumber)) on Disk $TargetDiskNumber."
            }
        } catch {
            Write-Warning "    Error while trying to assign drive letter to EFI partition: $($_.Exception.Message)"
        }
    }

    if (-not $efiMountPoint) {
        Write-Error "Could not access or mount the EFI partition on Disk $TargetDiskNumber."
        Write-Warning "You may need to manually assign a drive letter using Disk Management or diskpart."
        return $null
    }

    $efiOcPath = Join-Path -Path $efiMountPoint -ChildPath "EFI\OC"
    # Create EFI and OC directory if they don't exist
    try {
        if (-not (Test-Path -Path (Join-Path -Path $efiMountPoint -ChildPath "EFI") -PathType Container)) {
            New-Item -ItemType Directory -Path (Join-Path -Path $efiMountPoint -ChildPath "EFI") -ErrorAction Stop | Out-Null
        }
        if (-not (Test-Path -Path $efiOcPath -PathType Container)) {
            New-Item -ItemType Directory -Path $efiOcPath -ErrorAction Stop | Out-Null
            Write-Host "  Created directory structure: $efiOcPath"
        }
    } catch {
        Write-Error "Failed to create directory structure '$efiOcPath'. Error: $($_.Exception.Message)"
        return $null
    }
    
    return [PSCustomObject]@{
        Path = $efiOcPath
        TempDriveLetter = $tempDriveLetterAssigned # Will be $null if no letter was assigned by this function
    }
}


# --- Main Logic for Final File Copy ---
if ($null -ne $selectedUsbDrive -and ($prepResult -and $prepResult.Success)) {
    $usbEFIOCPaths = Get-UsbEfiOcPath -PreparedUsbInfo $prepResult -TargetDiskNumber $selectedUsbDrive.DiskNumber
    
    if ($usbEFIOCPaths -and $usbEFIOCPaths.Path) {
        $usbOcFullPath = $usbEFIOCPaths.Path
        Write-Host "Target USB EFI/OC path: $usbOcFullPath" -ForegroundColor Green

        # Create Kexts directory on USB
        $usbKextsDir = Join-Path -Path $usbOcFullPath -ChildPath "Kexts"
        if (-not (Test-Path -Path $usbKextsDir -PathType Container)) {
            try {
                New-Item -ItemType Directory -Path $usbKextsDir -ErrorAction Stop | Out-Null
                Write-Host "  Created Kexts directory on USB: $usbKextsDir"
            } catch {
                Write-Error "Failed to create Kexts directory '$usbKextsDir' on USB. Error: $($_.Exception.Message)"
                # Potentially halt or skip kext copying
            }
        }

        # Copy Kexts
        if (Test-Path -Path $usbKextsDir -PathType Container) {
            Write-Host "`nCopying kexts to USB..."
            # Define kexts that were downloaded (names of zip files, map to actual .kext later)
            $kextZipFiles = Get-ChildItem -Path $downloadDir -Filter "*.zip" | Where-Object {
                $_.Name -match "Lilu" -or $_.Name -match "WhateverGreen" -or $_.Name -match "VirtualSMC" -or `
                $_.Name -match "NVMeFix" -or $_.Name -match "RTL8111_driver_for_OS_X" # Adjust if zip names differ
            }

            if ($kextZipFiles.Count -eq 0) {
                Write-Warning "  No kext ZIP files found in '$downloadDir'. Ensure kexts were downloaded."
            }

            foreach ($kextZip in $kextZipFiles) {
                $kextBaseName = $kextZip.BaseName -replace '-RELEASE','' -replace '-MASTER','' -replace '_driver_for_OS_X','' # Simple name
                Write-Host "  Processing kext archive: $($kextZip.Name)"
                $tempKextExtractDir = Join-Path -Path $scriptRoot -ChildPath "temp_kext_extract_$(Get-Random)"
                
                if (Extract-ZipArchive -SourcePath $kextZip.FullName -DestinationPath $tempKextExtractDir) {
                    # Find .kext bundles within the extracted folder
                    # Some kexts are directly .kext, others might be in a subfolder or multiple .kexts (e.g. VirtualSMC + plugins)
                    $foundKextBundles = Get-ChildItem -Path $tempKextExtractDir -Recurse -Directory -Filter "*.kext" -ErrorAction SilentlyContinue
                    
                    if ($foundKextBundles.Count -gt 0) {
                        foreach ($kextBundle in $foundKextBundles) {
                            # Heuristic: Only copy kexts that are somewhat top-level or common (e.g. avoid examples, docs)
                            # This might need refinement if kexts are nested too deep or have complex structures.
                            # For VirtualSMC, we want SMCProcessor.kext, SMCSuperIO.kext, etc. if they are present.
                            if (($kextBundle.FullName.Split('\').Length - $tempKextExtractDir.Split('\').Length) -lt 4) { # Limit recursion depth
                                Write-Host "    Found .kext: $($kextBundle.Name). Copying to $usbKextsDir"
                                try {
                                    Copy-Item -Path $kextBundle.FullName -Destination $usbKextsDir -Recurse -Force -ErrorAction Stop
                                } catch {
                                    Write-Error "    Failed to copy $($kextBundle.Name). Error: $($_.Exception.Message)"
                                }
                            }
                        }
                    } else {
                        Write-Warning "    No .kext bundles found in extracted archive for $($kextZip.Name) at $tempKextExtractDir."
                    }
                }
                # Clean up temp kext extraction dir
                if (Test-Path -Path $tempKextExtractDir) { Remove-Item -Path $tempKextExtractDir -Recurse -Force -ErrorAction SilentlyContinue }
            }
            Write-Host "Kext copying process complete." -ForegroundColor Green
        }

        # Copy config.plist
        $sourceConfigPlist = Join-Path -Path $downloadDir -ChildPath "config.plist"
        if (Test-Path -Path $sourceConfigPlist -PathType Leaf) {
            $destinationConfigPlist = Join-Path -Path $usbOcFullPath -ChildPath "config.plist"
            Write-Host "`nCopying generated config.plist to USB: $destinationConfigPlist"
            try {
                Copy-Item -Path $sourceConfigPlist -Destination $destinationConfigPlist -Force -ErrorAction Stop
                Write-Host "  Successfully copied config.plist to USB." -ForegroundColor Green
            } catch {
                Write-Error "Failed to copy config.plist to USB. Error: $($_.Exception.Message)"
            }
        } else {
            Write-Warning "Generated config.plist not found at '$sourceConfigPlist'. Skipping copy to USB."
        }

        # Create ACPI directory on USB for SSDTs
        $usbAcpiDir = Join-Path -Path $usbOcFullPath -ChildPath "ACPI"
        if (-not (Test-Path -Path $usbAcpiDir -PathType Container)) {
            try {
                New-Item -ItemType Directory -Path $usbAcpiDir -ErrorAction Stop | Out-Null
                Write-Host "  Created ACPI directory on USB: $usbAcpiDir"
            } catch {
                Write-Warning "Failed to create ACPI directory '$usbAcpiDir' on USB. Error: $($_.Exception.Message)"
            }
        }

        # SSDT Guidance
        Write-Host "`n-------------------------------------" -ForegroundColor Yellow
        Write-Host "SSDT (Secondary System Description Table) Guidance" -ForegroundColor Yellow
        Write-Host "-------------------------------------"
        Write-Host "The generated config.plist references the following SSDTs for optimal Alder Lake performance:"
        Write-Host "  - SSDT-PLUG-ALT.aml (CPU Power Management)"
        Write-Host "  - SSDT-EC-USBX-DESKTOP.aml (Embedded Controller & USBX)"
        Write-Host "  - SSDT-AWAC-DISABLE.aml (Disables AWAC clock, uses system RTC)"
        Write-Host "  - SSDT-RHUB.aml (Resets USB RHUB ports)"
        Write-Host ""
        Write-Host "This script does NOT download or install these .aml files."
        Write-Host "You MUST download them manually."
        Write-Host "Recommended source: Dortania's Prebuilt SSDTs for Alder Lake."
        Write-Host "  Direct Link: https://dortania.github.io/Getting-Started-with-ACPI/SSDTs/prebuilt.html#desktop-alder-lake"
        Write-Host "  (Search 'Dortania prebuilt SSDTs Alder Lake' if the link is outdated)."
        Write-Host ""
        Write-Host "Once downloaded, place the .aml files into the following directory on your USB drive:"
        Write-Host "  $usbAcpiDir"
        Write-Host "-------------------------------------"

        # ISO Creation Guidance
        Write-Host "`n-------------------------------------" -ForegroundColor Yellow
        Write-Host "Bootable ISO Creation Guidance" -ForegroundColor Yellow
        Write-Host "-------------------------------------"
        Write-Host "This script prepares the USB drive to be bootable directly for Hackintosh installation."
        Write-Host "Creating a bootable .ISO file from this USB drive on Windows is a complex process"
        Write-Host "and is NOT handled by this script."
        Write-Host ""
        Write-Host "The USB drive itself is the primary intended boot media."
        Write-Host ""
        Write-Host "If you absolutely require an .ISO file, you will need to:"
        Write-Host "  1. Complete the macOS installation on a system using this USB drive."
        Write-Host "  2. Use tools within a macOS environment (like Disk Utility's 'Image from Folder' or third-party tools)"
        Write-Host "     to create an ISO from the macOS installer application or a fully installed system."
        Write-Host "-------------------------------------"


        # Clean up temporary drive letter if one was assigned by Get-UsbEfiOcPath
        if ($usbEFIOCPaths.TempDriveLetter) {
            Write-Host "`n  Attempting to remove temporary drive letter $($usbEFIOCPaths.TempDriveLetter) from EFI partition..."
            try {
                # Ensure the partition object is fresh before attempting to remove the letter
                $efiPartForCleanup = Get-Partition | Where-Object {$_.DiskNumber -eq $selectedUsbDrive.DiskNumber -and $_.PartitionNumber -eq $prepResult.EfiPartitionNumber}
                if ($efiPartForCleanup) {
                    Set-Partition -InputObject $efiPartForCleanup -NoDefaultDriveLetter -ErrorAction Stop
                    Write-Host "    Successfully removed temporary drive letter." -ForegroundColor Green
                } else {
                     Write-Warning "    Could not re-fetch EFI partition details for cleanup. Manual check might be needed."
                }
            } catch { Write-Warning "    Failed to remove temporary drive letter automatically: $($_.Exception.Message). You may ignore this or remove it manually via Disk Management." }
        }

    } else {
        Write-Error "Halting file copy to USB as EFI/OC path could not be determined or accessed."
    }
}


function Generate-ConfigPlist {
    param (
        # $systemInfo, # Pass the hardware info object later if needed for conditional logic
        [string]$MacSerialPath,
        [string]$SMBIOS = "iMac20,2" # Default SMBIOS for Alder Lake iGPU build
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
            "Delete" = @() # No common deletes needed initially
            "Patch" = @()  # No common patches needed initially, prefer SSDTs
            "Quirks" = [ordered]@{ # Standard Desktop Alder Lake Quirks
                "FadtEnableReset" = $false
                "NormalizeHeaders" = $false
                "RebaseRegions" = $false
                "ResetHwSig" = $false
                "ResetLogoStatus" = $true # Clears BIOS logo for smoother boot
                "SyncTableIds" = $false # Usually false, true if table IDs are out of sync
            }
        }
        "DeviceProperties" = [ordered]@{
            "Add" = [ordered]@{
                # PciRoot(0x0)/Pci(0x2,0x0) - Intel UHD 770 (Alder Lake iGPU)
                "PciRoot(0x0)/Pci(0x2,0x0)" = [ordered]@{
                    "AAPL,ig-platform-id" = "<data>CwAAkA==</data>" # 0B00A000 Base64 Encoded (0x0B00A000) - Alder Lake iGPU with display
                                                                   # Alternative: <data>CQAKAAAA</data> for 0900A000
                                                                   # Alternative for headless: <data>CgAAkA==</data> (0x0A00A000)
                    "framebuffer-patch-enable" = "<data>AQAAAA==</data>" # 01000000 (Enable framebuffer patching)
                    "framebuffer-stolenmem" = "<data>AAAABA==</data>"   # 00000004 (64MB minimum, usually fine for Alder Lake iGPU with enough system RAM) - Can be omitted for auto.
                                                                   # Forcing 64MB can sometimes help.
                    # "device-id" = "<data>pBkAAA==</data>" # 0x9A70 - Spoof if needed, but usually not for ADL UHD 770 with correct ig-platform-id
                    # "force-online" = "<data>AQAAAA==</data>" # Force online status for connectors if issues
                    # "enable-hdmi20" = "<data>AQAAAA==</data>" # Enable HDMI 2.0, if applicable
                }
                # PciRoot(0x0)/Pci(0x1F,0x3) - Onboard Audio (e.g., ALC897 on B760M)
                "PciRoot(0x0)/Pci(0x1F,0x3)" = [ordered]@{
                    "layout-id" = "<data>CwAAAA==</data>" # 0B000000 (Hex for 11) - Common for ALC897. Adjust if different codec/layout needed.
                    # "alc-delay" = 500 # milliseconds, if audio delay needed on boot
                    # "no-controller-patch" = "<data>AQAAAA==</data>" # If using AppleALC's controller patching causes issues
                }
            }
            "Delete" = [ordered]@{} # No common deletes needed initially
        }
        "Kernel" = [ordered]@{
            "Add" = @( # Order is important: Lilu, VirtualSMC, then others.
                # Lilu - Core patching kext
                [ordered]@{
                    "Arch" = "Any"; "BundlePath" = "Lilu.kext"; "Comment" = "Lilu kext"; "Enabled" = $true
                    "ExecutablePath" = "Contents/MacOS/Lilu"; "MaxKernel" = ""; "MinKernel" = ""; "PlistPath" = "Contents/Info.plist"
                },
                # VirtualSMC - SMC emulator
                [ordered]@{
                    "Arch" = "Any"; "BundlePath" = "VirtualSMC.kext"; "Comment" = "VirtualSMC kext"; "Enabled" = $true
                    "ExecutablePath" = "Contents/MacOS/VirtualSMC"; "MaxKernel" = ""; "MinKernel" = ""; "PlistPath" = "Contents/Info.plist"
                },
                # WhateverGreen - GPU patching
                [ordered]@{
                    "Arch" = "Any"; "BundlePath" = "WhateverGreen.kext"; "Comment" = "WhateverGreen kext"; "Enabled" = $true
                    "ExecutablePath" = "Contents/MacOS/WhateverGreen"; "MaxKernel" = ""; "MinKernel" = ""; "PlistPath" = "Contents/Info.plist"
                },
                # NVMeFix - For NVMe power management and compatibility
                [ordered]@{
                    "Arch" = "Any"; "BundlePath" = "NVMeFix.kext"; "Comment" = "NVMeFix kext"; "Enabled" = $true
                    "ExecutablePath" = "Contents/MacOS/NVMeFix"; "MaxKernel" = ""; "MinKernel" = ""; "PlistPath" = "Contents/Info.plist"
                },
                # Realtek Ethernet Kext (Assuming RTL8111/8168 variant from earlier download)
                # The BundlePath should match the kext downloaded (e.g., RealtekRTL8111.kext or similar)
                # This is a guess, user must verify kext name from their downloads.
                [ordered]@{
                    "Arch" = "Any"; "BundlePath" = "RealtekRTL8111.kext"; "Comment" = "Realtek RTL8111 Ethernet"; "Enabled" = $true
                    "ExecutablePath" = "Contents/MacOS/RealtekRTL8111"; "MaxKernel" = ""; "MinKernel" = ""; "PlistPath" = "Contents/Info.plist"
                }
                # Add other kexts like AppleALC (if not using DeviceProperties for layout-id), USBMap.kext, etc.
                # For AppleALC (if used):
                # [ordered]@{
                #    "Arch" = "Any"; "BundlePath" = "AppleALC.kext"; "Comment" = "AppleALC kext"; "Enabled" = $true
                #    "ExecutablePath" = "Contents/MacOS/AppleALC"; "MaxKernel" = ""; "MinKernel" = ""; "PlistPath" = "Contents/Info.plist"
                # }
            )
            "Block" = @() # For blocking problematic kexts, usually empty
            "Emulate" = [ordered]@{ # For CPU spoofing if needed, not typical for Alder Lake if SMBIOS is appropriate
                "Cpuid1Data" = "<data></data>" # Empty means no spoof
                "Cpuid1Mask" = "<data></data>" # Empty means no spoof
                "DummyPowerManagement" = $false # True for very old CPUs or specific unsupported ones
                "MaxKernel" = ""
                "MinKernel" = ""
            }
            "Force" = @() # Forcing kext injection, usually empty
            "Patch" = @() # Kernel patches, usually empty unless specific need
            "Quirks" = [ordered]@{ # Standard Desktop Alder Lake Kernel Quirks
                "AppleCpuPmCfgLock" = $false # Already false for most modern boards
                "AppleXcpmCfgLock" = $true  # Must be true for XCPM (native PM for Haswell+)
                "AppleXcpmExtraMsrs" = $false # Usually false, true for some specific XCPM needs
                "AppleXcpmForceBoost" = $false # Usually false
                "CustomPciSerialDevice" = $false # For custom serial port configuration via Misc/Serial
                "CustomSMBIOSGuid" = $false # False unless using custom SMBIOS GUID in PlatformInfo
                "DisableIoMapper" = $true   # Disables VT-D, can be false if VT-D is properly configured with DMAR table
                "DisableLinkeditJettison" = $true # Recommended for all systems
                "DisableRtcChecksum" = $false  # Usually false, true for some old systems
                "ExtendBTFeatureFlags" = $false # For Broadcom Bluetooth, set flags for extended features
                "ExternalDiskIcons" = $false # True to treat external drives as internal (Orange icons)
                "ForceAquantiaEthernet" = $false # For Aquantia 10GbE
                "ForceSecureBootScheme" = $false
                "IncreasePciBarSize" = $false # For systems with small PCI BARs (e.g. X99 with ReBAR for SAM)
                "LapicKernelPanic" = $false  # For HP systems or others with LAPIC issues
                "LegacyCommpage" = $false    # For very old CPUs
                "PanicNoKextDump" = $true   # Prevents kext dump in panic logs, cleaner logs
                "PowerTimeoutKernelPanic" = $true # Prevents sleep related panics from becoming reboot loops
                "ProvideCurrentCpuInfo" = $true # Essential for Alder Lake and newer for correct CPU info
                "SetApfsTrimTimeout" = -1 # Disables APFS trim timeout, usually -1 or 0. 999 for aggressive trim.
                "ThirdPartyDrives" = $false # True for TRIM on third-party SSDs on older macOS (not needed for NVMe on modern macOS)
                "XhciPortLimit" = $false    # False because USB mapping should be done via SSDT or USBMap.kext
            }
            "Scheme" = [ordered]@{ # Kernel cache scheme, usually default
                "CustomKernel" = $false # For custom compiled kernel
                "FuzzyMatch" = $true    # Recommended for future macOS compatibility
                "KernelArch" = "Auto"   # "Auto", "i386", "x86_64"
                "KernelCache" = "Auto"  # "Auto", "Cacheless", "Mkext"
            }
        }
        # Misc
        "Misc" = [ordered]@{
            "BlessOverride" = @()
            "Boot" = [ordered]@{
                "ConsoleAttributes" = 0
                "HibernateMode" = "None" # Or "Auto"
                "HibernateSkipsPicker" = $false
                "HideAuxiliary" = $false
                "InstanceIdentifier" = ""
                "LauncherOption" = "Disabled" # "Full" or "Short" to enable OpenCore as default boot, "Disabled" for testing
                "LauncherPath" = "Default"
                "PickerAttributes" = 17 # Enable GUI picker, 1 for text only
                "PickerAudioAssist" = $false
                "PickerMode" = "External" # "Builtin" or "External" (recommended)
                "PickerVariant" = "Auto" # Or specify like "Acidanthera\GoldenGate"
                "PollAppleHotKeys" = $true
                "ShowPicker" = $true
                "TakeoffDelay" = 0
                "Timeout" = 5
            }
            "Debug" = [ordered]@{
                "AppleDebug" = $true
                "ApplePanic" = $true # Creates panic log on USB EFI for debugging
                "DisableWatchDog" = $true # Prevents watchdog reboots
                "DisplayDelay" = 0
                "DisplayLevel" = 2147483650 # Default (DEBUG_INIT | DEBUG_ERROR | DEBUG_WARN | DEBUG_INFO | DEBUG_VERBOSE | DEBUG_LOAD)
                "LogModules" = "*" # Log all modules
                "SysReport" = $false
                "Target" = 3 # Log to screen and file (0 = disabled, 3 = screen+file, 67 = file only)
            }
            "Entries" = @() # For custom boot entries if needed
            "Security" = [ordered]@{
                "AllowSetDefault" = $true
                "ApECID" = 0
                "AuthRestart" = $false
                "BlacklistAppleUpdate" = $true # Recommended
                "DmgLoading" = "Signed" # "Any" for unsigned DMGs, "Signed" for Apple signed
                "EnablePassword" = $false
                "ExposeSensitiveData" = 6 # Bitmask: 0x1 (CPU name), 0x2 (SystemUUID), 0x4 (MLB, ROM, Serial)
                "HaltLevel" = 2147483648 # HALT_NONE
                "PasswordHash" = "<data></data>" # Empty if no password
                "PasswordSalt" = "<data></data>" # Empty if no password
                "ScanPolicy" = 0 # 0 for all devices
                "SecureBootModel" = "Disabled" # "Default" or other values for more security
                "Vault" = "Optional" # "Secure" or "Optional"
            }
            "Serial" = [ordered]@{ # For serial port configuration, usually not needed for desktops
                "Custom" = [ordered]@{
                    "BaudRate" = 115200
                    "ClockRate" = 1843200
                    "DetectCable" = $false
                    "ExtendedTxFifoSize" = 64
                    "FifoControl" = 7
                    "LineControl" = 3
                    "PciDeviceInfo" = "<data></data>" # Empty
                    "RegisterAccessWidth" = 8
                    "RegisterBase" = 1016
                    "RegisterStride" = 1
                    "UseHardwareFlowControl" = $false
                    "UseMmio" = $false
                }
                "Init" = $false
                "Override" = $false
            }
            "Tools" = @() # For OC tools like UEFI Shell, Memtest etc.
        }
        # NVRAM
        "NVRAM" = [ordered]@{
            "Add" = [ordered]@{
                "4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14" = [ordered]@{ # System Integrity Protection (SIP)
                    "DefaultBackgroundColor" = "<data>AAAAAA==</data>" # Black background, optional
                    "csr-active-config" = "<data>5wMAAA==</data>" # <E7030000> (SIP fully disabled: 0x3E7). <00000000> for SIP enabled.
                                                                    # Recommended initial: <E7030000> (0x3E7) or <030A0000> (0xA03) for allowing unsigned kexts + NVRAM protection
                                                                    # Using 0x3E7 (E7030000) for initial setup ease.
                }
                "7C436110-AB2A-4BBB-A880-FE41995C9F82" = [ordered]@{ # boot-args etc. (System Language, Boot Args)
                    "boot-args" = "-v debug=0x100 keepsyms=1 alcid=11 agdpmod=pikera" # alcid for layout-id 11, agdpmod for iGPU with dGPU. Add nv_disable=1 if needed.
                    "csr-active-config" = "<data>AAAAAA==</data>" # This is a duplicate key from OpenCore sample, but some guides include it. Let's use the one above.
                                                                  # Actually, this is a mistake in some samples. csr-active-config belongs to the other GUID.
                                                                  # Removing this csr-active-config from here.
                    "prev-lang:kbd" = "<data>ZW4tVVM6MA==</data>" # en-US:0 (en-US keyboard) Base64 encoded
                    "run-efi-updater" = "No"
                }
            }
            "Delete" = [ordered]@{ # Standard keys to delete for cleaner NVRAM
                "4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14" = @("csr-active-config") # Delete existing SIP if any
                "7C436110-AB2A-4BBB-A880-FE41995C9F82" = @("boot-args", "prev-lang:kbd") # Delete existing boot-args
            }
            "LegacyOverwrite" = $false
            "LegacySchema" = [ordered]@{ # For very old systems, not relevant for Alder Lake
                "7C436110-AB2A-4BBB-A880-FE41995C9F82" = @("EFILoginHiDPI", "EFIBluetoothDelay", "LocationServicesEnabled", "SystemAudioVolume", "SystemAudioVolumeDB", "SystemAudioVolumeSaved", "bluetoothActiveControllerInfo", "bluetoothInternalControllerInfo", "flagstate", "fmm-computer-name", "fmm-mobileme-token-FMM", "nvda_drv", "prev-lang:kbd")
                "8BE4DF61-93CA-11D2-AA0D-00E098032B8C" = @("Boot0080", "Boot0081", "Boot0082", "BootNext", "BootOrder")
            }
            "WriteFlash" = $true # Allow writing to NVRAM
        }
        # PlatformInfo - will be generated by Generate-PlatformInfo
        "PlatformInfo" = Generate-PlatformInfo -SMBIOSModel $SMBIOS -MacSerialUtilPath $MacSerialPath
        # UEFI
        "UEFI" = [ordered]@{
            "APFS" = [ordered]@{
                "EnableJumpstart" = $true
                "GlobalConnect" = $false # Set to true if path to APFS driver is not standard
                "HideVerbose" = $true   # Hides APFS verbose logging during boot
                "JumpstartHotPlug" = $false # Usually false
                "MinDate" = 0           # 0 for any version
                "MinVersion" = 0        # 0 for any version
            }
            "AppleInput" = [ordered]@{ # For Apple keyboards/mice in picker/bootloader
                "AppleEvent" = "Auto" # "Auto", "Builtin" or "Disabled"
                "CustomDelays" = $false # Or $true with specific delays if needed
                "KeyInitialDelay" = 50 # Standard value
                "KeySubsequentDelay" = 5 # Standard value
                "PointerSpeedDiv" = 1 # Standard value
                "PointerSpeedMul" = 1 # Standard value
            }
            "Audio" = [ordered]@{ # Audio settings for bootloader UI
                "AudioCodec" = 0 # Usually 0 unless specific codec needed for boot chime
                "AudioDevice" = "" # E.g., "PciRoot(0x0)/Pci(0x1F,0x3)" or empty for auto
                "AudioOutMask" = -1 # All channels
                "AudioSupport" = $false # Set to true for boot chime
                "DisconnectHda" = $false # Usually false
                "MaximumGain" = -15
                "MinimumAssistGain" = -30
                "MinimumAudibleGain" = -128 # Or -55
                "PlayChime" = "Auto" # "Auto", "Enabled", "Disabled"
                "ResetTrafficClass" = $false
                "SetupDelay" = 0 # Delay for audio setup
                "VolumeAmplifier" = 0 # Or 143 for some systems
            }
            "ConnectDrivers" = $true # Connects all UEFI drivers
            "Drivers" = @( # Essential drivers
                "HfsPlus.efi", # For HFS+ volumes (macOS Installers often use this)
                "OpenRuntime.efi", # Core OpenCore runtime services
                "OpenCanopy.efi"  # For GUI picker, remove if using text-only picker
                # Add other drivers like ExFatDxe.efi if needed, but usually not required with modern firmware
            )
            "Input" = [ordered]@{ # Input device settings for bootloader
                "KeyFiltering" = $false # Usually false
                "KeyForgetThreshold" = 5 # Standard
                "KeySupport" = $true # Enable keyboard input
                "KeySupportMode" = "Auto" # "Auto", "V1", "V2"
                "KeySwap" = $false # Swap Option/Command keys
                "PointerSupport" = $false # Set to true if using mouse in picker (requires compatible GOP)
                "PointerSupportMode" = "ASUS" # Or "UEFI", check Dortania for firmware compatibility
                "TimerResolution" = 50000 # Standard (50ms)
            }
            "Output" = [ordered]@{
                "ClearScreenOnModeSwitch" = $false
                "ConsoleMode" = "" # Empty for auto, or "Max" for max resolution
                "DirectGopRendering" = $false
                "ForceResolution" = $false # True with specific Resolution below if needed
                "GopPassThrough" = "Disabled" # Or "Apple", "UEFI"
                "IgnoreTextInGraphics" = $false
                "ProvideConsoleGop" = $true # Essential for GOP (Graphics Output Protocol)
                "ReconnectGraphicsOnConnect" = $false
                "ReconnectOnResChange" = $false
                "ReplaceTabWithSpace" = $false
                "Resolution" = "" # E.g., "1920x1080@32" or "Max"
                "SanitiseClearScreen" = $false # True for some firmwares with visual glitches
                "TextRenderer" = "BuiltinGraphics" # Or "SystemGraphics" / "SystemText"
                "UIScale" = -1 # -1 for auto, 1 or 2 for HiDPI scaling in picker
                "UgaPassThrough" = $false
            }
            "ProtocolOverrides" = [ordered]@{ # Usually default values are fine
                "AppleAudio" = $false
                "AppleBootPolicy" = $false
                "AppleDebugLog" = $false
                "AppleEg2Info" = $false
                "AppleFramebufferInfo" = $false
                "AppleImageConversion" = $false
                "AppleImg4Verification" = $false
                "AppleKeyMap" = $false
                "AppleRtcRam" = $false
                "AppleSecureBoot" = $false
                "AppleSmcIo" = $false
                "AppleUserInterfaceTheme" = $false
                "DataHub" = $false
                "DeviceProperties" = $false
                "FirmwareVolume" = $false # True for some Dell/older systems
                "HashServices" = $false # True for some Dell/older systems
                "OSInfo" = $false
                "UnicodeCollation" = $false # True for some HP systems
            }
            "Quirks" = [ordered]@{ # Standard Desktop Alder Lake UEFI Quirks
                "ActivateHpetSupport" = $false # Usually false unless HPET issues
                "DisableSecurityPolicy" = $false # True for some very locked down systems
                "EnableVectorAcceleration" = $true # For AVX acceleration in UEFI
                "EnableWriteUnprotector" = $false # True for older systems (Ivy Bridge and older)
                "ExitBootServicesDelay" = 0 # Or small delay like 3000000 for some systems
                "ForceOcWriteFlash" = $false # Use NVRAM/WriteFlash instead
                "ForgeUefiSupport" = $false # For very old UEFI or legacy systems
                "IgnoreInvalidFlexRatio" = $false # Usually false, True for some X99/X299
                "ReleaseUsbOwnership" = $true # Essential for USB ports to work correctly in macOS
                "ReloadOptionRoms" = $false # For systems needing to reload OptionROMs (e.g. GPU)
                "RequestBootVarRouting" = $true # Standard for modern systems
                "ResizeGpuBars" = -1 # -1 to disable, 0-19 for specific bar sizes. For Resizable BAR.
                "TscSyncTimeout" = 0 # Usually 0
                "UnblockFsConnect" = $false # True for some HP systems with missing SATA/NVMe
            }
            "ReservedMemory" = @() # For excluding specific memory regions if needed
        }
    }
    # Remove the incorrect csr-active-config from the second NVRAM Add section
    $config.NVRAM.Add."7C436110-AB2A-4BBB-A880-FE41995C9F82".Remove("csr-active-config")


    return $config
}

# --- Main logic integration for config.plist ---
# Determine path to macserial.exe
# This needs to be robust. Assuming OpenCore was downloaded and extracted.
$ocDownloadFolder = Get-ChildItem -Path $downloadDir -Directory -Filter "OpenCore-*-RELEASE" | Sort-Object CreationTime -Descending | Select-Object -First 1
$macSerialPath = ""
if ($ocDownloadFolder) {
    $macSerialPath = Join-Path -Path $ocDownloadFolder.FullName -ChildPath "Utilities\macserial\macserial.exe"
    if (-not (Test-Path -Path $macSerialPath -PathType Leaf)) {
         # Check for macserial (no .exe) for non-windows if script were cross-platform
        $macSerialPath = Join-Path -Path $ocDownloadFolder.FullName -ChildPath "Utilities\macserial\macserial" 
    }
}

if (-not (Test-Path -Path $macSerialPath -PathType Leaf)) {
    Write-Warning "macserial utility not found in downloaded OpenCore package at expected path (e.g., $downloadDir\OpenCore-X.Y.Z-RELEASE\Utilities\macserial\)."
    Write-Warning "PlatformInfo will contain placeholder values. You MUST generate them manually."
    # Allow script to continue with a placeholder path, Generate-PlatformInfo will handle it
    $macSerialPath = "NOT_FOUND_macserial" # Placeholder, Generate-PlatformInfo will warn
} else {
    Write-Host "macserial utility found at: $macSerialPath" -ForegroundColor Green
}

$generatedConfig = Generate-ConfigPlist -MacSerialPath $macSerialPath -SMBIOS "iMac20,2"
$configPlistOutputPath = Join-Path -Path $downloadDir -ChildPath "config.plist"

if (ConvertTo-PlistXml -InputObject $generatedConfig -OutputPath $configPlistOutputPath) {
    Write-Host "Generated config.plist has been saved to: $configPlistOutputPath" -ForegroundColor Cyan
    Write-Host "IMPORTANT: Review this generated config.plist carefully against Dortania guides for Alder Lake." -ForegroundColor Yellow
    Write-Host "You will need to copy this file to the EFI/OC/ directory on your prepared USB drive."
    Write-Host "Also, ensure you have the necessary Kexts and SSDTs in their respective EFI/OC subdirectories."
} else {
    Write-Error "Failed to generate or save config.plist."
}


function Prepare-UsbDrive {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$UsbDrive # The object from Select-UsbDrive
    )

    Write-Host "`nPreparing USB Drive: Disk $($UsbDrive.DiskNumber) - $($UsbDrive.FriendlyName) ($($UsbDrive.SizeGB) GB)" -ForegroundColor Yellow
    
    # Confirmation
    Write-Warning "ALL DATA ON DISK $($UsbDrive.DiskNumber) ($($UsbDrive.FriendlyName)) WILL BE ERASED!"
    $confirmation = Read-Host "Are you absolutely sure you want to continue? Type 'YES' to proceed:"
    if ($confirmation -ne 'YES') {
        Write-Host "USB drive preparation aborted by user." -ForegroundColor Red
        return $null
    }

    Write-Host "Proceeding with wiping Disk $($UsbDrive.DiskNumber)..."
    try {
        # Clear existing partitions and data
        Write-Host "  Clearing disk $($UsbDrive.DiskNumber)... (This may take a few moments)"
        Clear-Disk -Number $UsbDrive.DiskNumber -RemoveData -RemoveOEM -Confirm:$false -PassThru -ErrorAction Stop
        Write-Host "  Disk cleared successfully." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to clear disk $($UsbDrive.DiskNumber). Error: $($_.Exception.Message)"
        Write-Warning "Make sure no File Explorer windows are open for this drive, and no other processes are using it."
        return $null
    }

    # Initialize Disk as GPT
    try {
        Write-Host "  Initializing disk $($UsbDrive.DiskNumber) as GPT..."
        Initialize-Disk -Number $UsbDrive.DiskNumber -PartitionStyle GPT -PassThru -ErrorAction Stop | Out-Null
        Write-Host "  Disk initialized as GPT successfully." -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to initialize disk $($UsbDrive.DiskNumber) as GPT. Error: $($_.Exception.Message)"
        return $null
    }

    # Create EFI Partition
    $efiPartition = $null
    $efiVolume = $null
    try {
        Write-Host "  Creating EFI partition (500MB, FAT32)..."
        # Standard GPT type for EFI System Partition
        $efiPartitionType = '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
        $efiPartition = New-Partition -DiskNumber $UsbDrive.DiskNumber -Size 500MB -GptType $efiPartitionType -ErrorAction Stop
        
        # Wait a moment for the partition to be recognized before formatting
        Start-Sleep -Seconds 5 

        $efiVolume = Format-Volume -Partition $efiPartition -FileSystem FAT32 -NewFileSystemLabel "EFI" -Confirm:$false -Force -ErrorAction Stop
        Write-Host "  EFI partition created and formatted as FAT32 (Label: EFI)." -ForegroundColor Green
        if ($efiVolume.DriveLetter) {
            Write-Host "    EFI Volume assigned Drive Letter: $($efiVolume.DriveLetter)"
        } else {
            Write-Host "    EFI Volume did not automatically get a drive letter. Manual assignment might be needed if issues occur."
            # Attempt to assign a drive letter (this is experimental and might not always work or be desired)
            # try {
            #     $availableLetters = Get-Volume | Select-Object -ExpandProperty DriveLetter | Where-Object { $_ -ne $null }
            #     $letterToAssign = (69..90 | ForEach-Object {[char]$_}) | Where-Object {$availableLetters -notcontains $_} | Select-Object -First 1
            #     if ($letterToAssign) {
            #         Write-Host "    Attempting to assign letter $letterToAssign to EFI partition..."
            #         Set-Partition -DiskNumber $UsbDrive.DiskNumber -PartitionNumber $efiPartition.PartitionNumber -NewDriveLetter $letterToAssign -ErrorAction Stop
            #         $efiVolume = Get-Volume -Partition $efiPartition # Refresh volume info
            #         Write-Host "    EFI partition assigned drive letter: $($efiVolume.DriveLetter)"
            #     }
            # } catch { Write-Warning "    Failed to auto-assign drive letter to EFI: $($_.Exception.Message)" }
        }
    }
    catch {
        Write-Error "Failed to create or format EFI partition on disk $($UsbDrive.DiskNumber). Error: $($_.Exception.Message)"
        return $null
    }

    # Create macOS Installer Partition (exFAT)
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
        EfiVolume = $efiVolume # Contains DriveLetter if assigned
        MacOsInstallVolume = $macOsVolume # Contains DriveLetter if assigned
        EfiPartitionNumber = $efiPartition.PartitionNumber
        MacOsInstallPartitionNumber = $macOsPartition.PartitionNumber
    }
}

# Main logic integration (example call, will be refined)
if ($null -ne $selectedUsbDrive) {
    $prepResult = Prepare-UsbDrive -UsbDrive $selectedUsbDrive
    if ($prepResult -and $prepResult.Success) {
        Write-Host "`nUSB Drive preparation successful." -ForegroundColor Green
        # Displaying full volume details can be verbose, let's show key info
        if ($prepResult.EfiVolume) {
            Write-Host "  EFI Volume: Label '$($prepResult.EfiVolume.FileSystemLabel)', Letter '$($prepResult.EfiVolume.DriveLetter)', Path '$($prepResult.EfiVolume.Path)'"
        }
        if ($prepResult.MacOsInstallVolume) {
            Write-Host "  MACOS_INSTALL Volume: Label '$($prepResult.MacOsInstallVolume.FileSystemLabel)', Letter '$($prepResult.MacOsInstallVolume.DriveLetter)', Path '$($prepResult.MacOsInstallVolume.Path)'"
        }

        # --- Copy OpenCore to EFI Partition ---
        Write-Host "`n-------------------------------------" -ForegroundColor Yellow
        Write-Host "Copying OpenCore to EFI Partition" -ForegroundColor Yellow
        Write-Host "-------------------------------------"

        $efiMountPoint = $null
        if ($prepResult.EfiVolume -and $prepResult.EfiVolume.DriveLetter) {
            $efiMountPoint = "$($prepResult.EfiVolume.DriveLetter):\" # Path like E:\
        } elseif ($prepResult.EfiVolume -and $prepResult.EfiVolume.Path) {
            # Fallback if DriveLetter is not assigned but a path (like \\?\Volume{guid}\) exists
            # However, Copy-Item might not work directly with these paths without specific handling.
            # For now, prioritize drive letter. If not available, this step will likely fail or need user intervention.
            # A more robust solution might involve MountVol.exe or other methods to temporarily assign a letter if missing.
            # For now, we'll rely on the system assigning one or the Get-Volume providing a usable path.
            # $efiMountPoint = $prepResult.EfiVolume.Path # This might not be directly usable by Copy-Item for root.
            Write-Warning "EFI partition does not have a drive letter. Automatic OpenCore copy might fail."
            Write-Host "Attempting to use volume path: $($prepResult.EfiVolume.Path)"
            # Check if the path is a typical mount point, if not, it might be problematic
             if ($prepResult.EfiVolume.Path -notlike "\\?\Volume*\") { # If it's already a mount point like C:\mount\EFI
                $efiMountPoint = $prepResult.EfiVolume.Path
             } else {
                 # Try to get a temporary drive letter
                $efiPart = Get-Partition -DiskNumber $selectedUsbDrive.DiskNumber -PartitionNumber $prepResult.EfiPartitionNumber
                $tempDriveLetter = $null
                Write-Host "  Attempting to assign a temporary drive letter to the EFI partition..."
                try {
                    $availableLetters = Get-Volume | Select-Object -ExpandProperty DriveLetter | Where-Object { $_ -ne $null }
                    $letterToAssign = (69..90 | ForEach-Object {[char]$_}) | Where-Object {$availableLetters -notcontains $_} | Select-Object -First 1
                    if ($letterToAssign) {
                        Set-Partition -InputObject $efiPart -NewDriveLetter $letterToAssign -ErrorAction Stop
                        Start-Sleep -Seconds 3 # Give time for letter to be assigned
                        $refreshedVolume = Get-Volume -Partition $efiPart
                        if ($refreshedVolume.DriveLetter) {
                            $efiMountPoint = "$($refreshedVolume.DriveLetter):\"
                            $tempDriveLetter = $refreshedVolume.DriveLetter
                            Write-Host "    Successfully assigned temporary drive letter $tempDriveLetter to EFI partition." -ForegroundColor Green
                        }
                    } else { Write-Warning "    No available drive letters to assign to EFI partition."}
                } catch { Write-Warning "    Failed to assign temporary drive letter to EFI: $($_.Exception.Message)" }
             }
        }

        if (-not $efiMountPoint) {
            Write-Error "Could not determine EFI mount point. Cannot copy OpenCore files."
            Write-Warning "You may need to manually assign a drive letter to the EFI partition (e.g., using Disk Management or diskpart) and copy the EFI folder from the downloads directory."
        } else {
            # Find OpenCore ZIP file
            $ocZipPattern = "OpenCore-*-RELEASE.zip" # General pattern
            $ocZipFile = Get-ChildItem -Path $downloadDir -Filter $ocZipPattern | Sort-Object CreationTime -Descending | Select-Object -First 1
            
            if (-not $ocZipFile) {
                Write-Warning "Could not find downloaded OpenCore ZIP file in '$downloadDir' matching pattern '$ocZipPattern'."
            } else {
                Write-Host "Found OpenCore ZIP: $($ocZipFile.FullName)"
                $tempExtractDir = Join-Path -Path $scriptRoot -ChildPath "temp_oc_extract_$$" # Unique temp dir name
                
                if (Extract-ZipArchive -SourcePath $ocZipFile.FullName -DestinationPath $tempExtractDir) {
                    $ocEfiSourcePath = Join-Path -Path $tempExtractDir -ChildPath "EFI" # Standard OC structure has EFI folder at root of zip
                    # Some OC zips might have it nested, e.g. OpenCore-0.X.X-RELEASE/EFI. Check for common structures.
                    if (-not (Test-Path -Path $ocEfiSourcePath -PathType Container)) {
                         $nestedOcPath = Get-ChildItem -Path $tempExtractDir -Directory | Where-Object {$_.Name -like "OpenCore-*-RELEASE"} | Select-Object -First 1
                         if ($nestedOcPath) {
                            $ocEfiSourcePath = Join-Path -Path $nestedOcPath.FullName -ChildPath "EFI"
                         }
                    }


                    if (Test-Path -Path $ocEfiSourcePath -PathType Container) {
                        $efiDestination = Join-Path -Path $efiMountPoint -ChildPath "EFI"
                        Write-Host "Copying '$ocEfiSourcePath' to '$efiDestination'..."
                        try {
                            # Ensure EFI directory exists on target, Copy-Item -Recurse expects parent of EFI to exist.
                            if (-not (Test-Path -Path $efiMountPoint -PathType Container)) {
                                Write-Error "EFI mount point '$efiMountPoint' is not accessible or does not exist."
                                throw "EFI mount point not found."
                            }
                             # Remove existing EFI folder on USB if it exists to prevent merge issues (e.g. from previous runs)
                            if (Test-Path -Path $efiDestination) {
                                Write-Host "  Removing existing EFI folder at '$efiDestination' before copying."
                                Remove-Item -Path $efiDestination -Recurse -Force -ErrorAction Stop
                            }

                            Copy-Item -Path $ocEfiSourcePath -Destination $efiMountPoint -Recurse -Force -ErrorAction Stop
                            Write-Host "Successfully copied OpenCore EFI folder to '$efiDestination'." -ForegroundColor Green
                        }
                        catch {
                            Write-Error "Failed to copy OpenCore EFI folder. Error: $($_.Exception.Message)"
                            Write-Warning "Please ensure the EFI partition ($efiMountPoint) is accessible and try copying manually from '$ocEfiSourcePath'."
                        }
                    } else {
                        Write-Warning "Could not find 'EFI' folder within the extracted OpenCore archive at '$tempExtractDir'. Looked for '$ocEfiSourcePath'."
                    }
                }

                # Clean up temp extraction directory
                if (Test-Path -Path $tempExtractDir -PathType Container) {
                    Write-Host "Cleaning up temporary extraction directory: $tempExtractDir"
                    Remove-Item -Path $tempExtractDir -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
         # Remove temporary drive letter if assigned
        if ($tempDriveLetter) {
            Write-Host "  Attempting to remove temporary drive letter $tempDriveLetter from EFI partition..."
            try {
                Set-Partition -InputObject $efiPart -NoDefaultDriveLetter -ErrorAction Stop # Preferred way
                # Alternative: Remove-PartitionAccessPath -DiskNumber $selectedUsbDrive.DiskNumber -PartitionNumber $prepResult.EfiPartitionNumber -AccessPath "$($tempDriveLetter):\"
                Write-Host "    Successfully removed temporary drive letter $tempDriveLetter." -ForegroundColor Green
            } catch { Write-Warning "    Failed to remove temporary drive letter $tempDriveLetter automatically: $($_.Exception.Message). You may ignore this or remove it manually via Disk Management."}
        }
    } else {
        Write-Warning "`nUSB Drive preparation failed or was aborted."
    }
}

# --- macOS Download Guidance (via gibMacOS) ---
Write-Host "`n-------------------------------------" -ForegroundColor Yellow
Write-Host "macOS Download Stage (using gibMacOS)" -ForegroundColor Yellow
Write-Host "-------------------------------------"

$gibMacOSBatchFileDir = Join-Path -Path $downloadDir -ChildPath "gibMacOS-master" # Root of gibMacOS extracted folder
$gibMacOSBatchFilePath = Join-Path -Path $gibMacOSBatchFileDir -ChildPath "gibMacOS.bat"

if (-not (Test-Path -Path $gibMacOSBatchFilePath -PathType Leaf)) {
    Write-Error "gibMacOS.bat not found at expected location: $gibMacOSBatchFilePath"
    Write-Warning "Please ensure gibMacOS was downloaded correctly into the '$($downloadDir)\gibMacOS-master' directory."
    Write-Host "`nScript execution halted."
    Exit 1
} else {
    Write-Host "gibMacOS.bat found: $gibMacOSBatchFilePath" -ForegroundColor Green
    Write-Host "`nAction Required:" -ForegroundColor Cyan
    Write-Host "1. Open a new Command Prompt or PowerShell window."
    Write-Host "2. Navigate to: cd '$gibMacOSBatchFileDir'"
    Write-Host "3. Run the script: .\gibMacOS.bat"
    Write-Host "4. When prompted by gibMacOS, choose the option for macOS Sequoia (e.g., version 14.x)."
    Write-Host "   (It should be listed under 'publicrelease' or similar)."
    Write-Host "5. Allow the download to complete fully. This will download macOS installer files into a"
    Write-Host "   subfolder within: '$gibMacOSBatchFileDir\macOS Downloads\'"
    Write-Host "`n----------------------------------------------------------------------------------" -ForegroundColor Yellow
    Read-Host -Prompt "Press Enter here ONLY AFTER you have successfully downloaded macOS Sequoia using gibMacOS.bat"
    Write-Host "`n----------------------------------------------------------------------------------" -ForegroundColor Yellow
}

# Function to find downloaded macOS files
function Find-DownloadedMacOS {
    param (
        [Parameter(Mandatory=$true)]
        [string]$SearchPath, # e.g., "$downloadDir/gibMacOS-master/macOS Downloads/"
        [Parameter(Mandatory=$true)]
        [string]$TargetVersionName # e.g., "Sequoia"
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

    if (-not (Test-Path -Path $SearchPath -PathType Container)) {
        Write-Warning "  Search path '$SearchPath' does not exist."
        return $null
    }

    # gibMacOS typically saves to subfolders like 'publicrelease', 'developer'
    $subFoldersToSearch = @("publicrelease", "developer", "") # "" for direct search in SearchPath
    
    foreach ($subFolder in $subFoldersToSearch) {
        $currentSearchBasePath = Join-Path -Path $SearchPath -ChildPath $subFolder
        if (-not (Test-Path -Path $currentSearchBasePath -PathType Container)) {
            Write-Verbose "  Subfolder '$currentSearchBasePath' not found, skipping."
            continue
        }
        Write-Verbose "  Checking in: $currentSearchBasePath"

        # Look for directories containing the target version name
        $candidateDirs = Get-ChildItem -Path $currentSearchBasePath -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $TargetVersionName }
        
        foreach ($dir in $candidateDirs) {
            Write-Verbose "    Found potential directory: $($dir.FullName)"
            # Check for key indicator files/folders
            if (Test-Path -Path (Join-Path $dir.FullName "BaseSystem.dmg") -PathType Leaf) {
                Write-Host "  [+] Validated macOS $TargetVersionName found at: $($dir.FullName) (BaseSystem.dmg exists)" -ForegroundColor Green
                return $dir.FullName
            }
            # Add more checks if needed, e.g., for InstallESDDmg.pkg or an .app structure
            # if (Test-Path -Path (Join-Path $dir.FullName "InstallESDDmg.pkg") -PathType Leaf) { ... }
            # if (Test-Path -Path (Join-Path $dir.FullName "Install macOS $($TargetVersionName).app") -PathType Container) { ... }
        }
    }

    Write-Warning "  Could not find a validated macOS $TargetVersionName installer directory containing BaseSystem.dmg under '$SearchPath'."
    return $null
}

# Main logic integration for finding macOS files
$macOsInstallerSourcePath = $null
$macOsSearchBaseDir = Join-Path -Path $gibMacOSBatchFileDir -ChildPath "macOS Downloads" 

Write-Host "Attempting to locate macOS Sequoia files..."
$macOsInstallerSourcePath = Find-DownloadedMacOS -SearchPath $macOsSearchBaseDir -TargetVersionName "Sequoia"

if ($macOsInstallerSourcePath) {
    Write-Host "Successfully located macOS Sequoia installer files: $macOsInstallerSourcePath" -ForegroundColor Green
    Write-Host "`nIMPORTANT REMINDERS:" -ForegroundColor Yellow
    Write-Host "1. Ensure the 'MACOS_INSTALL' partition on your USB drive (e.g., Drive '$($prepResult.MacOsInstallVolume.DriveLetter):') is reformatted"
    Write-Host "   to 'Mac OS Extended (Journaled)' or 'APFS' using Disk Utility from macOS."
    Write-Host "2. You will then need to manually copy the ENTIRE CONTENTS of the folder:"
    Write-Host "   '$macOsInstallerSourcePath'"
    Write-Host "   to the root of the 'MACOS_INSTALL' partition."
    Write-Host "3. After that, you can proceed to configure your EFI/OpenCore `config.plist`."
} else {
    Write-Error "Could not automatically locate the downloaded macOS Sequoia files in '$macOsSearchBaseDir'."
    Write-Warning "Please ensure you ran gibMacOS.bat, downloaded macOS Sequoia, and that the files are in a subdirectory"
    Write-Warning "like '$($macOsSearchBaseDir)\publicrelease\*Sequoia*' or '$($macOsSearchBaseDir)\developer\*Sequoia*'."
    Write-Warning "You will need to manually identify this location for the next steps of creating the installer."
}


Write-Host "`nScript execution finished. Please review all outputs and guidance."
Write-Host "Remember to manually download SSDTs and prepare the macOS installer partition as instructed."

function Show-FinalGuidance {
    param (
        [string]$UsbEfiOcAcpiPath # Path to EFI/OC/ACPI on USB for SSDT instruction
    )

    Write-Host "`n`n------------------------------------------------------------------" -ForegroundColor Green
    Write-Host "FINAL GUIDANCE & IMPORTANT REMINDERS" -ForegroundColor Green
    Write-Host "------------------------------------------------------------------"

    # 1. BIOS Settings Reminder
    Write-Host "`n[1] Recommended BIOS Settings (vary by motherboard):" -ForegroundColor Yellow
    Write-Host "  DISABLE:"
    Write-Host "    - Secure Boot"
    Write-Host "    - Fast Boot"
    Write-Host "    - CSM (Compatibility Support Module)"
    Write-Host "    - Intel SGX (Software Guard Extensions)"
    Write-Host "    - CFG Lock (MSR 0xE2 Write Protection) - If this option exists, disable it. If not, ensure Kernel->Quirks->AppleXcpmCfgLock is true."
    Write-Host "    - Resizable BAR Support (if causing issues with iGPU, can be re-enabled later. Or set ResizeGpuBars = 0 in config)"
    Write-Host "  ENABLE:"
    Write-Host "    - VT-d (Virtualization Technology for Directed I/O) - Can be enabled if `DisableIoMapper` quirk is true (as set by this script)."
    Write-Host "    - Above 4G Decoding (Crucial for modern GPUs & some drivers)"
    Write-Host "    - EHCI/XHCI Hand-off"
    Write-Host "    - OS Type: Windows 8.1/10 UEFI Mode, or 'Other OS' (for UEFI boot)"
    Write-Host "    - DVMT Pre-Allocated (for iGPU): Typically 64M or 128M. (UHD 770 often works well with 64M if system RAM is plentiful)."
    Write-Host "    - XMP Profile for RAM: Profile 1 (or equivalent)"
    Write-Host "  Note: Consult your motherboard manual and Dortania's guides for specific settings."

    # 2. Script Automation Summary & Manual Steps
    Write-Host "`n[2] Script Automation Summary & Your Manual Steps:" -ForegroundColor Yellow
    Write-Host "  This script has automated:"
    Write-Host "    - Basic hardware information gathering."
    Write-Host "    - Download of OpenCore, essential Kexts, and gibMacOS."
    Write-Host "    - USB drive preparation (EFI partition, exFAT for macOS installer data)."
    Write-Host "    - Generation of a baseline OpenCore config.plist for Alder Lake (iGPU focus, iMac20,2 SMBIOS)."
    Write-Host "    - Copying of Kexts and the generated config.plist to the USB's EFI partition."
    Write-Host "  Your crucial MANUAL steps remaining:"
    Write-Host "    a. Download SSDT .aml files: As previously instructed, download the required .aml files for Alder Lake"
    Write-Host "       (SSDT-PLUG-ALT, SSDT-EC-USBX-DESKTOP, SSDT-AWAC-DISABLE, SSDT-RHUB) from Dortania's Prebuilt SSDTs page"
    Write-Host "       (https://dortania.github.io/Getting-Started-with-ACPI/SSDTs/prebuilt.html#desktop-alder-lake)"
    Write-Host "       and place them into: '$UsbEfiOcAcpiPath'"
    Write-Host "    b. Reformat 'MACOS_INSTALL' Partition: Boot from the USB, open Disk Utility (from Utilities menu),"
    Write-Host "       select the 'MACOS_INSTALL' partition, erase it, and format as 'APFS' (recommended) or 'Mac OS Extended (Journaled)'."
    Write-Host "    c. Copy macOS Installer Files: After formatting, quit Disk Utility. If the 'Install macOS' app doesn't start automatically,"
    Write-Host "       run the 'gibMacOS.bat' again (if needed, to re-identify the path) or locate your downloaded macOS files"
    Write-Host "       (e.g., in '$($downloadDir)\gibMacOS-master\macOS Downloads\publicrelease\*Sequoia*')."
    Write-Host "       Copy the *contents* of that folder (BaseSystem.dmg, etc.) to the root of your newly formatted 'MACOS_INSTALL' partition."
    Write-Host "       (This step is often done from within the macOS Installer environment if you use the 'Reinstall macOS' option after partitioning)."
    Write-Host "       Alternatively, some prefer to make the full installer app on another Mac and copy that."
    Write-Host "    d. Initial Boot & Troubleshooting: Attempt to boot from the USB. Be prepared to troubleshoot."
    Write-Host "       Review the generated config.plist. You may need to adjust DeviceProperties (especially iGPU settings if issues arise),"
    Write-Host "       kexts, or boot arguments based on your specific hardware and boot results."

    # 3. Nvidia GTX 970 Reminder
    # This reminder is kept for general context, even if the current config is iGPU focused.
    # If a user *has* this dGPU, it's relevant.
    $hardwareInfoForGpuCheck = Get-SystemInfo # Re-fetch for GPU check, or pass from main if already available
    if ($hardwareInfoForGpuCheck.GPUs | Where-Object {$_.Name -match "GTX 970" -or $_.DeviceID -match "13C2"}) { # 13C2 is DeviceID for GTX 970
        Write-Host "`n[3] Nvidia GTX 970 (Maxwell) GPU Note:" -ForegroundColor Yellow
        Write-Host "  macOS Sequoia (and recent macOS versions) DO NOT have drivers for Nvidia Maxwell (GTX 9xx) GPUs like the GTX 970."
        Write-Host "  This script has configured the system to primarily use the Intel iGPU (UHD 770) for graphics acceleration."
        Write-Host "  - If your monitor is connected to the iGPU (motherboard video output), you should get full graphics acceleration."
        Write-Host "  - If your monitor is connected to the GTX 970, you will likely experience NO graphics acceleration in macOS."
        Write-Host "    It's recommended to use the iGPU for display output for the best experience."
        Write-Host "    The `agdpmod=pikera` boot-arg is included, which helps with display output on some GPUs, but does not enable acceleration for Maxwell."
        Write-Host "    Consider removing or disabling the GTX 970 if not needed, or ensure displays are connected to the motherboard for iGPU output."
    }

    # 4. Troubleshooting Resources
    Write-Host "`n[4] Troubleshooting Resources:" -ForegroundColor Cyan
    Write-Host "  - Dortania's OpenCore Install Guide: https://dortania.github.io/OpenCore-Install-Guide/"
    Write-Host "  - Dortania's OpenCore Post-Install Guide: https://dortania.github.io/OpenCore-Post-Install/"
    Write-Host "  - Dortania's Troubleshooting: https://dortania.github.io/OpenCore-Install-Guide/troubleshooting/troubleshooting.html"
    Write-Host "  - Relevant online communities (e.g., r/hackintosh, InsanelyMac) can also be helpful, but always check Dortania's guides first."

    # 5. Disclaimer
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

# Call the final guidance function at the very end of the script
# It needs the path to EFI/OC/ACPI on the USB to correctly instruct the user for SSDTs
$finalUsbAcpiPath = "your_USB_EFI_OC_ACPI_path_here" # Default if $usbAcpiDir is not set
if ($usbAcpiDir -and (Test-Path -Path $usbAcpiDir)) { # $usbAcpiDir is defined in the file copy stage
    $finalUsbAcpiPath = $usbAcpiDir
} elseif ($usbOcFullPath) { # If $usbOcFullPath was set but $usbAcpiDir somehow wasn't
     $finalUsbAcpiPath = Join-Path -Path $usbOcFullPath -ChildPath "ACPI"
}

Show-FinalGuidance -UsbEfiOcAcpiPath $finalUsbAcpiPath
