<#
.SYNOPSIS
Enhanced system enumeration script for detailed system analysis on Windows 10 and above.

.DESCRIPTION
This script performs advanced enumeration of firewall rules, installed software, scheduled tasks, services, file permissions, and network information.
It includes a full directory listing with user-defined depth, SAM file permission enumeration, and improved output formatting.
It now prints progress messages to the console for user feedback.

.PARAMETER OutputFilename
Specifies the output file to save the results.

.PARAMETER ExcludeDirectories
Specifies directories to exclude during file and folder permissions enumeration.

.PARAMETER ScanDirectories
Specifies directories to scan for file and folder permissions.

.PARAMETER DirectoryDepth
Specifies the maximum depth for directory listing enumeration.

.PARAMETER Sections
Allows enabling or disabling specific sections of enumeration.

.EXAMPLE
.\Advanced-Enum.ps1 -OutputFilename "C:\Temp\SystemReport.txt" -ExcludeDirectories @("C:\Windows", "C:\Program Files") -DirectoryDepth 3
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $false)]
    [String]$OutputFilename = ".\AdvancedSystemReport.txt",

    [Parameter(Mandatory = $false)]
    [String[]]$ExcludeDirectories = @("C:\Windows", "C:\Program Files"),

    [Parameter(Mandatory = $false)]
    [String[]]$ScanDirectories = @("C:\"),

    [Parameter(Mandatory = $false)]
    [Int]$DirectoryDepth = 3,

    [Parameter(Mandatory = $false)]
    [String[]]$Sections = @("Firewall", "InstalledSoftware", "ScheduledTasks", "Services", "FilePermissions", "DirectoryListing", "SAMPermissions", "Network")
)

# Ensure the script is run as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator!"
    exit
}

# Initialize a StringBuilder for output
$outputBuilder = New-Object System.Text.StringBuilder

Function Write-Log {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [string]$Type = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp][$Type] $Message"
    $outputBuilder.AppendLine($logMessage) | Out-Null
    # Also print to console so user sees progress:
    Write-Host $logMessage
}

# Firewall Enumeration
Function Enumerate-Firewall {
    Write-Log "Starting firewall rules enumeration..."
    try {
        $firewallRules = Get-NetFirewallRule | Sort-Object DisplayName
        foreach ($rule in $firewallRules) {
            $ruleDetails = @{
                "Name"            = $rule.DisplayName
                "Enabled"         = $rule.Enabled
                "Direction"       = $rule.Direction
                "Action"          = $rule.Action
                "Protocol"        = $rule.Protocol
                "LocalAddresses"  = $rule.LocalAddresses
                "RemoteAddresses" = $rule.RemoteAddresses
            }
            $outputBuilder.AppendLine(($ruleDetails | Format-Table | Out-String)) | Out-Null
        }
        Write-Log "Completed firewall rules enumeration."
    } catch {
        Write-Log "Error enumerating firewall rules: $($_.Exception.Message)" "ERROR"
    }
}

# Installed Software Enumeration
Function Enumerate-InstalledSoftware {
    Write-Log "Starting installed software enumeration..."
    try {
        $softwareList = Get-CimInstance -ClassName Win32_Product | Sort-Object Name
        foreach ($software in $softwareList) {
            $softwareDetails = @{
                "Name"    = $software.Name
                "Version" = $software.Version
                "Vendor"  = $software.Vendor
            }
            $outputBuilder.AppendLine(($softwareDetails | Format-Table | Out-String)) | Out-Null
        }
        Write-Log "Completed installed software enumeration."
    } catch {
        Write-Log "Error enumerating installed software: $($_.Exception.Message)" "ERROR"
    }
}

# Scheduled Tasks Enumeration
Function Enumerate-ScheduledTasks {
    Write-Log "Starting scheduled tasks enumeration..."
    try {
        $tasks = Get-ScheduledTask | Sort-Object TaskName
        foreach ($task in $tasks) {
            $taskActions = $task.Actions | ForEach-Object { $_.Execute } -join ", "
            $taskDetails = @{
                "TaskName"       = $task.TaskName
                "TaskPath"       = $task.TaskPath
                "Principal"      = $task.Principal.UserId
                "State"          = $task.State
                "ExecutablePath" = $taskActions
            }
            $outputBuilder.AppendLine(($taskDetails | Format-Table | Out-String)) | Out-Null
        }
        Write-Log "Completed scheduled tasks enumeration."
    } catch {
        Write-Log "Error enumerating scheduled tasks: $($_.Exception.Message)" "ERROR"
    }
}

# Service Enumeration
Function Enumerate-Services {
    Write-Log "Starting service enumeration..."
    try {
        $services = Get-Service | Sort-Object Name
        foreach ($service in $services) {
            $cimService = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($service.Name)'" -ErrorAction SilentlyContinue
            $serviceDetails = @{
                "Name"      = $service.Name
                "Status"    = $service.Status
                "StartType" = $cimService.StartMode
                "LogOnAs"   = $cimService.StartName
            }
            $outputBuilder.AppendLine(($serviceDetails | Format-Table | Out-String)) | Out-Null
        }
        Write-Log "Completed service enumeration."
    } catch {
        Write-Log "Error enumerating services: $($_.Exception.Message)" "ERROR"
    }
}

# File and Folder Permissions Enumeration
Function Enumerate-FilePermissions {
    Write-Log "Starting file and folder permissions enumeration..."
    try {
        foreach ($directory in $ScanDirectories) {
            if ($ExcludeDirectories -contains $directory) { continue }
            $items = Get-ChildItem -Path $directory -Recurse -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                try {
                    $acl = Get-Acl -Path $item.FullName -ErrorAction SilentlyContinue
                    if ($acl) {
                        $permissions = $acl.Access | Out-String
                        $outputBuilder.AppendLine("$($item.FullName): $permissions") | Out-Null
                    }
                } catch {
                    Write-Log "Failed to get ACL for $($item.FullName): $($_.Exception.Message)" "WARNING"
                }
            }
        }
        Write-Log "Completed file and folder permissions enumeration."
    } catch {
        Write-Log "Error enumerating file permissions: $($_.Exception.Message)" "ERROR"
    }
}

# Full Directory Listing with User-Defined Depth
Function Enumerate-DirectoryListing {
    Write-Log "Starting full directory listing (depth $DirectoryDepth)..."
    function Get-ChildItemsWithDepth {
        param (
            [string]$Path,
            [int]$CurrentDepth,
            [int]$MaxDepth
        )
        if ($CurrentDepth -gt $MaxDepth) { return }
        try {
            $items = Get-ChildItem -Path $Path -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                $indent = " " * ($CurrentDepth * 2)
                $line = "$indent$item"
                $outputBuilder.AppendLine($line) | Out-Null
                if ($item.PSIsContainer) {
                    Get-ChildItemsWithDepth -Path $item.FullName -CurrentDepth ($CurrentDepth + 1) -MaxDepth $MaxDepth
                }
            }
        } catch {
            Write-Log ("Failed to list directory {0}: {1}" -f $Path, $_.Exception.Message) "WARNING"
        }
    }

    foreach ($directory in $ScanDirectories) {
        Get-ChildItemsWithDepth -Path $directory -CurrentDepth 0 -MaxDepth $DirectoryDepth
    }
    Write-Log "Completed directory listing."
}

# SAM File Permissions Enumeration
Function Enumerate-SAMPermissions {
    Write-Log "Starting SAM file permissions enumeration..."
    try {
        $samPath = "C:\Windows\System32\config\SAM"
        $acl = Get-Acl -Path $samPath -ErrorAction Stop
        $outputBuilder.AppendLine("SAM File Permissions:") | Out-Null
        $outputBuilder.AppendLine(($acl.Access | Out-String)) | Out-Null
        Write-Log "Completed SAM file permissions enumeration."
    } catch {
        Write-Log "Error enumerating SAM file permissions: $($_.Exception.Message)" "ERROR"
    }
}

# Network Information Enumeration
Function Enumerate-NetworkInfo {
    Write-Log "Starting network information enumeration..."
    try {
        $arpTable = arp -a | Out-String
        $netstatOutput = netstat -an | Out-String
        $dnsInfo = Get-DnsClientServerAddress | Format-Table | Out-String
        $ipConfig = Get-NetIPConfiguration | Format-Table | Out-String
        
        $outputBuilder.AppendLine("ARP Table:") | Out-Null
        $outputBuilder.AppendLine($arpTable) | Out-Null
        $outputBuilder.AppendLine("Netstat Output:") | Out-Null
        $outputBuilder.AppendLine($netstatOutput) | Out-Null
        $outputBuilder.AppendLine("DNS Server Addresses:") | Out-Null
        $outputBuilder.AppendLine($dnsInfo) | Out-Null
        $outputBuilder.AppendLine("IP Configuration:") | Out-Null
        $outputBuilder.AppendLine($ipConfig) | Out-Null

        Write-Log "Completed network information enumeration."
    } catch {
        Write-Log "Error enumerating network information: $($_.Exception.Message)" "ERROR"
    }
}

# Execute Selected Sections
if ($Sections -contains "Firewall") { Enumerate-Firewall }
if ($Sections -contains "InstalledSoftware") { Enumerate-InstalledSoftware }
if ($Sections -contains "ScheduledTasks") { Enumerate-ScheduledTasks }
if ($Sections -contains "Services") { Enumerate-Services }
if ($Sections -contains "FilePermissions") { Enumerate-FilePermissions }
if ($Sections -contains "DirectoryListing") { Enumerate-DirectoryListing }
if ($Sections -contains "SAMPermissions") { Enumerate-SAMPermissions }
if ($Sections -contains "Network") { Enumerate-NetworkInfo }

# Save the output to the specified file
try {
    $outputBuilder.ToString() | Out-File -FilePath $OutputFilename -Encoding UTF8
    Write-Log "Enumeration completed. Results saved to $OutputFilename."
} catch {
    Write-Log "Failed to save output: $($_.Exception.Message)" "ERROR"
}
