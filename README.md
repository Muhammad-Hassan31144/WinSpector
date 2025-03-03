
# WinSpector: Enhanced System Enumeration Script,

**WinSpector** is a PowerShell script designed for comprehensive system enumeration on Windows 10 and above.,
It gathers detailed information from your system to help with security assessments, red teaming, or system administration tasks.,

## Features,

- **Firewall Enumeration:** Lists firewall rules with details such as direction, protocol, and remote/local addresses.,
- **Installed Software:** Retrieves installed software information using modern cmdlets.,
- **Scheduled Tasks:** Enumerates scheduled tasks along with execution details.,
- **Service Enumeration:** Lists services including status, startup type, and logon account.,
- **File and Folder Permissions:** Recursively enumerates permissions across specified directories.,
- **Full Directory Listing:** Provides a tree-like directory listing up to a user-defined depth.,
- **SAM File Permissions:** Retrieves Access Control List (ACL) details for the SAM file.,
- **Network Information:** Gathers ARP, netstat, DNS server, and IP configuration details.,

## Prerequisites,

- **Operating System:** Windows 10 or above.,
- **PowerShell Version:** PowerShell 5.1 or later.,
- **Privileges:** Must be run as Administrator.,

## Usage,

Run the script using PowerShell with a bypass for the execution policy.,

### Display Output in Console,
```cmd
powershell -ExecutionPolicy Bypass -File .\\WinSpector.ps1,
```

### Write Output to a File,
```cmd
powershell -ExecutionPolicy Bypass -File .\\WinSpector.ps1 -OutputFilename \"C:\\Temp\\SystemReport.txt\",
```

### Advanced Options,

- **-ExcludeDirectories:** Directories to exclude from file and folder permissions enumeration.,
- **-ScanDirectories:** Directories to scan. *(Default: C:\\)*,
- **-DirectoryDepth:** Maximum recursion depth for directory listing. *(Default: 3)*,
- **-Sections:** Enable or disable specific sections. Options include:,
  - `Firewall`,
  - `InstalledSoftware`,
  - `ScheduledTasks`,
  - `Services`,
  - `FilePermissions`,
  - `DirectoryListing`,
  - `SAMPermissions`,
  - `Network`,
",
### Example,
```powershell
.\\WinSpector.ps1 -OutputFilename \"C:\\Temp\\SystemReport.txt\" -ExcludeDirectories @(\"C:\\Windows\", \"C:\\Program Files\") -ScanDirectories @(\"C:\\Users\") -DirectoryDepth 2 -Sections @(\"FilePermissions\", \"DirectoryListing\", \"Network\"),
```

### Execution Flow,
1. **Firewall Enumeration:** Retrieves and formats firewall rule details.,
2. **Installed Software:** Enumerates software installed on the system.,
3. **Scheduled Tasks:** Collects details about scheduled tasks.,
4. **Service Enumeration:** Gathers information on system services.,
5. **File and Folder Permissions:** Recursively scans specified directories for permission details.,
6. **Full Directory Listing:** Outputs a directory tree up to the defined depth.,
7. **SAM File Permissions:** Retrieves ACLs for the SAM file.,
8. **Network Information:** Outputs network configuration details, including ARP, netstat, DNS, and IP settings.,

### Disclaimer,
This tool is provided for educational and authorized security testing purposes only.,
Use it responsibly and ensure you have appropriate permissions before running this script on any system.

