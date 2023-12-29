# Import required modules
Import-Module ActiveDirectory
Import-Module CIM

# Define parameters
$systemPaths = @("C:\Windows\System32", "C:\Windows\SysWOW64")
$daysSinceLastPasswordSet = 90
$yearsSinceLastInstall = 1

# Get world-exposed shares
function Get-WorldExposedShares {
    $shares = Get-WmiObject -Class Win32_Share | Where-Object { $_.Type -eq 0 }
    return $shares
}

# Get domain users and their local group membership
function Get-DomainUsersAndGroups {
    $users = Get-WmiObject -Class Win32_UserAccount
    $groups = Get-WmiObject -Class Win32_Group
    $userGroups = $users | Where-Object { $_.SID -match $groups.SID }
    return $userGroups
}

# Check for DLL hijacking vulnerabilities
function Check-DLLHijacking {
    $path = $args[0]
    $dlls = Get-ChildItem -Path $path -Filter "*.dll" -Recurse | Where-Object { $_.VersionInfo -ne $null }
    foreach ($dll in $dlls) {
        $fileDescription = $dll.VersionInfo.FileDescription
        if ([string]::IsNullOrWhiteSpace($fileDescription)) {
            Write-Host "Potential DLL Hijacking: $($dll.FullName)"
        }
    }
}

# Get UAC settings
function Get-UACSettings {
    $uacSettings = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"
    return $uacSettings
}

# Get leftovers from standalone installations
function Get-LeftoversFromStandaloneInstallations {
    $uninstallKeys = Get-ChildItem -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue
    foreach ($uninstallKey in $uninstallKeys) {
        $displayName = $uninstallKey.GetValue("DisplayName")
        if ($displayName) {
            Write-Host "- $displayName"
        }
    }
}

# Get local accounts with weak passwords
function Get-LocalAccountsWithWeakPasswords {
    $accounts = Get-LocalUser | Where-Object { $_.Name -ne "Administrator" -and $_.Name -ne "Guest" }
    foreach ($account in $accounts) {
        $passwordInfo = $account | Get-LocalUserPasswordInfo
        if ($passwordInfo.PasswordRequired -and $passwordInfo.PasswordLastSet -lt (Get-Date).AddDays(-$daysSinceLastPasswordSet)) {
            Write-Host "- $($account.Name)"
        }
    }
}

# Get outdated software versions
function Get-OutdatedSoftwareVersions {
    $software = Get-WmiObject -Class Win32_Product
    foreach ($product in $software) {
        $name = $product.Name
        $version = $product.Version
        $installDate = $product.InstallDate
        if ($installDate -lt (Get-Date).AddYears(-$yearsSinceLastInstall)) {
            Write-Host "Name: $name"
            Write-Host "Version: $version"
            Write-Host "Installed Date: $installDate"
            Write-Host "-----------------------------------"
        }
    }
}

# Get world-exposed shares
$shares = Get-WorldExposedShares

# Get domain users and their local group membership
$userGroups = Get-DomainUsersAndGroups

# Check for DLL hijacking vulnerabilities
foreach ($path in $systemPaths) {
    Check-DLLHijacking $path
}

# Get UAC settings
$uacSettings = Get-UACSettings

# Get leftovers from standalone installations
Get-LeftoversFromStandaloneInstallations

# Get local accounts with weak passwords
Get-LocalAccountsWithWeakPasswords

# Get outdated software versions
Get-OutdatedSoftwareVersions
