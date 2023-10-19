$shares = Get-WmiObject -Class Win32_Share | Where-Object { $_.Type -eq 0 }

if ($shares) {
    Write-Host "World Exposed local file system shares:"
    $shares | ForEach-Object {
        Write-Host "Share Name: $($_.Name)"
        Write-Host "Path: $($_.Path)"
        Write-Host "Description: $($_.Description)"
        Write-Host "-----------------------------------"
    }
} else {
    Write-Host "No World Exposed local file system shares found."
}


$users = Get-WmiObject -Class Win32_UserAccount
$groups = Get-WmiObject -Class Win32_Group

if ($users -and $groups) {
    Write-Host "Domain users and their local group membership:"
    $users | ForEach-Object {
        $user = $_
        $userGroups = $groups | Where-Object { $_.SID -match $user.SID }
        if ($userGroups) {
            Write-Host "Username: $($user.Name)"
            Write-Host "Local Groups:"
            $userGroups | ForEach-Object {
                Write-Host "- $($_.Name)"
            }
            Write-Host "-----------------------------------"
        }
    }
} else {
    Write-Host "No domain users and groups found."
}


$systemPaths = @(
    "C:\Windows\System32",
    "C:\Windows\SysWOW64"
)

Write-Host "DLL Hijacking Vulnerabilities:"
$systemPaths | ForEach-Object {
    $path = $_
    $dlls = Get-ChildItem -Path $path -Filter "*.dll" -Recurse | Where-Object { $_.VersionInfo -ne $null }
    $dlls | ForEach-Object {
        $dll = $_
        $fileDescription = $dll.VersionInfo.FileDescription
        if ([string]::IsNullOrWhiteSpace($fileDescription)) {
            Write-Host "Potential DLL Hijacking: $($dll.FullName)"
        }
    }
}


$uacSettings = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA"

if ($uacSettings -and $uacSettings.EnableLUA -eq 1) {
    Write-Host "User Account Control (UAC) is enabled."
} else {
    Write-Host "User Account Control (UAC) is disabled or not configured."
}


$uninstallKeys = Get-ChildItem -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue

if ($uninstallKeys) {
    Write-Host "Leftovers from standalone installations:"
    $uninstallKeys | ForEach-Object {
        $uninstallKey = $_
        $displayName = $uninstallKey.GetValue("DisplayName")
        if ($displayName) {
            Write-Host "- $displayName"
        }
    }
} else {
    Write-Host "No leftovers from standalone installations found."
}


$localAccounts = Get-LocalUser | Where-Object { $_.Name -ne "Administrator" -and $_.Name -ne "Guest" }

if ($localAccounts) {
    Write-Host "Local accounts with weak passwords:"
    $localAccounts | ForEach-Object {
        $account = $_
        $passwordInfo = $account | Get-LocalUserPasswordInfo
        if ($passwordInfo.PasswordRequired -and $passwordInfo.PasswordLastSet -lt (Get-Date).AddDays(-90)) {
            Write-Host "- $($account.Name)"
        }
    }
} else {
    Write-Host "No local accounts found."
}


$software = Get-WmiObject -Class Win32_Product

if ($software) {
    Write-Host "Outdated software versions:"
    $software | ForEach-Object {
        $product = $_
        $name = $product.Name
        $version = $product.Version
        $installDate = $product.InstallDate
        if ($installDate -lt (Get-Date).AddYears(-1)) {
            Write-Host "Name: $name"
            Write-Host "Version: $version"
            Write-Host "Installed Date: $installDate"
            Write-Host "-----------------------------------"
        }
    }
} else {
    Write-Host "No software versions found."
}
