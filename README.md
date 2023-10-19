# Functionality:


- Enumeration of World Exposed local file system shares.

- Enumeration of domain users and their local group membership.

- Detection of potential DLL hijacking vulnerabilities.

- Checking of User Account Control (UAC) settings.

- Identification of leftovers from standalone installations.

- Checking for weak passwords in local accounts.
   

# Usage

 - Open a PowerShell terminal with administrative privileges.

- Copy and paste the entire script into the PowerShell terminal.

- Press Enter to execute the script.

- The script will display the results of the security audit checks in the terminal.


![WDtest](https://github.com/0x5FE/WindowsAuditingTool/assets/65371336/6dcd5442-26cc-4278-b636-41521ae7827d)



# Problem-Solving Solutions:


***Execution Policy Restriction:*** If changing the execution policy does not resolve the issue, consider using the -ExecutionPolicy Bypass parameter when executing the script. For example: `PowerShell -ExecutionPolicy Bypass -File WDauditingtool.ps1.`



***Access Denied Errors:*** Ensure that the account you are using has the necessary administrative privileges. If the issue persists, try running the script with the ***"Run as Administrator" option.***



***WMI Errors:*** If restarting the WMI service does not resolve the issue, consider rebuilding the WMI repository. Open a PowerShell terminal with administrative privileges and run the following commands:

      Stop-Service winmgmt -Force  
      Get-WmiObject -Query "SELECT * FROM __Namespace WHERE Name='WMI'" | Remove-WmiObject
      winmgmt /resetrepository


After running these commands, restart the ***WMI service*** using the Restart-Service winmgmt command.



***Registry Key Errors:***  Verify that the required registry paths exist and have the appropriate permissions. If necessary, create missing registry keys or modify permissions using the ***Set-ItemProperty cmdlet or the Registry Editor.*** 



***Missing Dependencies:*** Install missing modules using the Install-Module cmdlet. For example: `Install-Module ModuleName.`



***False Positives:*** Manually verify the results to confirm their validity. Perform additional checks or investigations to determine if the reported issues are genuine security flaws.


# Note

Remember to always use the tool responsibly and ethically, ensuring that you have proper authorization and adhere to legal and ethical guidelines when performing security assessments or tests.

# Disclaimer: 

The creator are not responsible for any misuse or illegal activities performed using this script. This script is designed for testing purposes.
