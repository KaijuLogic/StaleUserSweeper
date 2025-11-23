# StaleUserSweeper
My way of solving a classic problem: disabling users that have not logged into the domain in a while. This script is written for on-premises Windows active directory domains. 

## DESCRIPTION
For security purposes accounts that are not being utilised should be disabled. This script will check a list of OUs that need to be monitored and disable them if they have passed the desired threshold. This script will disabled the user, move it to the desired OU after disabling and update the users description stating why it was disabled and when. The original user description is preservered at the end of the description. This script will not disable accounts that have been recently created until they pass the threshold. 

Reports will be generated in the directory the script is run from C:\Current\Path\DisabledUsersLogs\Reports and C:\Current\Path\DisabledUsersLogs\RunLogs\

**It's recommended to run in -whatif mode when testing in your environment to ensure the results are what you expect before fully implementing.**

## FEATURES
- Logs created for evidence that certain controls or requirements are being met
- Runlog for troubleshooting and record keeping
- CSV report of users that were disabled for each run. Collects the following info: 
        Name
        Username
        AD OU the user belonged to
        the users last login date
- Updates the users description stating why they were disabled and when.
- All sub OUs will be scanned as well, so if you don't want every user, in every sub OU checked then be specific with your OU list.
- Functions with "Get-Help"
- Supports "-whatif" runs

## Pre-Requisits
Not much, this either needs to be run on a server with Active Directory installed, or system with RSAT tools. 
You also need the appropriate Active Directory permissions to modify users. 
RSAT: https://www.microsoft.com/en-us/download/details.aspx?id=45520 

## Usage
- Create a text file with a list of OUs you want this script to check
    - Each OU should be on a new line for simplicity
    - An example file is included with this repo
- Download or clone this repo 
- Run the script 

### Example 1
```PowerShell
StaleUserSweeper.ps1 -OUListPath "C:\Scripts\DisableUsers\MonitoredOUs.txt" -DisabledUserOU "OU=DisabledUsers,DC=Testnet,DC=com"
```

This will look through the list of OUs in the MonitoredOUs.txt text file and see if any users have not logged in within the default setting of 90 days. If they have they will be disabled and moved to the DisabledUsers OU. 


### Example 2
```PowerShell
StaleUserSweeper.ps1 -OUListPath "C:\Scripts\DisableUsers\MonitoredOUs.txt" -DisabledUsersOU "OU=DisabledUsers,DC=Testnet,DC=com" -UnusedDays 60
```

This will look through the list of OUs in the MonitoredOUs.txt text file and see if any users have not logged in within 60 days.

## Additional Notes
Want to know more about this script and future improvements? Check out my blog post about it on https://www.kaijulogic.com/ 
Check out my blog if you want to be in the loop on future projects, career stories and troubleshooting tips. https://www.kaijulogic.com/ 
