<#
    .SYNOPSIS
    This script can be used to automate disabling accounts that have not logged into AD in XX number of days.

    .DESCRIPTION
    For security purposes, accounts that are not being utilised should be disabled. This script will check a list of OUs that need to be monitored and disable them 
    if they have passed the desired threshold. This script will disable the user, move it to the desired OU after disabling and update the user's description stating why
    it was disabled and when. The original user description is preserved at the end of the description. This script will not disable accounts that have been recently created 
    until they pass the threshold. 

    The default threshold is set to 90 days. Two logs are created from this script in:
    - DisabledUsersLogs : Contains CSV reports showing which users were disabled and basic info about the account
    - RunLogs : Provides a run log that can be useful for troubleshooting and tracking if the script is running as expected.

    It's recommended to run in -whatif mode when testing in your environment to ensure the results are what you expect before fully implementing. 

    .PARAMETER OUListPath
    Provide a path to a .txt (e.g. C:\Temp\MonitoredOUs.txt) file with a list of what OUs you want the script to check/monitor. Each OU should be on a new line and have it's full path (e.g. OU=GeneralUsers,OU=UserGroup-01,DC=Testnet,DC=com)

    .PARAMETER DisabledUsersOU
    Provide the OU where disabled users should be moved to. (e.g. OU=DisabledUsers,DC=Testnet,DC=com)

    .PARAMETER UnusedDays
    Provide the maximum age in days for users before they are disabled. If this is not set, the script will default to 90 days.

    .EXAMPLE
    C:\StaleUserSweeper.ps1 -OUListPath "C:\Scripts\DisableUsers\MonitoredOUs.txt" -DisabledUserOU "OU=DisabledUsers,DC=Testnet,DC=com"

    The above example will look through the list of OUs in the MonitoredOUs.txt text file and check whether any users have not logged in within the default 90-day period. If they have, they will be disabled and moved to the DisabledUsers OU. 
    Reports will be generated in the directory the script is run from C:\Scripts\DisableUsers\DisabledUsersLogs and C:\Scripts\DisableUsers\RunLogs

    .EXAMPLE
    C:\Scripts\StaleUserSweeper.ps1 -OUListPath "C:\Scripts\DisableUsers\MonitoredOUs.txt" -DisabledUsersOU "OU=DisabledUsers,DC=Testnet,DC=com" -UnusedDays 60

    The above example will iterate through the list of OUs in the MonitoredOUs.txt file and check whether any users have not logged in within 60 days.

    .NOTES
    Created by: KaijuLogic
    Created Date: 05.2021
    Last Modified Date: 23.11.2025
    Last Modified By: KaijuLogic

    LATEST MODIFICATIONS:
        23.11.2025
                Corrected some spelling
                Fixed user filter
                Cleaned up some notes
                
        20.11.2025: 
                Added splatting to Find-InactiveUsers and userprops variable to try and make things easier to read and edit
                added parameters to Set-DisabledUsers and allowed to take in data from a pipe for easier to reading and portability
                Added OU path validation
                Updating script descriptions and notes
                Implemented better try-catches for getting oulist contents and testing ou path. Implemented 'throws' to better fit powershell standards

    TO-DO: 
        DONE: improve folder creation
        DONE: Verify the provided OU path exists 
        DONE: Update Get-Help section to be functional with correct information
        DONE: Update log creation to newer version so it matches other scripts. - waiting to test
        Allow multiple destinations to be given for disabled users. Something like a CSV that specifies both which OUs to monitor and where users from those OUs should be sent when disabled.  


    .DISCLAIMER:
    This script may be used for legal purposes only. The user assumes full responsibility for any actions performed using this script. 
    The author accepts no liability for any damage caused by this script.        
#>
####################### SCRIPT PARAMETERS #######################
[CmdletBinding(SupportsShouldProcess)]
Param(
	[Parameter(Mandatory=$True)]
    [ValidateScript({
        if (Test-Path $_ -PathType leaf) {
            return $True
        } else {
            Throw "$_ not found, please verify the path to your list is correct."
        }
    })]
	[String]$OUListPath,

    [Parameter(Mandatory=$True)]
	[String]$DisabledUsersOU,

    [Parameter(Mandatory=$false)]
	[Int]$UnusedDays = 90
)
################################## Import Modules #################################
<
try{
	Import-Module ActiveDirectory
}
catch{
	Throw "Failed to import ActiveDirectory module, are you sure this is running on a system with AD or RSAT tools installed."
}

#################################### SET COMMON VARIABLES ###################################
$CurrentDate = Get-Date
$CurrentPath = split-path -Parent $PSCommandPath

# Establish our paths for log creation and results
$LogDateDir = $CurrentDate.ToString("yyyy-MM")
$LogFileNameTime = $CurrentDate.ToString("yyyy-MM-dd_HH.mm.ss")

$DisabledLogDir = Join-Path -Path $CurrentPath -ChildPath "DisabledUsersLogs\Reports\$LogDateDir"
$RunLogDir = Join-Path -Path $CurrentPath -ChildPath "DisabledUsersLogs\RunLogs\$LogDateDir"

$DisabledLogFile = Join-Path -Path $DisabledLogDir -ChildPath "DisabledAccounts_$LogFileNameTime.csv"
$RunLogOutput = Join-Path -Path $RunLogDir -ChildPath "DisableAccounts_RunLog_$LogFileNameTime.txt"

#Used to tracks how long the script took to process
$sw = [Diagnostics.Stopwatch]::StartNew()
#################################### FUNCTIONS #######################################
#Function to create folders and path if they do not already exist to allow for logs to be created. 
Function Set-NewFolder {
    param(
        [Parameter(Mandatory=$true)]
        [string[]] $FolderPaths
    )
    ##Tests for and creates necessary folders and files for the script to run and log appropriatel
	foreach ($Path in $FolderPaths){
	    if (!(Test-Path $Path)){
	        Write-Verbose "$Path does not exist, creating path"
	        Try{
	            New-Item -Path $Path -ItemType "directory" | out-null
	        }
	        Catch{
	            Throw "Error creating path: $Path. Error provided: $($_.ErrorDetails.Message)"
	        }
        }
	}
}

Function Write-ScriptLog{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [ValidateSet("Info","WARN","ERROR","FATAL","DEBUG")]
        [string]$level = "INFO",

        [Parameter(Mandatory=$true)]
        [string]$Message,

        [Parameter(Mandatory=$true)]
        [string]$logfile
    )

    $Stamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

    $Line = "$Stamp | $Level | $Message"
    
    #To make our cli output look ~pretty~
    $ColorDitcionary = @{"INFO" = "Cyan"; "WARN" = "Yellow"; "ERROR" = "Red"}
    Write-Host $Line -ForegroundColor $ColorDitcionary[$Level]

    Add-content $logfile -Value $Line -Force
}

#Used to gather users that have not logged in in the provided range. 
Function Find-InactiveUsers{
    Param(
        [Parameter(Mandatory=$true)]
        [String[]]$OUlistContent,

        [Parameter(Mandatory=$true)]
	    [int]$MaxAge
    )
    Write-Verbose "Attempting to collect inactive users"
    foreach ($OU in $OUlistContent){
        write-verbose "Currently checking $OU"
        $UserSearchParams = @{
            AccountInactive = $True
            TimeSpan = "$MaxAge.00:00:00"
            SearchBase = $OU
            UsersOnly = $True
        }

        $UserProps = "Name", "SamAccountName", "DisplayName", "DistinguishedName", "WhenCreated", "LastLogonDate", "Description"

        Try{
            #Filters out any accounts that were created within the max age limit, this makes sure
            #that any users that were recently created aren't disabled until their account reaches the threshold.
            Search-ADAccount @UserSearchParams |
                Get-ADuser -properties $UserProps |
                Where-Object {$_.WhenCreated -lt (Get-Date).AddDays(-$UnusedDays)} |
                Select-Object $UserProps
        }
        Catch{          
            Write-ScriptLog -level ERROR -Message "Failed to get user list. ERROR: $_" -logfile $RunLogOutput
            Throw "Failed to get user list. ERROR: $($_.ErrorDetails.Message)"
        }
    }
}

#Disables accounts, adds information for when they were disabled, and moves them to the appropriate OU
Function Set-DisabledUsers{
    Param(
        [Parameter(ValueFromPipeline=$true)]
        [Object[]]$User,

        [Parameter(Mandatory=$true)]
	    [String]$DestOU
    )
    Process {
        $UserName = $User.DisplayName
        #Disable account
        Write-Verbose "Attempting to disable $UserName"
        If ($PSCmdlet.ShouldProcess($UserName)){
            Try{
                Disable-ADAccount -Identity $User.DistinguishedName
                Write-ScriptLog -level INFO -message "$UserName Account Disabled" -logfile $RunLogOutput
            }
            Catch{
                Write-ScriptLog -level WARN -message "Failed to disable the user $UserName. ERROR: $($_.ErrorDetails.Message)" -logfile $RunLogOutput
                Throw  "Failed to disable the user $UserName"
            }

            #Update user description with note and date when it was disabled
            Write-Verbose "Attempting to set description for: $UserName"
            Try{
                $new_desc = "Auto-Disabled Due to Inactivity: " + $CurrentDate + " :" + "ORIGINALDESC:" + $User.Description 
                Set-ADUser $User.DistinguishedName -Description $new_desc
                Write-ScriptLog -level INFO -message "$UserName Description Updated" -logfile $RunLogOutput
            }
            Catch{
                Write-ScriptLog -level WARN -message "Failed to set description for $UserName. ERROR: $($_.ErrorDetails.Message)" -logfile $RunLogOutput
                Throw  "Failed to set description for $UserName" 
            }

            #Move disabled user to the disabled users OU 
            Write-Verbose "Attempting to move: $UserName to $DisabledUsersOU"
            Try{
                Move-ADObject -Identity $User.DistinguishedName -TargetPath $DisabledUsersOU
                Write-ScriptLog -level INFO -message "$UserName moved to $DisabledUsersOU" -logfile $RunLogOutput
            }
            Catch{
                Write-ScriptLog -level WARN -message "Failed to move $UserName. ERROR: $($_.ErrorDetails.Message)" -logfile $RunLogOutput 
                Throw  "Failed to mov $UserName" 
            }
        }
        # Get Users and output to log file
        Write-Verbose "Attempting to create CSV report of disabled accounts"
        Try{
            #Tried creating a com object to make the code easier to read
            $ReportProps = [PSCustomObject]@{
                Name = $User.Name
                SamAccountName = $User.SamAccountName
                DistinguishedName = $User.DistinguishedName
                LastLogonDate = $User.LastLogonDate
                DateDisabled = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            }
            $ReportProps | Export-Csv $DisabledLogFile -append -NoTypeInformation
        }
        Catch{
            Write-ScriptLog -level WARN -message "Failed to create log file of disbled users. ERROR: $($_.ErrorDetails.Message)" -logfile $RunLogOutput 
            Throw "Failed to create log file of disbled users."
        }
    }
}


#################################### EXECUTION #####################################
Set-NewFolder -FolderPath $DisabledLogDir,$RunLogDir

Write-ScriptLog -level INFO -message "Auto Disable Stale Accounts Max age setting $UnusedDays Days" -logfile $RunLogOutput
Write-ScriptLog -level INFO -message "RUN BY $ENV:UserName ON $ENV:ComputerName" -logfile $RunLogOutput

try{
    Write-Verbose "Attempting to open $OUlist"
    #Reads the OU list and removes any blank lines if they exist
    $OUlist = Get-Content -path $OUListPath | ? {$_.trim() -ne "" }
}
catch{
    Write-ScriptLog -level ERROR -message "Something went wrong reading from $OUlist. ERROR: $($_.ErrorDetails.Message)" -logfile $RunLogOutput
    Throw "Something went wrong reading from $OUlist."
}

try{
    Write-Verbose "Checking if $DisabledUsersOU exists"
    Get-ADOrganizationalUnit -Identity $DisabledUsersOU | Out-null
}
catch{
    Write-ScriptLog -level ERROR -message "Could not find destination OU $DisabledUsersOU. ERROR: $($_.ErrorDetails.Message)" -logfile $RunLogOutput
    Throw "Could not find destination OU $DisabledUsersOU."
}

$InactiveList = Find-InactiveUsers -OUlistContent $OUlist -MaxAge $UnusedDays

If ($InactiveList){
    Write-Verbose "Attempting to disable collected usernames."
    $InactiveList | Set-DisabledUsers -DestOU $DisabledUsersOU
}
else{
    Write-ScriptLog -level INFO -message "No inactive accounts were found on this run" -logfile $RunLogOutput
}

$sw.stop()

Write-ScriptLog -level INFO -message  "ADMX and GPO backup script ran for: $($sw.elapsed)" -logfile $RunLogOutput