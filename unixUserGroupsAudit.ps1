# Purpose: To analyise local group membership of users on a unix server. Useful when performing an audit work and confined to a windows PC
# Required: /etc/group and /etc/passwd file
# Author: Sam Granger

##############
##	 INIT 	##
##############

Param(
  [string]$passwdFile,
  [string]$groupFile,
  [string]$serverName,
  [string]$outputPath
)

Set-StrictMode -version 2

$date 		= Get-Date -format yyyy-MM-dd-HHmmss
$scriptname = $MyInvocation.MyCommand.Name
$username   = $env:username
$VERSION	= "2016.05.01"

##################
## 	FUNCTIONS	##
##################

function usage {
	Write-Host -foregroundcolor "yellow" "Usage  : $scriptname"
	Write-Host -foregroundcolor "yellow" "           -passwdFile file-name-of-passwd-file"
	Write-Host -foregroundcolor "yellow" "           -groupFile file-name-of-group-file"
	Write-Host -foregroundcolor "yellow" "           -serverName name-of-server-files-came-from"
	Write-Host -foregroundcolor "yellow" "           [-outputPath output-path]"
	Write-Host
	Write-Host -foregroundcolor "yellow" "Example: $scriptname -passwdFile "".\passwd"" -groupFile "".\groupFile"" -serverName ""server123"" ";
}

function setWindowTitle {
	param ([string]$title)
	((Get-Host).UI.RawUI).WindowTitle = $title
}

function readGroupFile {
	param($groupFile)
	# Create Group File Object
	$groupObjects = @()
	ForEach ($group in $groupFile) {
		#Split line on ":"
		$splitGroup = $group -split(":")
		
		#Create new group object
		$groupObject = New-Object -TypeName PSObject
		$groupObject | Add-Member -MemberType NoteProperty -Name group_name -Value $splitGroup[0]
		$groupObject | Add-Member -MemberType NoteProperty -Name password -Value $splitGroup[1]
		$groupObject | Add-Member -MemberType NoteProperty -Name group_id -Value $($splitGroup[2] -as [long])
		$groupObject | Add-Member -MemberType NoteProperty -Name group_list -Value $splitGroup[3]	
		$groupObjects += $groupObject
	}
	return $groupObjects
}

function readPasswdFile {
	param($passwdFile)
	# Create Password Object from passwd file
	$passwdObjects = @()
	ForEach ($passwd in $passwdFile) {
		#Split line on ":"
		$splitpasswd = $passwd -split(":")
		
		#Create new group object
		$passwdObject = New-Object -TypeName PSObject
		$passwdObject | Add-Member -MemberType NoteProperty -Name username -Value $splitpasswd[0]
		$passwdObject | Add-Member -MemberType NoteProperty -Name password -Value $splitpasswd[1]
		$passwdObject | Add-Member -MemberType NoteProperty -Name user_id -Value $($splitpasswd[2] -as [long])
		$passwdObject | Add-Member -MemberType NoteProperty -Name group_id -Value $($splitpasswd[3] -as [long])
		$passwdObject | Add-Member -MemberType NoteProperty -Name user_id_info -Value $splitpasswd[4]	
		$passwdObject | Add-Member -MemberType NoteProperty -Name home_dir -Value $splitpasswd[5]	
		$passwdObject | Add-Member -MemberType NoteProperty -Name shell -Value $splitpasswd[6]	
		$passwdObjects += $passwdObject		
		}
	return $passwdObjects
}

function findPrimaryGroup {
	param(
		[long]$user_groupID,
		$groupObject
		)
	ForEach ($objX in $groupObject) {
		$groupName = $objX.group_name
		$groupID = $objX.group_id
		if ($groupID -eq $user_groupID){
			return $groupName
		}
	}
	return "Unknown Primary Group"	#Should never reach here, however sometime a GID maybe '4294967294' due to NFS Shares (or something)
}

function findSecondaryGroup {
	param(
		[string]$userName,
		[long]$userID,
		$groupObject
		)
	$secondaryGroup = @()
	
	ForEach ($objY in $groupObject) {
		$groupName = $objY.group_name
		$groupList = "" #Clear group list
		$groupList = $objY.group_list
		if (!([string]::IsNullOrEmpty($groupList))) { #Check if their are groups associated to that group file
			#Split the string into an object to make searching easier
			$splitGroupList = $groupList -split(",")
			#Match either userName or userID (Use regex for complete match)
			$match = $splitGroupList -match "^$($userName)$|^$($userID.toString())$"
			if ($match) {
				$secondaryGroup += $groupName
			}
		}
	}
	#Convert varibale into string
	$secondaryGroupLine = $secondaryGroup -join(",")
	
	#Return secondaryGroups as string
	return $secondaryGroupLine
}

 
##################
## 	   MAIN		##
##################

$start = Get-Date

# Test all parameters required have been provided
if (!($passwdFile -and $groupFile)) {
	usage; exit 1
	}

if(!(Test-Path -path "$passwdFile")) {
	Write-Host -foregroundcolor "red" "[!] Could not access path $passwdFile"
	exit 1
}

if(!(Test-Path -path "$groupFile")) {
	Write-Host -foregroundcolor "red" "[!] Could not access path $groupFile"
	exit 1
}

if ([string]::IsNullOrEmpty($serverName)) {
	Write-Host -foregroundcolor "red" "[!] Please give your server a name"
	exit 1
}

if (!($outputPath)) {
	$outputPath = "."
	}

if(!(Test-Path -path "$outputPath")) {
	Write-Host -foregroundcolor "red" "[!] Could not access path $outputPath"
	exit 1
}

#Set up output files
$outputName = "UserGroupsAudit_$serverName"
$outputLOG 	= "$outputPath\$outputName - LOG - $date.txt"
$exportCSV = "$outputPath\$outputName - $date.csv"

#Start Logging
$ErrorActionPreference="SilentlyContinue"
Stop-Transcript | out-null
$ErrorActionPreference = "Continue"
Start-Transcript -path $outputLOG -append

#Starting messages
Write-Host "[*] Running script '$scriptName'"
Write-Host "[*] Script version $VERSION"
Write-Host "[*] Running as $username"
setWindowTitle -title "Analysing user and groups for $serverName"

Write-Host ""

#Read password and group file
$groupRead = Get-Content $groupFile
$groupCount = $groupRead.count

$passwdRead = Get-Content $passwdFile
$passwdCount = $passwdRead.count

#Convert files into objects
Write-Host "[*] Importing group file, '$groupCount' lines"
$group = readGroupFile -groupFile $groupRead
Write-Host "`t[!] Finished importing group file"

Write-Host "[*] Importing passwd file '$passwdCount' lines"
$passwd = readPasswdFile -passwdFile $passwdRead
Write-Host "`t[!] Finished importing passwd file"

#Find primary and secondary group membership
$passwdMembership = @()
$i = 1

Write-Host "[*] Analysing user membership"
ForEach ($user in $passwd) {
	$userName = $user.userName
	$userID = $user.user_id
	$groupID = $user.group_id
	
	$percent = ($i/$passwdCount)*10
	$percentClean = "{0:N2}" -f $percent
	Write-Progress -activity "Looking at membership for '$userName'" -status "$percentClean% Complete:" -percentcomplete $percent;
	
	#Search for primary group
	$primaryGroup = findPrimaryGroup -user_groupID $groupID -groupObject $group
	
	#Search for secondary group(s)
	$secondaryGroup = findSecondaryGroup -userName $userName -userID $userID -groupObject $group

	$user| Add-Member -MemberType NoteProperty -Name primary_group -Value $primaryGroup
	$user| Add-Member -MemberType NoteProperty -Name secondary_group -Value $secondaryGroup

	$passwdMembership += $user
	
	$i++
}

Write-Host "[*] Exporting file to '$exportCSV'"
#Export to CSV
$passwdMembership | Select username, password, user_id, group_id, user_id_info, home_dir, shell, primary_group, secondary_group | Sort user_id | Export-Csv -NoTypeInformation -Path $exportCSV

#Finish script
$finish = Get-Date
Write-Host ""
Write-Host "[*] Done."
Write-Host "[*] Duration: $((new-timespan $start $finish).TotalSeconds) seconds; $finish"

setWindowTitle -title "Analysis for $serverName complete. DONE."

#Stop logging
Stop-Transcript