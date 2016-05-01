## ABOUT ##
Git: unix-user-group-auditor
Purpose: To analyse local group membership of users on a unix server. Useful when performing an audit work and confined to a windows PC
Required: /etc/group and /etc/passwd file
Author: Sam Granger

## EXECUTION POLICY ##
To run open powershell as an Administrator and run 'Set-ExecutionPolicy Bypass'

## USAGE ##
Usage  : unixUserGroupsAudit.ps1
           -passwdFile file-name-of-passwd-file
           -groupFile file-name-of-group-file
           -serverName name-of-server-files-came-from
           [-outputPath output-path]

Example: unixUserGroupsAudit.ps1 -passwdFile ".\passwd" -groupFile ".\groupFile" -serverName "server123"