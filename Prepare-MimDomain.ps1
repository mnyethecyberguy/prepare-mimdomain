<#
    .SYNOPSIS
    Script to create service accounts, groups, and set SPNs in AD for MIM to prepare for installation.

    .DESCRIPTION
    Script to create service accounts, groups, and set SPNs in AD for MIM to prepare for installation.

    .EXAMPLE

    .NOTES
    #####################################################################################
    # Author: Michael Nye - https://github.com/mnyethecyberguy                          #
    # Project: Prepare-MimDomain - https://github.com/mnyethecyberguy/prepare-mimdomain #
    # Module Dependencies: ActiveDirectory                                              #
    # Permission level: Domain Admin                                                    #
    # Powershell v5 or greater                                                          #
    #####################################################################################
#>
# -------------------------------------------------------------------------

# ------------------- IMPORT AD MODULE ------------------------------------
Import-Module ActiveDirectory

# ------------------- BEGIN USER DEFINED VARIABLES ------------------------
$SCRIPTNAME    	= "Prepare-MimDomain"
$SCRIPTVERSION 	= "1.0"

# Set domain FQDN, domain short name, and MIM Service Server short name for use in setting SPNs
$strDomainFQDN  = "mydomain.fqdn"
$strDomainShort = "mydomain"
$strMimSrvName  = "mimserviceservername"

# ------------------- END OF USER DEFINED VARIABLES -----------------------

# ------------------- BEGIN MAIN SCRIPT VARIABLES -------------------------
# Establish variable with date/time of script start
$Scriptstart    = Get-Date -Format G

$strCurrDir 	= split-path $MyInvocation.MyCommand.Path
$strLogFolder 	= "$SCRIPTNAME -{0} {1}" -f ($_.name -replace ", ","-"),($Scriptstart -replace ":","-" -replace "/","-")
$strLogPath 	= "$strCurrDir\logs"

# Create log folder for run and logfile name
New-Item -Path $strLogPath -name $strLogFolder -itemtype "directory" -Force > $NULL
$LOGFILE 		= "$strLogPath\$strLogFolder\$SCRIPTNAME.log"

# error action preference must be set to stop for script to function properly, default setting is continue
$ErrorActionPreference = 'stop'

# ------------------- END MAIN SCRIPT VARIABLES ---------------------------

# ------------------- DEFINE FUNCTIONS - DO NOT MODIFY --------------------

Function Writelog ($LogText)
{
	$date = Get-Date -format G
	
    write-host "$date $LogText"
	write-host ""
	
    "$date $LogText" >> $LOGFILE
	"" >> $LOGFILE
}

Function BeginScript () {
    Writelog "-------------------------------------------------------------------------------------"
    Writelog "**** BEGIN SCRIPT AT $Scriptstart ****"
    Writelog "**** Script Name:     $SCRIPTNAME"
    Writelog "**** Script Version:  $SCRIPTVERSION"
    Writelog "-------------------------------------------------------------------------------------"

    $error.clear()
}

Function EndScript () {
	Writelog "-------------------------------------------------------------------------------------"
    Writelog "**** SCRIPT RESULTS ****"
    Writelog "-------------------------------------------------------------------------------------"

    $Scriptfinish = Get-Date -Format G
	$span = New-TimeSpan $Scriptstart $Scriptfinish
	
  	Writelog "-------------------------------------------------------------------------------------"
  	Writelog "**** $SCRIPTNAME script COMPLETED at $Scriptfinish ****"
	Writelog $("**** Total Runtime: {0:00} hours, {1:00} minutes, and {2:00} seconds ****" -f $span.Hours,$span.Minutes,$span.Seconds)
	Writelog "-------------------------------------------------------------------------------------"
}

# ------------------- END OF FUNCTION DEFINITIONS -------------------------


# ------------------- SCRIPT MAIN - DO NOT MODIFY -------------------------
$inputpw    = Read-Host -Prompt 'Enter password for service accounts:'
$sp         = ConvertTo-SecureString $inputpw -asplaintext -force

BeginScript

# ------------------- CREATE SERVICE ACCOUNTS for MIM ---------------------
New-ADUser -SamAccountName MIMINSTALL -name MIMINSTALL
Set-ADAccountPassword -identity MIMINSTALL -NewPassword $sp
Set-ADUser -identity MIMINSTALL -Enabled 1 -PasswordNeverExpires 1

New-ADUser -SamAccountName MIMMA -name MIMMA
Set-ADAccountPassword -identity MIMMA -NewPassword $sp
Set-ADUser -identity MIMMA -Enabled 1 -PasswordNeverExpires 1

New-ADUser -SamAccountName MIMSync -name MIMSync
Set-ADAccountPassword -identity MIMSync -NewPassword $sp
Set-ADUser -identity MIMSync -Enabled 1 -PasswordNeverExpires 1

New-ADUser -SamAccountName MIMService -name MIMService
Set-ADAccountPassword -identity MIMService -NewPassword $sp
Set-ADUser -identity MIMService -Enabled 1 -PasswordNeverExpires 1

New-ADUser -SamAccountName MIMSSPR -name MIMSSPR
Set-ADAccountPassword -identity MIMSSPR -NewPassword $sp
Set-ADUser -identity MIMSSPR -Enabled 1 -PasswordNeverExpires 1

New-ADUser -SamAccountName SharePoint -name SharePoint
Set-ADAccountPassword -identity SharePoint -NewPassword $sp
Set-ADUser -identity SharePoint -Enabled 1 -PasswordNeverExpires 1

New-ADUser -SamAccountName SqlServer -name SqlServer
Set-ADAccountPassword -identity SqlServer -NewPassword $sp
Set-ADUser -identity SqlServer -Enabled 1 -PasswordNeverExpires 1

New-ADUser -SamAccountName BackupAdmin -name BackupAdmin
Set-ADAccountPassword -identity BackupAdmin -NewPassword $sp
Set-ADUser -identity BackupAdmin -Enabled 1 -PasswordNeverExpires 1

New-ADUser -SamAccountName MIMPool -name MIMPool
Set-ADAccountPassword -identity MIMPool -NewPassword $sp
Set-ADUser -identity MIMPool -Enabled 1 -PasswordNeverExpires 1

# -------------------------------------------------------------------------
# ------------------- CREATE SECURITY GROUPS for MIM ----------------------
New-ADGroup -name MIMSyncAdmins -GroupCategory Security -GroupScope Global -SamAccountName MIMSyncAdmins
New-ADGroup -name MIMSyncOperators -GroupCategory Security -GroupScope Global -SamAccountName MIMSyncOperators
New-ADGroup -name MIMSyncJoiners -GroupCategory Security -GroupScope Global -SamAccountName MIMSyncJoiners
New-ADGroup -name MIMSyncBrowse -GroupCategory Security -GroupScope Global -SamAccountName MIMSyncBrowse
New-ADGroup -name MIMSyncPasswordSet -GroupCategory Security -GroupScope Global -SamAccountName MIMSyncPasswordSet
Add-ADGroupMember -identity MIMSyncAdmins -Members Administrator
Add-ADGroupmember -identity MIMSyncAdmins -Members MIMService
Add-ADGroupmember -identity MIMSyncAdmins -Members MIMInstall

# -------------------------------------------------------------------------
# ------------------- ADD SPNs TO ENABLE KERBEROS -------------------------
setspn -S http/mim.$strDomainFQDN $strDomainShort\MIMPool
setspn -S http/mim $strDomainShort\MIMPool
setspn -S http/passwordreset.$strDomainFQDN $strDomainShort\MIMSSPR
setspn -S http/passwordregistration.$strDomainFQDN $strDomainShort\MIMSSPR
setspn -S FIMService/mim.$strDomainFQDN $strDomainShort\MIMService
setspn -S FIMService/$strMimSrvName.$strDomainFQDN $strDomainShort\MIMService

# ------------------- END OF SCRIPT MAIN ----------------------------------


# ------------------- CLEANUP ---------------------------------------------


# ------------------- SCRIPT END ------------------------------------------
$error.clear()

EndScript