$fulloutput = @()

#Most of the code came from: https://stackoverflow.com/questions/35344825/powershell-export-user-rights-assignment
#I just added some code to identify suspicous accounts

# Fail script if we can't find SecEdit.exe
$SecEdit = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) "SecEdit.exe"
if ( -not (Test-Path $SecEdit) ) {
  Write-Error "File not found - '$SecEdit'" -Category ObjectNotFound
  exit

}

 
# LookupPrivilegeDisplayName Win32 API doesn't resolve logon right display
# names, so use this hashtable
$UserLogonRights = @{
  "SeBatchLogonRight"                 = "Log on as a batch job"
  "SeDenyBatchLogonRight"             = "Deny log on as a batch job"
  "SeDenyInteractiveLogonRight"       = "Deny log on locally"
  "SeDenyNetworkLogonRight"           = "Deny access to this computer from the network"
  "SeDenyRemoteInteractiveLogonRight" = "Deny log on through Remote Desktop Services"
  "SeDenyServiceLogonRight"           = "Deny log on as a service"
  "SeInteractiveLogonRight"           = "Allow log on locally"
  "SeNetworkLogonRight"               = "Access this computer from the network"
  "SeRemoteInteractiveLogonRight"     = "Allow log on through Remote Desktop Services"
  "SeServiceLogonRight"               = "Log on as a service"
}

 

# Create type to invoke LookupPrivilegeDisplayName Win32 API

$Win32APISignature = @'
[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool LookupPrivilegeDisplayName(
  string systemName,
  string privilegeName,
  System.Text.StringBuilder displayName,
  ref uint cbDisplayName,
  out uint languageId
);
'@

try
{
$AdvApi32 = Add-Type advapi32 $Win32APISignature -Namespace LookupPrivilegeDisplayName -PassThru
}
catch
{
}
 

# Use LookupPrivilegeDisplayName Win32 API to get display name of privilege
# (except for user logon rights)

function Get-PrivilegeDisplayName {
  param(
    [String] $name
  )
  $displayNameSB = New-Object System.Text.StringBuilder 1024
  $languageId = 0
  $ok = $AdvApi32::LookupPrivilegeDisplayName($null, $name, $displayNameSB, [Ref] $displayNameSB.Capacity, [Ref] $languageId)
  if ( $ok ) {
    $displayNameSB.ToString()
  }

  else {
    # Doesn't lookup logon rights, so use hashtable for that
    if ( $UserLogonRights[$name] ) {
      $UserLogonRights[$name]
    }
    else {
      $name
    }
  }
}


# Outputs list of hashtables as a PSObject
function Out-Object {
  param(
    [System.Collections.Hashtable[]] $hashData
  )

  $order = @()
  $result = @{}
  $hashData | ForEach-Object {
    $order += ($_.Keys -as [Array])[0]
    $result += $_

  }
  New-Object PSObject -Property $result | Select-Object $order
}


# Translates a SID in the form *S-1-5-... to its account name;

function Get-AccountName {

  param(
    [String] $principal

  )

  if ( $principal[0] -eq "*" ) {
    $sid = New-Object System.Security.Principal.SecurityIdentifier($principal.Substring(1))
    Try {$out = $sid.Translate([Security.Principal.NTAccount])}
    catch
        {
        $out = $principal
        }
    $out
  }
  else {
    $principal
  }

}

 

$TemplateFilename = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
$LogFilename = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
$StdOut = & $SecEdit /export /cfg $TemplateFilename /areas USER_RIGHTS /log $LogFilename

if ( $LASTEXITCODE -eq 0 ) {

  Select-String '^(Se\S+) = (\S+)' $TemplateFilename | Foreach-Object {
    $Privilege = $_.Matches[0].Groups[1].Value
    $Principals = $_.Matches[0].Groups[2].Value -split ','
    foreach ( $Principal in $Principals ) 
    {

    <#

        look for these permissions.

        SeImpersonatePrivilege
        SeAssignPrimaryPrivilege
        SeTcbPrivilege
        SeBackupPrivilege
        SeRestorePrivilege
        SeCreateTokenPrivilege
        SeLoadDriverPrivilege
        SeTakeOwnershipPrivilege
        SeDebugPrivilege
        


        #>
         if (($Privilege -eq 'SeTcbPrivilege' `
        -or ($Privilege -eq 'SeBackupPrivilege' -and (Get-AccountName $Principal) -notlike '*BUILTIN\Administrators*' -and (Get-AccountName $Principal) -notlike '*BUILTIN\Backup Operators*' ) `
        -or $Privilege -eq 'SeAssignPrimaryPrivilege' `
        -or ($Privilege -eq 'SeImpersonatePrivilege' -and ((Get-AccountName $Principal) -notlike '*NT AUTHORITY\LOCAL SERVICE*' -and (Get-AccountName $Principal) -notlike '*NT AUTHORITY\NETWORK SERVICE'  -and (Get-AccountName $Principal) -notlike '*BUILTIN\Administrators' -and (Get-AccountName $Principal) -notlike '*NT AUTHORITY\SERVICE' )) `
        -or $Privilege -eq 'SeCreateTokenPrivilege' `
        -or ($Privilege -eq 'SeLoadDriverPrivilege' -and (Get-AccountName $Principal) -notlike '*BUILTIN\Administrators*') `
        -or ($Privilege -eq 'SeRestorePrivilege' -and (Get-AccountName $Principal) -notlike '*BUILTIN\Backup Operators*' -and (Get-AccountName $Principal) -notlike '*BUILTIN\Administrators' )  `
        -or ($Privilege -eq 'SeTakeOwnershipPrivilege' -and (Get-AccountName $Principal) -notlike '*BUILTIN\Administrators*') `
        -or ($Privilege -eq 'SeDebugPrivilege' -and (Get-AccountName $Principal) -notlike '*BUILTIN\Administrators*')) )
            {
                $fulloutput += `
                 Out-Object `
                    @{"Privilege" = $Privilege},
                    @{"PrivilegeName" = Get-PrivilegeDisplayName $Privilege},
                    @{"Principal" = Get-AccountName $Principal},
                    @{"Suspicious" = "True"}

            }
            else

            {
                 $fulloutput += `
                 Out-Object `
                    @{"Privilege" = $Privilege},
                    @{"PrivilegeName" = Get-PrivilegeDisplayName $Privilege},
                    @{"Principal" = Get-AccountName $Principal},
                    @{"Suspicious" = "False"}
            }
       
    }
  }
}

else {
  $OFS = ""
  Write-Error "$StdOut"
}

Remove-Item $TemplateFilename,$LogFilename -ErrorAction SilentlyContinue

 
$fulloutput | Sort-Object Suspicious -Descending | Out-GridView