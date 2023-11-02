<#
    .SYNOPSIS
        Builds an email from a list of templates, then sends the email to the user with a cc to user manager

    .DESCRIPTION
        Builds an email from a list of templates, then sends the email to the user with a cc to user manager
        Prompts for authentication before sending email
        10 Templates are currently available
        Templates are sourced from <git server address>
        !! The menu style approach and read host whould be dropped, and rewritten with parameters, to allow for automation
        
    .INPUTS
        None.

    .OUTPUTS
        Sends email to user and manager, logs email details and body text in ScriptLogs
        
    .EXAMPLE
        PS> .\Send-SocClientEmail.ps1
#>


function Select-Template { # Probably can do this another way.  Might be more elegant to have a help function display the options to the user, and parameterize the input
  Write-Host "`r`nSelect an email template:" 
        $templateOption = Read-Host "`r`n[ 1] Deleted forwarding rules notification`n[ 2] Deleted SMTP forwarding notification`n[ 3] Forwarding rule explanation request`n[ 4] Stolen laptop information request`n[ 5] Malware reboot pending`n[ 6] Malware present on USB`n[ 7] Malware present on Optical media`n[ 8] Non admin account added to admin group`n[ 9] Added self to admin group`n[10] Copyrighted software`r`n`r`nTemplate choice "  
               
        if ($templateOption -eq "1") {
            $script:url = "<git server address>/raw/email/forwarding_rule_deletion.txt"
            $script:logType = "forwarding_rule_deletion"
            $script:ruleSnip = Read-Host -prompt "`r`nExample Rule Snip"
            $script:templateSubject = "Mailbox rule automatically forwarding email"
		} 
        elseif ($templateOption -eq "2") {
            $script:url = "<git server address>/raw/email/forwarding_SMTP_deletion.txt"
            $script:logType = "forwarding_SMTP_deletion"
            $script:smtpForwardingAddress = Read-Host -prompt "`r`nSMTP forwarding address"
            $script:templateSubject = "Mailbox SMTP configuration automatically forwarding email"
        }
        elseif ($templateOption -eq "3") {
            $script:url = "<git server address>/forwarding_rule_explanation_request.txt"
            $script:logType = "forwarding_info_request"
            $script:ruleSnip = Read-Host -prompt "`r`nExample Rule Snip"
            $script:templateSubject = "Mailbox forwarding information request"
        }
        elseif ($templateOption -eq "4") {
            $script:url = "<git server address>/raw/email/stolen_laptop.txt"
            $script:logType = "stolen_laptop"
            $script:snowNumber = Read-Host -prompt "`r`nServiceNow ticket number"
            $script:laptopMake = Read-Host -prompt "Laptop Make"
            $script:laptopModel = Read-Host -prompt "Laptop Model Number"
            $script:laptopSerial = Read-Host -prompt "Laptop Serial Number"
            $script:laptopHostname = Read-Host -prompt "Laptop Hostname"
            $script:templateSubject = "Stolen laptop information request"
        }
        elseif ($templateOption -eq "5") {
            $script:url = "<git server address>/raw/email/malware_present_reboot_pending.txt"
            $script:logType = "malware_present_reboot_pending"
            $script:detectedDate = Read-Host -prompt "`r`nDate Malware detected"
            $script:malwareFilePath = Read-Host -prompt "Malware File Path"
            $script:templateSubject = "Reboot required to eradicate malware"
        }
        elseif ($templateOption -eq "6") {
            $script:url = "<git server address>/raw/email/malware_present_on_usb_media.txt"
            $script:logType = "malware_present_on_usb_media"
            $script:detectedDate = Read-Host -prompt "`r`nDate Malware detected"
            $script:malwareFilePath = Read-Host -prompt "Malware File Path"
            $script:templateSubject = "Malware discovered on USB device"
        }
        elseif ($templateOption -eq "7") {
            $script:url = "<git server address>/raw/email/email/malware_present_on_optical_drive.txt"
            $script:logType = "malware_present_on_optical_drive"
            $script:detectedDate = Read-Host -prompt "`r`nDate Malware detected"
            $script:malwareFilePath = Read-Host -prompt "Malware File Path"
            $script:templateSubject = "Malware discovered on CD/DVD device"
        }
        elseif ($templateOption -eq "8") {
            $script:url = "<git server address>/raw/email/non_admin_add_to_admin_group.txt"
            $script:logType = "non_admin_add_to_admin_group"
            $script:nonAdminAccount = Read-Host -prompt "`r`nNon Admin account that was added"
            $script:adminUser = Read-Host -prompt "Admin account that performed this"
            $script:groupName = Read-Host -prompt "Privileged group name"
            $script:templateSubject = "Non privileged account added to privileged group"
        }
        elseif ($templateOption -eq "9") {
            $script:url = "<git server address>/raw/email/non_admin_add_to_admin_group.txt"
            $script:logType = "non_admin_add_to_admin_group"
            $script:adminAccount = Read-Host -prompt "`r`nAdmin account name"
            $script:groupName = Read-Host -prompt "Privileged group name"
            $script:templateSubject = "Self owned privileged account added to privileged group"
        }
        elseif ($templateOption -eq "10") {
            $script:url = "<git server address>/raw/email/copyrighted_software.txt"
            $script:logType = "copyrighted_software"
            $script:piratedFiles = Read-Host -prompt "Files breaching copyright"
            $script:templateSubject = "Copyright protected software"
        }
        else {
            Write-Host "`r`nNo correct option selected, exiting"
            exit
        }
}

function Create-MailBody {
    $token = "<token>" # For the life of me, I can't remember what this is.  Must be auth token for Git repo
    $headers = @{"Authorization" = "token $token" }
    $template = Invoke-RestMethod -uri $url -Headers $headers -ContentType "application/json"
    $script:emailBody = $ExecutionContext.InvokeCommand.ExpandString($template)
}

function Check-Template {
  # Write-Host "`r`n$emailBody"  ## Probably need to output this so the user can read and verify
  Write-Host "`r`nIs the information in this email correct?" 
        $script:continue = Read-Host "[Y] Yes  [N] No"  
}
 
function Get-UserInfo { 
    [cmdletbinding(DefaultParameterSetName='emailAddress')] 
    Param(
        [Parameter(ParameterSetName='samAccountName')] [String] $samAccountName,
        [Parameter(ParameterSetName='managerDN')] [String] $managerDN, 
        [Parameter(ParameterSetName='emailAddress')] [String] $emailAddress 
    ) 
    # get local GC for doing the AD queries 
    $localSite = (Get-ADDomainController -Discover).Site 
    $newTargetGC = Get-ADDomainController -Discover -Service 2 -SiteName $localSite 
    If (!$newTargetGC) {$newTargetGC = Get-ADDomainController -Discover -Service 6 -NextClosestSite} 
    $localGC = "$($newTargetGC.HostName)" + ":3268" 
    if ( -not ([string]::IsNullOrWhiteSpace($managerDN))) { 
        $userInfo = Get-ADUser -filter "DistinguishedName -eq '$managerDN'" -Server $localGC -Properties Name, City, Co, Department, mail, Manager, Title, UserPrincipalName, msExchExtensionAttribute31, msExchExtensionAttribute32, SamAccountName, PasswordLastSet, TelephoneNumber, LastLogonDate, Enabled 
    } 
    if ( -not ([string]::IsNullOrWhiteSpace($emailAddress))) { 
       $userInfo = Get-ADUser -filter "EmailAddress -eq '$emailAddress'" -Server $localGC -Properties Manager
    }
    if ( -not ([string]::IsNullOrWhiteSpace($samAccountName))) { 
        $userInfo = Get-ADUser -filter "SamAccountName -eq '$samAccountName'" -Server $localGC -Properties Name, City, Co, Department, mail, Manager, Title, UserPrincipalName, msExchExtensionAttribute31, msExchExtensionAttribute32, SamAccountName, PasswordLastSet, TelephoneNumber, LastLogonDate, Enabled 
    }  
    $userInfo 
}

function Get-EmailDetails {
    Write-Host "Looking up details in AD for users first name and manager email"
    $userDetails = Get-UserInfo -emailAddress $emailAddress
    $script:userFirstName = $UserDetails.GivenName
    $script:managerEmail = (Get-UserInfo -managerDN ($userDetails.Manager)).UserPrincipalName
    $script:sender = (Get-UserInfo -samAccountName $analyst).UserPrincipalName
    $script:subject = "$templateSubject [SOC Ticket#$irfNumber]"
    $script:smtpServer = "outlook.office365.com"
}

# Main Script starts here
$emailAddress = Read-Host -prompt 'Email Address of user'
$irfNumber = Read-Host -prompt 'Incident Ticket Number'
$utcDate = (Get-Date).ToUniversalTime() # These two can probably made into a one liner
$currentDate = (get-date -date $utcDate).tostring("yyyyMMddHHmm")
$analyst = $env:UserName
Select-Template # User chooses which template to send
# Setup log files
$outfilePath = "\\<SMB share for log file>\" + $analyst + "\" # This and the next line could be one line.  Made two lines for visibility
$logFile = $outfilePath + $logType + "_" + "contact_email" + "_" + $emailAddress + "-" + $currentDate + ".txt"
Tee-Object -InputObject "User contact email log for $emailAddress - IRF $irfNumber" -FilePath $logFile
Tee-Object -InputObject "Running under the following user context: $analyst" -FilePath $logFile -Append
Tee-Object -InputObject "`r`nTemplate $templateSubject selected - $logType" -FilePath $logFile -Append
Get-EmailDetails # Get all of the parameters required for building the email - AD lookups occur here
Create-MailBody
Tee-Object -InputObject "`r`nThe details are:`r`nTo: $emailAddress`r`nManager: $managerEmail`r`nFrom: $sender`r`nSubject: $subject`r`n`r`nEmail Body:`r`n`r`n$emailBody" -FilePath $logFile -Append
Check-Template # Check with user 
if ($continue.ToLower() -eq "y") {
    Write-Host "User context is $analyst`r`nPlease enter your AD password for this account to send the email"
    Send-MailMessage -To $emailAddress -Subject $subject -From $sender -Cc "<analyst email address variable here>" -Body $emailBody -SmtpServer $smtpServer -UseSsl -Credential $sender
    Tee-Object -InputObject "`r`nEmail sent.`r`nLog has been saved to $logFile`r`n" -FilePath $logFile -Append
} 
elseif ($continue.ToLower() -eq "n") {  # Probably should just make this else instead of elseif
    Tee-Object -InputObject "`r`nTemplate not accepted, exiting`r`nEmail NOT sent.`r`nLog has been saved to $logFile`r`n" -FilePath $logFile -Append
}
