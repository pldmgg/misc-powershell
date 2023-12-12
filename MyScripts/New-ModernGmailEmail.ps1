$ModuleName = 'Send-MailKitMessage'
if (!$(Get-Module -ListAvailable $ModuleName -ErrorAction SilentlyContinue)) {
    try {
        $InstallModuleResult = Install-Module $ModuleName -AllowClobber -Force -ErrorAction Stop -WarningAction SilentlyContinue
        Import-Module $ModuleName -ErrorAction Stop
    } catch {
        Write-Warning $_.Exception.Message
        Write-Error "Unable to install $ModuleName module! Halting!"
        $global:FunctionResult = "1"
        return
    }
}

<#
Send-MailKitMessage -SMTPServer <string> -Port <int> -From <MimeKit.MailboxAddress> -RecipientList <MimeKit.InternetAddressList>
[-UseSecureConnectionIfAvailable] [-Credential <pscredential>] [-CCList <MimeKit.InternetAddressList>] [-BCCList
<MimeKit.InternetAddressList>] [-Subject <string>] [-TextBody <string>] [-HTMLBody <string>] [-AttachmentList <string[]>]
#>
$SMTPServer = "smtp.gmail.com"
$SMTPPort = "587"
$GmailAuthString = 'thisisnotrealaaa'
$UserName = "jsmith@gmail.com"
$SenderName = "John Smith"
$SenderEmail = $UserName
$RecipientName = "Jane Doe"
$RecipientEmail = "jdoe@domain.com"
$From = [MimeKit.MailboxAddress]::new($SenderName, $SenderEmail)
$Recipients = [MimeKit.InternetAddressList]::new()
$Recipients.Add([MimeKit.MailboxAddress]::new($RecipientName, $RecipientEmail))
[securestring]$Psswd = ConvertTo-SecureString $GmailAuthString -AsPlainText -Force
$Creds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $UserName, $Psswd

$SMKMParams = @{
    SmtpServer                      = $SMTPServer
    Port                            = $SMTPPort
    From                            = $From
    RecipientList                   = $Recipients
    UseSecureConnectionIfAvailable  = $True
    Credential                      = $Creds
    Subject                         = "$env:ComputerName ALERT"
    TextBody                        = 'This is a test'
}
Send-MailKitMessage @SMKMParams