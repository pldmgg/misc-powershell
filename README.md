# misc-powershell
Miscellaneous PowerShell Scripts

Contents:

1) Get-AllDiskInfo.ps1

SYNOPSIS
    
This script along with the Get-AllDiskInfo function (at the end) attempts to provide all disk information for the localhost in a way that ties Disk, Partition, and Volume information together ***in one output***.

DESCRIPTION
    
At first glance, it may seem that more recent PowerShell cmdlets (and even just diskpart) already fulfill this need.  However, all newer PowerShell cmdlets that I have explored fail to tie Disk, Partition, and Volume information together ***in the same output***
    
This script/function also provides the ability to create hashtables and PSObjects based on Disk/Partition for easier extensibility.
    
This script/function is compatible with ***all*** versions of PowerShell, since, ultimately, it is all based on diskpart output.



2) Generate-EncryptedPwdFile.ps1

SYNOPSIS

This script/function prompts the user for a password, which is then encrypted via a certificate (in .pfx format), converted to base64, and then written to a file on the filesystem in a location provided by the user.

The resulting file containing the encrypted password can be decrypted using the Decrypt-EncryptedPwdFile.ps1 script/function in this repository.



3) Decrypt-EncryptedPwdFile.ps1

SYNOPSIS

This script/function will decrypt an encrypted password written using the Generate-EncryptedPwdFile.ps1 script/function in this repository.  

WARNING: The decrypted password will be written to STDOUT.



4) Generate-CertTemplate.ps1

SYNOPSIS

This script/function generates a New Certificate Template AND Publishes it for use.  It does NOT generate actual certificates.  This script attempts to simplify Certificate Template creation by copying Certificate Template attributes from existing default Certificate Templates to the New Certificate Template.

This can be run as a script by uncommenting the very last line calling the Generate-CertTemplate function, or by simply loading the entire function into your current shell and then calling it.

IMPORTANT NOTE: By running the function without any parameters, the user will be walked-through several prompts. This is the recommended way to use this function until the user feels comfortable with parameters defined in the function.

This script/function depends on the PSPKI Module found here: http://pspki.codeplex.com/

For more details, see the SYNOPSIS and DESCRIPTION sections within the script itself.

