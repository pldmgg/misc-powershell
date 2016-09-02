# misc-powershell
Miscellaneous PowerShell Scripts

Contents:


1) Decrypt-EncryptedPwdFile.ps1

This script/function will decrypt a file that contains an encrypted password that was written using the Generate-EncryptedPwdFile.ps1 script/function in this repository.  

WARNING: The decrypted password will be written to STDOUT.



2) Generate-CertTemplate.ps1

This script/function generates a New Certificate Template AND Publishes it for use.  It does NOT generate actual certificates.

This script/function attempts to simplify Certificate Template creation by mapping hashtables/arrays of OID and hexadecimal values to the choices an administrator would see using the Certificate Template Console GUI.

(Please see https://github.com/pldmgg/misc-powershell/blob/master/Generate-Certificate.ps1 for the script/function that actually generates a Certificate for use based off of a Certificate Template.)

This can be run as a script by uncommenting the very last line calling the Generate-CertTemplate function, or by simply loading the entire function into your current PowerShell shell and then calling it.

IMPORTANT NOTE 1: By running the function without any parameters, the user will be walked through several prompts. This is the recommended way to use this function until the user feels comfortable with parameters mentioned below.



3) Generate-Certificate.ps1

This script/function requests and receives a New Certificate from your Windows-based Issuing Certificate Authority.

When used in conjunction with the Generate-CertTemplate.ps1 script/function, all needs can be satisfied. (See: https://github.com/pldmgg/misc-powershell/blob/master/Generate-CertTemplate.ps1)

This can be run as a script by uncommenting the very last line calling the Generate-Certificate function, or by simply loading the entire function into your current PowerShell shell and then calling it.

IMPORTANT NOTE 1: By running the function without any parameters, the user will be walked through several prompts. This is the recommended way to use this function until the user feels comfortable with parameters mentioned below.



4) Generate-EncryptedPwdFile.ps1

This script/function prompts the user for a password, which is then encrypted via a certificate (in .pfx format), converted to base64, and then written to a file on the filesystem in a location provided by the user.

The resulting file containing the encrypted password can be decrypted using the Decrypt-EncryptedPwdFile.ps1 script/function in this repository.



5) Get-AllDiskInfo.ps1
    
This script along with the Get-AllDiskInfo function (at the end) has 2 goals that can be satisfied depending on the 

supplied parameters.
    

Goal #1: Provide ALL disk information for the localhost in a way that ties Disk, Partition, and Volume information together ***in one output***


Goal #2: Provide a very flexible way to access any and all information about any given Disk/Partition/Volume using either an Array of HashTables, or Array of PSObjects. (NOTE: Array of PSObjects provides the most flexibility for later parsing).  


IMPORTANT NOTE: Ultimately, the output of this script is almost entirely based on diskpart. If output is not what you would expect, check diskpart to make sure. For example, diskpart cuts off the Volume Label name at 11 characters. If a Volume Label name is greater that 11 characters, this cutoff will be present in this script/function's output.



6) New-HashTableFromHTML.ps1

This function/script generates a multi-dimensional HashTable from a single HTML table (i.e. ONE <table></table> element). There are several caveats however:

1) Row N x Column 1 in the HTML table must contain ONLY ONE VALUE or NO VALUE at all.

2) Column Headers must contain ONLY ONE VALUE per column or NO VALUE at all.

3) One-to-many relationships (i.e. one value in Row N x Column 1 and more than one value in Row N x Column 1+N) are only handled properly if Column 1+N contains a MAXIMUM of 2 values. Example: https://coreos.com/os/docs/latest/booting-on-ec2.html



7) Send-EmailOnPublicIPChange.ps1

This script, when run as a scheduled task, monitors your public IP Address by checking http://checkip.dyndns.com. 

The first time the script is run, it writes your current Public IP to a file under the user account's $HOME directory according to what http://checkip.dyndns.com reports as your Public IP. When the script runs again, it checks the IP within the file against what http://checkip.dyndns.com reports as your Public IP. If there was a change, the script:

    - Overwrites the file in the $HOME directory with the new Public IP address

    - Uses the specified gmail account to email the Verizon SMS forwarding service to send a text message to your phone notifying you of the change.

WARNING: You may only check http://checkip.dyndns.com once every 600 seconds (and consequently, you should schedule this script to run no more than once every 600 seconds). If you check http://checkip.dyndns.com more often, then it may not resolve. 

