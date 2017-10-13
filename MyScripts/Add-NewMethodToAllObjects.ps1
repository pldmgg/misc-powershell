# Add New Method to ALL Objects in PowerShell

# The below adds the method PSAddMember() to all objects in the PowerShell Session
[system.object] | Update-TypeData -MemberType ScriptMethod -MemberName PSAddMember -Value {
    switch ($args.count) {
        1 { 
            $hash = $args[0] -as [HashTable]
            foreach ($key in $hash.keys) {
                Add-Member -InputObject $this -Name $key -value $hash.$key -MemberType NoteProperty -Force
            }
        }

        2 {
            $name,$value = $args
            Add-Member -InputObject $this -Name $name -value $value -MemberType NoteProperty -Force
        }

        3 {
            $name,$value,$MemberType = $args
            Add-Member -InputObject $this -Name $name -value $value -MemberType $MemberType -Force
        }
    }
}

# The below adds the method MSDN() to all objects in the PowerShell Session
[system.object] | Update-TypeData -MemberType ScriptMethod -MemberName MSDN -Value {
    if (($global:MSDNViewer -eq $null) -or ($global:MSDNViewer.HWND -eq $null)) {
        $global:MSDNViewer = New-Object -ComObject InternetExplorer.Application
    }
    $Uri = "http://msdn2.microsoft.com/library/" + $this.GetType().FullName + ".ASPX"
    $global:MSDNViewer.Navigate2($Uri)
    $global:MSDNViewer.Visible = $TRUE
}