# ActiveDirectorySearcher
## Search active Directory Objects
```
Get-ADObject # DirectorySearcher
Enum-Dacls # Finds interesting Dcals 
to-ldif # Coverts results of Get-ADObject into ldif

Get-ADObject -filter "(objectclass=OrganizationalUnit)" -scope 2 -pagesize 500 -limit 10000 -force

Get-ADObject -DCAddress 192.168.2.10 -base "dc=shrimp,dc=co" -ntsecurity -filter "(objectclass=OrganizationalUnit)" -scope 2 | %{Enum-Dacls $_ -FormatString }

Get-ADObject -DCAddress 192.168.2.10 -base "dc=shrimp,dc=co" -ntsecurity -scope 2 -pagesize 500 -limit 10000 -Force | %{to-ldif $_} | Out-File C:\users\admin\Desktop\domain.ldif
```
