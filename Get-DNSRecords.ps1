
function Convert-DNSRecord {
<#
.SYNOPSIS
Helpers that decodes a binary DNS record blob.
Author: Michael B. Smith, Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  
.DESCRIPTION
Decodes a binary blob representing an Active Directory DNS entry.
Used by Get-DomainDNSRecord.
Adapted/ported from Michael B. Smith's code at https://raw.githubusercontent.com/mmessano/PowerShell/master/dns-dump.ps1
.PARAMETER DNSRecord
A byte array representing the DNS record.
.OUTPUTS
System.Management.Automation.PSCustomObject
Outputs custom PSObjects with detailed information about the DNS record entry.
.LINK
https://raw.githubusercontent.com/mmessano/PowerShell/master/dns-dump.ps1
#>

    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Byte[]]
        $DNSRecord,
        [string]$Name
    )

    BEGIN {
        function Get-Name {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '')]
            [CmdletBinding()]
            Param(
                [Byte[]]
                $Raw
            )

            [Int]$Length = $Raw[0]
            [Int]$Segments = $Raw[1]
            [Int]$Index =  2
            [String]$Name  = ''

            while ($Segments-- -gt 0)
            {
                [Int]$SegmentLength = $Raw[$Index++]
                while ($SegmentLength-- -gt 0) {
                    $Name += [Char]$Raw[$Index++]
                }
                $Name += "."
            }
            $Name
        }
    }

    PROCESS {
        # $RDataLen = [BitConverter]::ToUInt16($DNSRecord, 0)
        $RDataType = [BitConverter]::ToUInt16($DNSRecord, 2)
        $UpdatedAtSerial = [BitConverter]::ToUInt32($DNSRecord, 8)

        $TTLRaw = $DNSRecord[12..15]

        # reverse for big endian
        $Null = [array]::Reverse($TTLRaw)
        $TTL = [BitConverter]::ToUInt32($TTLRaw, 0)

        $Age = [BitConverter]::ToUInt32($DNSRecord, 20)
        if ($Age -ne 0) {
            $TimeStamp = ((Get-Date -Year 1601 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0).AddHours($age)).ToString()
        }
        else {
            $TimeStamp = '[static]'
        }

        $DNSRecordObject = New-Object PSObject

        if ($RDataType -eq 1) {
            $IP = "{0}.{1}.{2}.{3}" -f $DNSRecord[24], $DNSRecord[25], $DNSRecord[26], $DNSRecord[27]
            $Data = $IP
            $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'A'
        }

        elseif ($RDataType -eq 2) {
            $NSName = Get-Name $DNSRecord[24..$DNSRecord.length]
            $Data = $NSName
            $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'NS'
        }

        elseif ($RDataType -eq 5) {
            $Alias = Get-Name $DNSRecord[24..$DNSRecord.length]
            $Data = $Alias
            $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'CNAME'
        }

        elseif ($RDataType -eq 6) {
            # TODO: how to implement properly? nested object?
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'SOA'
        }

        elseif ($RDataType -eq 12) {
            $Ptr = Get-Name $DNSRecord[24..$DNSRecord.length]
            $Data = $Ptr
            $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'PTR'
        }

        elseif ($RDataType -eq 13) {
            # TODO: how to implement properly? nested object?
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'HINFO'
        }

        elseif ($RDataType -eq 15) {
            # TODO: how to implement properly? nested object?
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'MX'
        }

        elseif ($RDataType -eq 16) {
            [string]$TXT  = ''
            [int]$SegmentLength = $DNSRecord[24]
            $Index = 25

            while ($SegmentLength-- -gt 0) {
                $TXT += [char]$DNSRecord[$index++]
            }

            $Data = $TXT
            $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'TXT'
        }

        elseif ($RDataType -eq 28) {
            # TODO: how to implement properly? nested object?
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'AAAA'
        }

        elseif ($RDataType -eq 33) {
            # TODO: how to implement properly? nested object?
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'SRV'
        }

        else {
            $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
            $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'UNKNOWN'
        }

        $DNSRecordObject | Add-Member Noteproperty 'UpdatedAtSerial' $UpdatedAtSerial
        $DNSRecordObject | Add-Member Noteproperty 'TTL' $TTL
        $DNSRecordObject | Add-Member Noteproperty 'Age' $Age
        $DNSRecordObject | Add-Member Noteproperty 'TimeStamp' $TimeStamp
        $DNSRecordObject | Add-Member Noteproperty 'Data' $Data
        $DNSRecordObject | Add-Member Noteproperty 'name' $name
        $DNSRecordObject
    }
}

function Get-DNSrecords{
    param(
    [string]$DomainDN,
    [int]$limit,
    [int]$pagesize,
    [string]$DCAddress,
    [string]$name
    )

    $filter = "(dnsrecord=*)"
    if($name){
    
    $filter = "(&($filter)(name=$name))"
    }

    $search = new-object -type system.directoryservices.directorysearcher
    $search.filter = $filter
    if($DCAddress){$DomainDN = "$DCAddress/" + "DC=DomainDnsZones," + "$DomainDN"}
    if($DomainDN){
        $ADPath = "LDAP://$DomainDN"
        $entry = new-object -type system.directoryservices.directoryentry -argumentlist $ADPath
        $search.searchroot = $entry
	}
    else{ 
        $base = $search.searchroot.distinguishedName
        $DomainDN = "DC=DomainDnsZones," + "$base"
        $ADPath = "LDAP://$DomainDN"
        $adpATH
        $entry = new-object -type system.directoryservices.directoryentry -argumentlist $ADPath
        $search.searchroot = $entry
    
     }
    $search.searchroot
    $search.propertiestoload.add("dnsrecord") | out-null
    $search.propertiestoload.add("name") | out-null
    $search.SearchScope = 2
    $results = $search.findall()
    $results | %{ Convert-DNSRecord $_.Properties["dnsrecord"][0] -name $_.properties["name"]}
    $search.dispose()


}



