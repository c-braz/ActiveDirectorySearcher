function to-ldif{
    param(
    $object
    )

    $properties = $object.properties
    "DN: "+ "$($properties.distinguishedname)"
    foreach($key in $properties.keys){
        foreach($val in  $properties[$key]){
	    if($key -match "ntsecuritydescriptor"){
                $val = [system.convert]::ToBase64String($val)
                "$($key):: $($val)"
                }
            else{"$($key): $($val)"}
        }
        }
    ''
}

function Enum-Dacls{
        param(
        $Object,
        [switch]$FormatString,
        [switch]$AllDacls
        )

        $rightsguid = @{
            'a1990816-4298-11d1-ade2-00c04fd8d5cd' = 'Open-Address-Book';
            'ab721a52-1e2f-11d0-9819-00aa0040529b' = 'Domain-Administer-Server';
            '45ec5156-db7e-47bb-b53f-dbeb2d03c40f' = 'Reanimate-Tombstones';
            'be2bb760-7f46-11d2-b9ad-00c04f79f805' = 'Update-Schema-Cache';
            'ba33815a-4f93-4c76-87f3-57574bff8109' = 'Migrate-SID-History';
            '4b6e08c2-df3c-11d1-9c86-006008764d0e' = 'msmq-Receive-computer-Journal';
            'cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd' = 'Change-Infrastructure-Master';
            '06bd3202-df3e-11d1-9c86-006008764d0e' = 'msmq-Send';
            '1131f6ae-9c07-11d1-f79f-00c04fc2dcd2' = 'Read-Only-Replication-Secret-Synchronization';
            '9923a32a-3607-11d2-b9be-0000f87a36b2' = 'DS-Install-Replica';
            '2f16c4a5-b98e-432c-952a-cb388ba33f2e' = 'DS-Execute-Intentions-Script';
            'edacfd8f-ffb3-11d1-b41d-00a0c968f939' = 'Apply-Group-Policy';
            '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes';
            '1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8' = 'Reload-SSL-Certificate';
            '00299570-246d-11d0-a768-00aa006e0529' = 'User-Force-Change-Password';
            '4b6e08c0-df3c-11d1-9c86-006008764d0e' = 'msmq-Receive-Dead-Letter';
            '280f369c-67c7-438e-ae98-1d46f3c6f541' = 'Update-Password-Not-Required-Bit';
            'ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501' = 'Unexpire-Password';
            'b7b1b3dd-ab09-4242-9e30-9980e5d322f7' = 'Generate-RSoP-Planning';
            'e2a36dc9-ae17-47c3-b58b-be34c55ba633' = 'Create-Inbound-Forest-Trust';
            '06bd3201-df3e-11d1-9c86-006008764d0e' = 'msmq-Peek';
            '69ae6200-7f46-11d2-b9ad-00c04f79f805' = 'DS-Check-Stale-Phantoms';
            '91d67418-0135-4acc-8d79-c08e857cfbec' = 'SAM-Enumerate-Entire-Domain';
            '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Manage-Topology';
            '4b6e08c3-df3c-11d1-9c86-006008764d0e' = 'msmq-Peek-computer-Journal';
            '440820ad-65b4-11d1-a3da-0000f875ae0d' = 'Add-GUID';
            'b4e60130-df3f-11d1-9c86-006008764d0e' = 'msmq-Open-Connector';
            'bae50096-4752-11d1-9052-00c04fc2d4cf' = 'Change-PDC';
            '0e10c968-78fb-11d2-90d4-00c04f79dc55' = 'Certificate-Enrollment';
            '06bd3203-df3e-11d1-9c86-006008764d0e' = 'msmq-Receive-journal';
            'ee914b82-0a98-11d1-adbb-00c04fd8d5cd' = 'Abandon-Replication';
            '62dd28a8-7f46-11d2-b9ad-00c04f79f805' = 'Recalculate-Security-Inheritance';
            'ab721a55-1e2f-11d0-9819-00aa0040529b' = 'Send-To';
            '06bd3200-df3e-11d1-9c86-006008764d0e' = 'msmq-Receive';
            'ab721a56-1e2f-11d0-9819-00aa0040529b' = 'Receive-As';
            '05c74c5e-4deb-43b4-bd9f-86664c2a7fd5' = 'Enable-Per-User-Reversibly-Encrypted-Password';
            '7c0e2a7c-a419-48e4-a995-10180aad54dd' = 'Manage-Optional-Features';
            'ab721a54-1e2f-11d0-9819-00aa0040529b' = 'Send-As';
            '68b1d179-0d15-4d4f-ab71-46152e79a7bc' = 'Allowed-To-Authenticate';
            '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Get-Changes-All';
            '4b6e08c1-df3c-11d1-9c86-006008764d0e' = 'msmq-Peek-Dead-Letter';
            'f98340fb-7c5b-4cdb-a00b-2ebdfa115a96' = 'DS-Replication-Monitor-Topology';
            '0bc1554e-0a99-11d1-adbb-00c04fd8d5cd' = 'Recalculate-Hierarchy';
            'ab721a53-1e2f-11d0-9819-00aa0040529b' = 'User-Change-Password';
            '7726b9d5-a4b4-4288-a6b2-dce952e80a7f' = 'Run-Protect-Admin-Groups-Task';
            '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2' = 'DS-Replication-Synchronize';
            '3e0f7e18-2c7a-4c10-ba82-4d926db99a3e' = 'DS-Clone-Domain-Controller';
            'd58d5f36-0a98-11d1-adbb-00c04fd8d5cd' = 'Change-Rid-Master';
            'e12b56b6-0a95-11d1-adbb-00c04fd8d5cd' = 'Change-Schema-Master';
            '9432c620-033c-4db7-8b58-14ef6d0bf477' = 'Refresh-Group-Cache';
            '014bf69c-7b3b-11d1-85f6-08002be74fab' = 'Change-Domain-Master';
            'b7b1b3de-ab09-4242-9e30-9980e5d322f7' = 'Generate-RSoP-Logging';
            '1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd' = 'Allocate-Rids';
            '4ecc03fe-ffc0-4947-b630-eb672a8a9dbc' = 'DS-Query-Self-Quota';
            '89e95b76-444d-4c62-991a-0facbeda640c' = 'DS-Replication-Get-Changes-In-Filtered-Set';
            'fec364e0-0a98-11d1-adbb-00c04fd8d5cd' = 'Do-Garbage-Collection';
        }

        [byte[]]$raw = $Object.properties.ntsecuritydescriptor[0]
        $SD = [system.security.accesscontrol.rawsecuritydescriptor]::new($raw,0)
        $dacls = $SD.DiscretionaryAcl
        
        
        if($AllDacls){$intrestingdacls = $dacls}
        else{
            foreach($dacl in $dacls){
                [int]$rid = $dacl.SecurityIdentifier.Value.split("-")[-1]
                [array]$intrestingdacls += if( $rid -gt 999){
                    $dacl
                }
            }
        }

        if($intrestingdacls){
            foreach($intdacl in $intrestingdacls){
                $adrights = @()
                [int]$mask = $intdacl.accessmask
	            if($mask -band 1){$adrights += 'CreateChild'}
	            if($mask -band 2){$adrights += 'DeleteChild'}
                if($mask -band 4){$adrights += 'ListChildren'}
                if($mask -band 8){$adrights += 'Self'}
                if($mask -band 16){$adrights += 'ReadProperty'}
                if($mask -band 32){$adrights += 'WriteProperty'}
                if($mask -band 64){$adrights += 'DeleteTree'}
                if($mask -band 128){$adrights += 'ListObject'}
                if($mask -band 65536){$adrights += 'Delete'}
                if($mask -band 131072){$adrights += 'ReadControl'}
                if($mask -band 131076){$adrights += 'GenericExecute'}
                if($mask -band 131112){$adrights += 'GenericWrite'}
                if($mask -band 131220){$adrights += 'GenericRead'}
                if($mask -band 262144){$adrights += 'WriteDacl'}
                if($mask -band 524288){$adrights += 'WriteOwner'}
                if($mask -band 983551){$adrights += 'GenericAll'}
                if($mask -band 1048576){$adrights += 'Synchronize'}
                if($mask -band 16777216){$adrights += 'AccessSystemSecurity'}
                if($mask -band 256){
                    $adrights += 'ExtendedRight'
                    $ExntendedRight = $rightsguid[[string]$intdacl.ObjectAceType]
                }
                $CustomDacl = [PSCustomObject]@{
                    Distinguishedname = $Object.properties.distinguishedname
                    ActiveDirectoryRights = $adrights
                    ExntendedRight = $ExntendedRight
                    SID = $intdacl.SecurityIdentifier.Value
                    OriginalDacl = $intdacl
                }
                [array]$CustomDacls += $CustomDacl
           }
        }

        if($FormatString){    
            foreach($CustomDacl in $CustomDacls){
                "DN: " + $CustomDacl.Distinguishedname
                "Sid: " + $CustomDacl.SID
                "ExtendedRight: " + $CustomDacl.ExntendedRight
                "ADRights: " + $CustomDacl.ActiveDirectoryRights
                ''
            }
       }
       else{$CustomDacls}
    }

function Get-ADObject{
    param(
    [string]$filter,
    [string]$base,
    [int]$scope,
    [int]$limit,
    [int]$pagesize,
    [switch]$ntsecurity,
    [switch]$ExtendedDN,
    $atrributes = @(),
    [string]$DCAddress,
    [switch]$Force
    )

    if(!$Force){
        if($pagesize){
                Write-Output "If the page size is less than limit size. This will cause the limit to never be reached and will return all objects matching the filter! If you know what you are doing use -Force."
                "Exiting..."
                break
        }
    }

    $search = new-object -type system.directoryservices.directorysearcher
    $search.filter = $filter
    $ADPath = "LDAP://$DCAddress/$base"
    $entry = new-object -type system.directoryservices.directoryentry -argumentlist $ADPath
    $search.searchroot = $entry
    foreach($attrib in $attributes){$search.propertiestoload.add($attrib) | out-null}
    $search.sizelimit = $limit
    $search.PageSize = $pagesize
    $search.SearchScope = $scope
    if($ExtendedDN){$search.ExtendedDN = 1}
    if($ntsecurity){$search.securitymasks = 7}

    $results = $search.findall()
    $results
    $search.dispose()

    

}
