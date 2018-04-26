function Ensure-AzureIaC4VDCRoleAssignment ($path = "C:\git\bp\MgmtGroup\b2a0bb8e-3f26-47f8-9040-209289b412a8\BP\", $deleteifNecessary=$false)
{

    Get-ChildItem -Path $path -Recurse -Include RoleAssignment*.json |% {


            ## Role Assignments can be done at subscription level only

            [string]$effectiveScope = getScope (get-item $_.PSParentPath)
            Write-Host $effectiveScope
            Write-Host $_.Name

            #$model = "C:\git\bp\MgmtGroup\b2a0bb8e-3f26-47f8-9040-209289b412a8\BP\RoleAssignment-Uday Pandya.json"
            $model = $_.FullName
            $model = get-item $model


            $RoleAssignmentJson = Get-Content -Path $model | Out-String | ConvertFrom-Json

            $_roledefinitionid = (($RoleAssignmentJson.properties.roleDefinitionId -split '/' )  | select -Last 1)
            $_objectid =  $RoleAssignmentJson.properties.principalId   

            $asc_uri= " https://management.azure.com/$effectiveScope/providers/Microsoft.Authorization/roleAssignments?api-version=2018-01-01-preview"
            $asc_requestHeader = @{
                Authorization = "Bearer $(getAccessToken)"
                'Content-Type' = 'application/json'
            }

            $response = Invoke-WebRequest -Uri $asc_uri -Method Get -Headers $asc_requestHeader -UseBasicParsing -ContentType "application/json"
            $JsonObject = ($response.content | ConvertFrom-Json).Value

            $RmRoleAssignment = $JsonObject |? {$_.properties.scope -eq $effectiveScope -and 
                                                ($_.properties.roledefinitionid).contains($_roledefinitionid) -and 
                                                $_.properties.principalId -eq $_objectid}



            if(-not $RmRoleAssignment)
            {

                 Write-Host "Scope: $effectiveScope Missing user " + $_objectid  +  $_roledefinitionid
                 New-AzureRmRoleAssignment -Scope $effectiveScope -ObjectId $_objectid  -RoleDefinitionId  $_roledefinitionid

                
                ##############################################################################
                #Work around until RBAC at managemnt group is inherited to subscriotion level#
                ##############################################################################


                if($effectiveScope.StartsWith('/providers/Microsoft.Management/managementGroups/'))
                {
                    
                    ls -Recurse -Directory -Path  (get-item $_.PSParentPath) |%  {

                            [string]$subscriptionScope = getScope (get-item $_.FullName)
                            if($subscriptionScope.StartsWith('/subscriptions/'))
                            {

                                Write-Host $subscriptionScope
                                Write-Host "Scope: $subscriptionScope Missing user " + $RoleAssignmentJson.properties.principalId   +  $_roledefinitionid
                                New-AzureRmRoleAssignment -Scope $subscriptionScope -ObjectId $RoleAssignmentJson.properties.principalId  -RoleDefinitionId  $_roledefinitionid 

                                #copy Assignment file to Subscirption so that it doesnt get deleted

                                copy $model $_.FullName

                            }

                    }
                    
                }

                <#
                else
                {
            
                    Write-Host "Scope: $effectiveScope Missing user " + $_objectid  +  $_roledefinitionid
                    New-AzureRmRoleAssignment -Scope $effectiveScope -ObjectId $_objectid  -RoleDefinitionId  $_roledefinitionid

                }
                #>
            }
    }


    [array] $effectivepath  = (Get-Item -Path $path)

    $effectivepath += (Get-ChildItem -Path $path -Recurse -Directory)

    $effectivepath  |% {

        $effectiveScope = getscope (get-item $_.Fullname)
        $folderlocation = $_.Fullname

        $asc_uri= " https://management.azure.com/$effectiveScope/providers/Microsoft.Authorization/roleAssignments?api-version=2018-01-01-preview"
        $asc_requestHeader = @{
            Authorization = "Bearer $(getAccessToken)"
            'Content-Type' = 'application/json'
        }

        $response = Invoke-WebRequest -Uri $asc_uri -Method Get -Headers $asc_requestHeader -UseBasicParsing -ContentType "application/json"
        $JsonObject = ($response.content | ConvertFrom-Json).Value
    
        $JsonObject |? { $_.properties.scope -eq $effectiveScope}  |% {

            if($_.properties.principalType -eq 'User' )
            {
            
                $aaduser = (Get-AzureRmADUser -ObjectId $_.properties.principalId).DisplayName
            }
            if($_.properties.principalType -eq 'ServicePrincipal')
            {
                $aaduser = (Get-AzureRmADServicePrincipal -ObjectId $_.properties.principalId).DisplayName
            }

            $roldefinition =  (Get-AzureRmRoleDefinition -id  (($_.properties.roleDefinitionId -split '/' ) | select -Last 1)).Name
            
            $roldefinitionFilePath  = $(join-path  $folderlocation -ChildPath $("RoleAssignment-$aaduser-$roldefinition.json"))
            
            if($deleteifNecessary -and (Test-Path $roldefinitionFilePath) -eq $false)
            {

                Write-Host "Deleting roleAssignments at scope $effectiveScope name: $($_.Name)"
                $asc_uri= " https://management.azure.com/$effectiveScope/providers/Microsoft.Authorization/roleAssignments/$($_.Name)?api-version=2018-01-01-preview"
                Invoke-WebRequest -Uri $asc_uri -Method DELETE -Headers $asc_requestHeader -UseBasicParsing -ContentType "application/json"


                if($effectiveScope.StartsWith('/providers/Microsoft.Management/managementGroups/'))
                {
                    
                    ls -Recurse -Directory -Path  $folderlocation |%  {

                            [string]$subscriptionScope = getScope (get-item $_.FullName)
                            if($subscriptionScope.StartsWith('/subscriptions/'))
                            {
                                Write-Host "(MgmtGroup Nested) Deleting roleAssignments at scope $subscriptionScope name: $($_.Name)"

                                $asc_uri= " https://management.azure.com/$subscriptionScope/providers/Microsoft.Authorization/roleAssignments/$($_.Name)?api-version=2018-01-01-preview"
                                Invoke-WebRequest -Uri $asc_uri -Method DELETE -Headers $asc_requestHeader -UseBasicParsing -ContentType "application/json"


                                if(test-path $(join-path  $_.FullName -ChildPath $("RoleAssignment-$aaduser-$roldefinition.json")))
                                {
                                    remove-item $(join-path  $_.FullName -ChildPath $("RoleAssignment-$aaduser-$roldefinition.json")) -Force -Confirm:$false
                                }
                                
                            }

                    }
                    
                }

            }

            else
            {

                Write-Host "Writing roleAssignments at $roldefinitionFilePath"
                $_ | convertto-json -Depth 10  | out-file -Force -FilePath $roldefinitionFilePath

            }

        } 

    }


}


function Ensure-AzureIaC4VDCRoleDefintion ($path = "C:\git\bp\MgmtGroup\b2a0bb8e-3f26-47f8-9040-209289b412a8\BP\", $deleteifNecessary=$false)
{

    Get-ChildItem -Path $path -Recurse -Include RoleDefintion-*.json |% {

     [string]$effectiveScope = getScope (get-item $_.PSParentPath)
     Write-Host $effectiveScope
     Write-Host $_.Name

     #$model = "C:\git\bp\MgmtGroup\b2a0bb8e-3f26-47f8-9040-209289b412a8\BP\bb81881b-d6a7-4590-b14e-bb3c575e42c5\RoleDefintion-BP App DevOps-u4.json"
     $model = $_.FullName
     $subID = Split-Path (Split-Path $model -Parent) -Leaf

     $RoleDefintionJson = Get-Content -Path $model | Out-String | ConvertFrom-Json
          
     #$RoleDefintionJson | ConvertTo-Json |Out-File -FilePath $model -Force
        
        $RoleDefintion =  Get-AzureRmRoleDefinition -Scope "/subscriptions/$mgmtSubscriptionID"  -Name $RoleDefintionJson.Name 
        if(-not $RoleDefintion)
        {

            #Must be GUID
            $asc_uri= "https://management.azure.com/subscriptions/$mgmtSubscriptionID/providers/Microsoft.Authorization/roleDefinitions/$(New-Guid)?api-version=2018-01-01-preview"           
            $asc_requestHeader = @{
                Authorization = "Bearer $(getAccessToken)"
                'Content-Type' = 'application/json'
            }
    
            $permissions = @()
            $permissions += @{ actions= $($RoleDefintionJson.actions) }

            if($RoleDefintionJson.notActions.Count -eq 0)
            {
                $permissions += (New-object System.Collections.Arraylist)
            }
            else {
                $permissions += @{ notActions= $($RoleDefintionJson.notActions) }
            }
            
            $myObject = [PSCustomObject]@{
                properties= @{
            
                    roleName = $RoleDefintionJson.Name
                    description = $RoleDefintionJson.Description
                    type= "CustomRole"
                    assignableScopes = ($RoleDefintionJson.assignableScopes)
                    permissions = $permissions                                
                }
            }

            #Ensure management subid is present in assignable scopes
            if(-not $myObject.properties.AssignableScopes.Contains( "/subscriptions/$mgmtSubscriptionID"))
            {
                $myObject.properties.AssignableScopes +=  "/subscriptions/$mgmtSubscriptionID"
            }


            if(-not $myObject.properties.AssignableScopes.Contains("$effectiveScope"))
            {
                $myObject.properties.AssignableScopes += $effectiveScope
            }

            Invoke-WebRequest -Uri $asc_uri -Method Put -Headers $asc_requestHeader -Body ($myObject | ConvertTo-Json -Depth 10) -UseBasicParsing -ContentType "application/json"

            $RoleDefintion =  Get-AzureRmRoleDefinition -Scope "/subscriptions/$mgmtSubscriptionID" -Name $RoleDefintionJson.Name 
        }
        #Existing role defintion but new subscription

        ls -Recurse -Directory -Path C:\git\bp\MgmtGroup\b2a0bb8e-3f26-47f8-9040-209289b412a8\BP |%  {
              
              [string]$subscriptionScope = getScope (get-item $_.FullName)
             
              if($subscriptionScope.StartsWith('/subscriptions/'))
              {
                Write-Host $subscriptionScope

                    if(-not $RoleDefintion.AssignableScopes.Contains("$subscriptionScope"))
                    {
                        $RoleDefintion.AssignableScopes += $subscriptionScope
                    }
            
              }

        }

        $updatedRoleDefinition = Set-AzureRmRoleDefinition -Role $RoleDefintion
    
        #Updating rolde defintion file to reflect new scopes
        $updatedRoleDefinition | ConvertTo-Json -Depth 10 | Out-File $model  -Force
     
    }


    #Only focus on AzureRM Roledefinition

    $roledef = Get-AzureRmRoleDefinition  -Scope "/subscriptions/$mgmtSubscriptionID" -Custom
    
    if($roledef -ne $null) 
    {
        $roledef |% {
                
            $RoleDefinitionFileName =  (Join-Path $mgmtSubscriptionPath "RoleDefintion-$($_.Name).json")
                
                
            if($deleteifNecessary -and (Test-Path $RoleDefinitionFileName) -eq $false)
            {

                Write-Host "Deleting RoleDefinition at $RoleDefinitionFileName"
                remove-AzureRmRoleDefinition  -Scope  "/subscriptions/$mgmtSubscriptionID" -Id $_.Id -Confirm:$false -Force 
            }

            else 
            {
                Write-Host "Writing RoleDefinition at $RoleDefinitionFileName"
                $_ | ConvertTo-Json -Depth 10 | Out-File $RoleDefinitionFileName -Force

            }
                
                
        }
                        
                        
    }

    <#

    ##########################################################################
    #We will be statically checking role definition in mgmt subscription only#
    ##########################################################################

    [array] $effectivepath  = (Get-Item -Path $path)
    $effectivepath += (Get-ChildItem -Path $path -Recurse -Directory)
    $effectivepath  |% {

        [string]$effectiveScope = getScope (get-item $_.FullName)
        [string]$localdirectory = $_.FullName

        $roledef = Get-AzureRmRoleDefinition  -Scope $effectiveScope -Custom
        if($roledef -ne $null) 
        {
            $roledef |% {
                
                $RoleDefinitionFileName =  (Join-Path $localdirectory "RoleDefintion-$($_.Name).json")
                
                
                if($deleteifNecessary -and (Test-Path $RoleDefinitionFileName) -eq $false)
                {

                    Write-Host "Deleting RoleDefinition at $RoleDefinitionFileName"
                    remove-AzureRmRoleDefinition  -Scope $effectiveScope -Id $_.Id -Confirm:$false -Force 
                }

                else 
                {
                    Write-Host "Writing RoleDefinition at $RoleDefinitionFileName"
                    $_ | ConvertTo-Json -Depth 10 | Out-File $RoleDefinitionFileName -Force

                }
                
                
            }
                        
                        
        }

    }
    #>


}




function Write-PolicyAssignmentAtScope ($path, $effectiveScope, 
                                        $policydefinitionID, 
                                        $deleteifNecessary = $false)
    {
        #$path = "C:\git\bp\MgmtGroup\b2a0bb8e-3f26-47f8-9040-209289b412a8\BP"
        #$effectiveScope = '/providers/Microsoft.Management/managementGroups/BP-Hub'
        #$effectiveScope = '/subscriptions/0a938bc2-0bb8-4688-bd37-9964427fe0b0'
        #$policydefinitionID = '/providers/Microsoft.Management/managementGroups/BP/providers/Microsoft.Authorization/policyDefinitions/routeTablePolicy'
    
        #write-host  "Scope: $($effectiveScope)$($policydefinitionID)" 
        $asc_uri=  "https://management.azure.com/$effectiveScope/providers/Microsoft.Authorization/policyassignments?api-version=2017-06-01-preview&`$filter=policyDefinitionId eq '$policydefinitionID'"
        $asc_requestHeader = @{
            Authorization = "Bearer $(getAccessToken)"
            'Content-Type' = 'application/json'
        }

        $response =  Invoke-WebRequest -Uri $asc_uri -Method Get -Headers $asc_requestHeader -UseBasicParsing -ContentType "application/json"
        
        $JsonObject = $null
        $JsonObject = ($response.content | ConvertFrom-Json).Value


        $JsonObject |? {$_.properties.scope -eq $effectiveScope} |% {
            

            $policyAssignmentFilename = (join-path  $path -ChildPath $("PolicyAssignment-$($_.name).json"))

                 
            if($deleteifNecessary -and (Test-Path $policyAssignmentFilename) -eq $false)
            {
                 Write-Host "Deleting PolicyAssignmentAtScope at $policyAssignmentFilename"

                 $asc_uri=  "https://management.azure.com/$effectiveScope/providers/Microsoft.Authorization/policyassignments/$($_.Name)?api-version=2017-06-01-preview&`$filter=policyDefinitionId eq '$policydefinitionID'"

                 Invoke-WebRequest -Uri $asc_uri -Method DELETE -Headers $asc_requestHeader -UseBasicParsing -ContentType "application/json"

                
            }
            else
            {
                
                Write-Host "Writing PolicyAssignmentAtScope at $policyAssignmentFilename "
                $_ | convertto-json -Depth 10  | out-file -Force -FilePath $policyAssignmentFilename
            }

            
    
        }
}


function Ensure-AzureIaC4VDCPolicyAssignments ($path = 'C:\git\bp\MgmtGroup\b2a0bb8e-3f26-47f8-9040-209289b412a8\BP\BP-Spoke', 
                                               $effectiveScope = $(getScope $path) ,
                                                $deleteifNecessary = $false)
{

    #CREATE
    
    Get-ChildItem -Path $path -Recurse -Include PolicyAssignment-*.json |% {

        [string]$effectiveScope = getScope (get-item $_.PSParentPath)
        Write-Host $effectiveScope
        Write-Host $_.Name

        #$model =  get-item "C:\git\bp\MgmtGroup\b2a0bb8e-3f26-47f8-9040-209289b412a8\BP\PolicyAssignment-routeTablePolicy.json"
        $model = $_.FullName
        $model = get-item $model

        $PolicyAssignmentJsonName = $model.BaseName.Replace('PolicyAssignment-','')

        $PolicyAssignmentJson = Get-Content -Path $model | Out-String | ConvertFrom-Json

        $PolicyAssignmentJson.Name = $PolicyAssignmentJsonName
        $PolicyAssignmentJson.Properties.scope = $effectiveScope

        #Ensure Policy Definition ID and Scope of an ID is correct

        $sku = @{
                   name= "A1"
                   tier= "Standard"
                 }


         $asc_uri=  "https://management.azure.com/$effectiveScope/providers/Microsoft.Authorization/policyassignments/$($PolicyAssignmentJsonName)?api-version=2017-06-01-preview"
         $asc_requestHeader = @{
                Authorization = "Bearer $(getAccessToken)"
                'Content-Type' = 'application/json'
            }

         Invoke-WebRequest -Uri $asc_uri -Method Put -Headers $asc_requestHeader -Body ($PolicyAssignmentJson | ConvertTo-Json -Depth 10) -UseBasicParsing -ContentType "application/json"

    }


    #SWEEP
    [array] $effectivepath  = (Get-Item -Path $path)

    $effectivepath += (Get-ChildItem -Path $path -Recurse -Directory)

    $effectivepath  |% {

        [string]$effectiveScope = getScope (get-item $_.FullName)
        [string]$localdirectory = $_.FullName

        $asc_uri= "https://management.azure.com/$effectiveScope/providers/Microsoft.Authorization/policyDefinitions?api-version=2018-03-01"
        $asc_requestHeader = @{
            Authorization = "Bearer $(getAccessToken)"
            'Content-Type' = 'application/json'
        }

        $response = Invoke-WebRequest -Uri $asc_uri -Method Get -Headers $asc_requestHeader -UseBasicParsing -ContentType "application/json"
        $policyDefinitions = ($response.content | ConvertFrom-Json).Value
    
 
        $policyDefinitions |% {

            write-host  "Scope: $($effectiveScope)/$($_.properties.displayName)" 
            Write-PolicyAssignmentAtScope -path (get-item $localdirectory) -effectiveScope $effectiveScope -policydefinitionID $_.id -deleteifNecessary:$deleteifNecessary
    
        } 

    }


}


function Ensure-AzureIaC4VDCPolicyDefinitions ($path = 'C:\git\bp\MgmtGroup\b2a0bb8e-3f26-47f8-9040-209289b412a8\BP\BP-Spoke', $effectiveScope = $(getScope $path), $deleteifNecessary = $false)
{

    Get-ChildItem -Path $path -Recurse -Include PolicyDefintion-*.json |% {

         [string]$effectiveScope = getScope (get-item $_.PSParentPath)
         Write-Host $effectiveScope
         Write-Host $_.Name

         #$model =  get-item "C:\git\bp\MgmtGroup\b2a0bb8e-3f26-47f8-9040-209289b412a8\BP\PolicyDefintion-routeTablePolicy.json"
         $model = $_.FullName
         $model = get-item $model

         $PolicyDefintionJson = Get-Content -Path $model | Out-String | ConvertFrom-Json
         $PolicyDefintionJsonName = $model.BaseName.Replace('PolicyDefintion-','')
     
         $PolicyDefintionJson.Name = $PolicyDefintionJsonName
         $PolicyDefintionJson.Properties.displayName = $PolicyDefintionJsonName
     
         if (( Get-Member -InputObject $PolicyDefintionJson -Name id1) -ne $null)
         {
             $PolicyDefintionJson  | Add-member  -MemberType NoteProperty -Name id -Value ''
         }
    
     
         $PolicyDefintionJson.id =  "$effectiveScope/providers/Microsoft.Authorization/policyDefinitions/$PolicyDefintionJsonName"

   
         $PolicyDefintion =  Get-AzureRmPolicyDefinition  |? {   $_.Properties.policytype -eq 'custom'-and `
                                                                $($_.ResourceId).contains($effectiveScope) -and `
                                                                $_.Name -eq $PolicyDefintionJsonName}
    
         $PolicyDefintionJson.Name = $PolicyDefintionJsonName  

        
        $asc_uri= "https://management.azure.com/$effectiveScope/providers/Microsoft.Authorization/policyDefinitions/$($PolicyDefintionJsonName)?api-version=2018-03-01"
        $asc_requestHeader = @{
            Authorization = "Bearer $(getAccessToken)"
            'Content-Type' = 'application/json'
        }

        Invoke-WebRequest -Uri $asc_uri -Method Put -Headers $asc_requestHeader -Body ($PolicyDefintionJson | ConvertTo-Json -Depth 10) -UseBasicParsing -ContentType "application/json"
        
    }


    [array] $effectivepath  = (Get-Item -Path $path)

    $effectivepath += (Get-ChildItem -Path $path -Recurse -Directory)

    $effectivepath    |% {


        [string]$effectiveScope = getScope (get-item $_.FullName)
        [string]$localdirectory = $_.FullName

        $asc_uri= "https://management.azure.com/$effectiveScope/providers/Microsoft.Authorization/policyDefinitions?api-version=2018-03-01"
        $asc_requestHeader = @{
            Authorization = "Bearer $(getAccessToken)"
            'Content-Type' = 'application/json'
        }

        $response = Invoke-WebRequest -Uri $asc_uri -Method Get -Headers $asc_requestHeader -UseBasicParsing -ContentType "application/json"
        $JsonObject = ($response.content | ConvertFrom-Json).Value
    
 
        $JsonObject|? {$_.properties.policyType -ne 'BuiltIn' -and $_.id.Contains($effectiveScope)} |% {

             $policyDefinitionName = $null
             $policyDefinitionName = $_.properties.displayName
             
             if($policyDefinitionName -eq $null)
             {
                $policyDefinitionName =  $_.Name
             }

             $policyDefinitionFilePath =  $(join-path  $localdirectory -ChildPath $("PolicyDefintion-$policyDefinitionName.json"))

                
            if($deleteifNecessary -and (Test-Path $policyDefinitionFilePath) -eq $false)
            {
                
                    Write-Host "Deleting policyDefinitions at scope $effectiveScope name: $($_.Name)"

                    $asc_uri= "https://management.azure.com/$effectiveScope/providers/Microsoft.Authorization/policyDefinitions/$($_.Name)?api-version=2018-03-01"

                    Invoke-WebRequest -Uri $asc_uri -Method DELETE -Headers $asc_requestHeader -UseBasicParsing -ContentType "application/json"

            }
            else
            {
                 Write-Host "Writing Policy at  $policyDefinitionFilePath"
                 $_ | convertto-json -Depth 10  | out-file -Force -FilePath $policyDefinitionFilePath


            }


        } 

    }
}


function Ensure-AzureIaC4VDCMgmtandSubscriptions($path = 'C:\git\bp\MgmtGroup', $deleteifNecessary = $false)
{

    <#
    $mgmtGroupList =  (Get-AzureRmManagementGroup)

    ls -Recurse -Directory -Path $path |%    {

        $effectiveScope = getScope $_.fullname

        $currentScope = $_

        if($effectiveScope.StartsWith('/providers/Microsoft.Management/managementGroups/'))
        {

            $mgmtGroup = $mgmtGroupList |? {$_.Name -eq $currentScope.BaseName }
            $mgmtGroup


            if($mgmtGroup -eq $null )
            {
                New-AzureRmManagementGroup -GroupName $_.basename -DisplayName $_.basename -ParentId (getScope ($_.parent).BaseName) -Confirm:$false
                
            }
            
            $mgmtGroup =  (Get-AzureRmManagementGroup -GroupName ($_.Basename) -Expand)


            if($mgmtGroup.ParentId  -ne $null)
            {

                if  ($mgmtGroup.ParentId -ne (getscope ($_.Parent).FullName) )
                {
                    Update-AzureRmManagementGroup -GroupName $mgmtGroup.Name -ParentId (getscope($_.Parent).FullName) 
                }
            }
        

        }
        

    }
    #>

    
    Get-AzureRMManagementGroup |% { 

        $mgmtGroup =   Get-AzureRMManagementGroup -Expand  -GroupName $_.Name 
        
        #$mgmtGroup =   Get-AzureRMManagementGroup -Expand  -GroupName "BP"
        

        $mgmtGroup

        if ($mgmtGroup.ParentId -eq $null)
        {
            #Root Mgmt Group
            mkdir ($mgmtGroup.id -split '/' | select -Last 1) -Force | out-null
            [string] $basepath =  "." + "\" 
        }

        else
        {

            #Does my parent exists?

            $parentMgmtGroup = ls $path -Recurse -Directory -Filter ($mgmtGroup.ParentId  -split '/' | select -Last 1)

            if(-not $parentMgmtGroup)
            {
                mkdir (($mgmtGroup.ParentId -split '/' | select -Last 1) +"\" + ($mgmtGroup.id -split '/' | select -Last 1)) -Force | out-null

                $parentMgmtGroup = ls $path -Recurse -Directory -Filter ($mgmtGroup.ParentId  -split '/' | select -Last 1)


            }
            else
            {
                Write-host "Existing Directory Found at : " + $parentMgmtGroup.FullName

                
            }

            [string] $basepath = ($parentMgmtGroup.FullName.ToString() +"\").Trim()
            $basepath

        }

         
        $mgmtGroup.Children |% {

            $childId =  ($_.ChildId -split '/' | select -Last 1)
            $childId

            if($childId -ne '')
            {

                $childMgmtGroup = ls $path -Recurse -Directory -Filter ($_.ChildId -split '/' | select -Last 1)
                $childllocation = ( $basepath + "\" + ($mgmtGroup.id -split '/' | select -Last 1))
        
                if(-not $childMgmtGroup)
                {
                    #Creating Children

                    Write-host $basepath
                    Write-host ($mgmtGroup.id -split '/' | select -Last 1)
                    Write-host $childId
        
                    mkdir (Join-Path $childllocation  -ChildPath $childId) -Force | out-null

                }
                else
                {
                    Write-host "Existing Children Found at : " + $childMgmtGroup.FullName

                    $source = $childMgmtGroup.FullName
                   

                    if(Test-Path -Path $childllocation\$childId)
                    {
                        Write-Host "Child is already at right location $childllocation\$ch"
                    }
                    else
                    {
                        #Moving Orphan child
                        move-item -Path $source -Destination $childllocation
                    }
                }

                if($_.ChildType -eq '/subscription')
                {
                    write-host "Susbscription Found $childId"

                   

                }
            }

        }
    
    $basepath =  ""
  
    }                 
    
}



function Ensure-AzureIaC4VDCTemplateDeployment ($path = 'C:\git\bp\MgmtGroup', $deleteifNecessary = $false)
{

    Get-ChildItem -Path $path -Recurse -Include Deployment-*.json -Exclude *.parameters.json |% {

        [string]$effectiveScope = getScope (get-item $_.PSParentPath)
        Write-Host $effectiveScope
        Write-Host $_.Name

        if($effectiveScope.StartsWith('/subscriptions/'))
        {

            #$model =  get-item "C:\git\bp\MgmtGroup\b2a0bb8e-3f26-47f8-9040-209289b412a8\BP\BP-Spoke\Deployment-westsu2-101-vnet-two-subnets.json"
            
            $model = get-item $_.FullName
            $tempalteParameterFile =   join-path $_.Directory.FullName "$($model.BaseName).parameters.json"
          

            $location = ($model.BaseName).Split('-')[1]
            $rgname = ($model.BaseName).Replace("Deployment-$location-",'')

            $asc_uri= "https://management.azure.com/$effectiveScope/resourcegroups/$($rgname)?api-version=2017-05-10"
            $asc_requestHeader = @{
                Authorization = "Bearer $(getAccessToken)"
                'Content-Type' = 'application/json'
            }

            Invoke-WebRequest -Uri $asc_uri -Method Put -Headers $asc_requestHeader -Body $('{ "location" : "' + $($location) + '"}') -UseBasicParsing -ContentType "application/json"


            $templateDefinitionJson = Get-Content -Path $model | Out-String | ConvertFrom-Json
            $templateDefinitionParametersJson = Get-Content -Path $tempalteParameterFile | Out-String | ConvertFrom-Json

           
            $myObject = [PSCustomObject]@{
                properties= @{
            
                    template =  $templateDefinitionJson
                    parameters = $templateDefinitionParametersJson.parameters
                    mode = "Incremental"                   
                }
            }


            $asc_uri= "https://management.azure.com/$effectiveScope/resourcegroups/$($rgname)/providers/Microsoft.Resources/deployments/$($model.BaseName)?api-version=2017-05-10"
            $asc_requestHeader = @{
                Authorization = "Bearer $(getAccessToken)"
                'Content-Type' = 'application/json'
            }

            Invoke-WebRequest -Uri $asc_uri -Method Put -Headers $asc_requestHeader -Body ($myObject | ConvertTo-Json -Depth 10) -UseBasicParsing -ContentType "application/json"


            #New-AzureRmResourceGroupDeployment -Name $model.BaseName -ResourceGroupName $rgname -Mode Incremental `
            #        -TemplateParameterFile $tempalteParameterFile `
            #        -TemplateFile $model -Debug

            #New-AzureRmResourceGroupDeployment -Name test -ResourceGroupName

        }
        else
        {

            #Mgmt Group

            Get-ChildItem -Recurse -Path $_.PSParentPath -Directory |% {



           }

        }


    }
     

}

#cd C:\git\bp\MgmtGroup

$mgmtSubscriptionID = 'bb81881b-d6a7-4590-b14e-bb3c575e42c5'

#$path = "C:\git\bp\MgmtGroup\b2a0bb8e-3f26-47f8-9040-209289b412a8\BP"
$path = "$pwd\MgmtGroup"

Write-Host "Using Current Path: $path"


Import-Module $pwd\Common.psm1


#$mgmtSubscriptionPath = Join-Path "C:\git\bp\MgmtGroup\b2a0bb8e-3f26-47f8-9040-209289b412a8\BP" "$mgmtSubscriptionID"
$mgmtSubscriptionPath = Join-Path "$pwd\MgmtGroup\bp" "$mgmtSubscriptionID"

$falgDeleteIfNecessary = $false


Ensure-AzureIaC4VDCMgmtandSubscriptions -path $path


#Ensure-AzureIaC4VDCRoleDefintion  -path $path -deleteifNecessary:$true
#Ensure-AzureIaC4VDCRoleAssignment  -path $path -deleteifNecessary:$true

#Ensure-AzureIaC4VDCPolicyDefinitions -path $path -deleteifNecessary:$true
#Ensure-AzureIaC4VDCPolicyAssignments -path $path -deleteifNecessary:$true

#Ensure-AzureIaC4VDCTemplateDeployment -path $path
