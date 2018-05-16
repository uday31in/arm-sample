Get-Module -ListAvailable
Write-host "Version of AzureRM.Profile Loaded in Session"
get-module

#Update-Module -Name AzureRM -Force -AllowPrerelease -Confirm:$false
$ascpricingtierconfig = @"
{
"properties":  {
                    "policyLevel":  "Subscription",
                    "name":  "default",
                    "unique":  "Off",
                    "logCollection":  "On",
                    "recommendations":  {
                                            "patch": "On",
			                                "baseline": "On",
			                                "antimalware": "On",
			                                "diskEncryption": "On",
			                                "acls": "On",
			                                "nsgs": "On",
			                                "waf": "On",
			                                "sqlAuditing": "On",
			                                "sqlTde": "On",
			                                "ngfw": "On",
			                                "vulnerabilityAssessment": "On",
			                                "storageEncryption": "On",
			                                "jitNetworkAccess": "On",
			                                "appWhitelisting": "On"
                                        },
                    "logsConfiguration":  {
                                                "storages":  {

                                                            }
                                            },
                    
                    "omsWorkspaceConfiguration": {
			            "workspaces": {}
		            },
                    "securityContactConfiguration":  {
                                                        "securityContactEmails":  [
                                                                                        "uday.pandya@microsoft.com",
                                                                                        "hello@world.com"
                                                                                    ],
                                                        "securityContactPhone":  "867-5309",
                                                        "areNotificationsOn":  true,
                                                        "sendToAdminOn":  false
                                                    },
                    "pricingConfiguration":  {
                                                "resourceGroup": "",
			                                    "active": "On",
			                                    "level": "Subscription",
			                                    "selectedPricingTier": "Standard",
			                                    "standardTierStartDate": "2018-05-09T18:23:38",
			                                    "premiumTierStartDate": "0001-01-01T00:00:00"
                                            }
                    
                }
}
"@

<#

if (Get-Module -ListAvailable -Name AzureRM.ManagementGroups) {
    Write-Host "Module exists - ManagementGroups"
} else {
   
   Remove-Module -Name AzureRM.Profile -Force
   Install-PackageProvider -Name NuGet -Force -Scope CurrentUser
   Install-Module -Name AzureRM.ManagementGroups -Force -Verbose -Scope CurrentUser -AllowPrerelease
   
}

if (Get-Module -ListAvailable -Name AzureRM.Subscription) {
    Write-Host "Module exists - Subscription"
} else {

   Install-Module -Name AzureRM.Subscription -Force -Verbose -Scope CurrentUser -AllowPrerelease
   
}

if (Get-Module -ListAvailable -Name AzureRM.Billing) {
    Write-Host "Module exists - Billing"
} else {

  
   Install-Module -Name Azurerm.Billing -Force -Verbose -Scope CurrentUser -AllowPrerelease
   
}

Import-Module AzureRM.ManagementGroups -Force
#>





if($AzureRmManagementGroup -eq $null )
{

    $global:AzureRmManagementGroup = (Get-AzureRmManagementGroup) |% { Get-AzureRmManagementGroup -GroupName $_.Name -Expand } 

    $AzureRmManagementGroup |% {

        Write-Host "Mgmt Group Name: $($_.Name) ID: $($_.Id)"

    }

}



function Get-ScriptDirectory { Split-Path $MyInvocation.ScriptName }

function getScope([System.io.DirectoryInfo] $name)
{

    [string ]$scope = ( $name.BaseName) -ireplace ('Mgmt-', '') -ireplace ('Sub-', '')
    $_mgmtgroup = $AzureRmManagementGroup |? {  ($_.Name -eq $scope -or $_.DisplayName -eq $scope -or $_.id -eq "/providers/Microsoft.Management/managementGroups/$scope" ) -and
                                                ($_.Type -eq '/providers/Microsoft.Management/managementGroups')
                                             } 

    #Search Mgmt Group First
    if($_mgmtgroup -ne $null)
    {

        return ($_mgmtgroup.Id).trim()

    }

     #Search for Subscription
     $_subscription = ($AzureRmManagementGroup.Children |? {  ($_.DisplayName -eq $scope -or $_.ChildId -eq "/subscriptions/$scope") -and
                                                              ($_.ChildType -eq '/subscription')
                                                           })
     if($_subscription -ne $null)
     {
        return ($_subscription.ChildId).trim()
    
     }

     #search for Resource Group
     if(    ($name.name -ne 'nestedtemplates') -and
            ((getScope $name.Parent.Name).startswith('/subscriptions') -eq $true)
        )
      {
             return "$(getScope ($name.Parent.Name))/resourcegroups/$($scope)"
             
      }


}


function getNamebyID([string] $id)
{
    $_mgmtgroup = $AzureRmManagementGroup |? {  ($_.id -eq $id ) -and
                                                ($_.Type -eq '/providers/Microsoft.Management/managementGroups')
                                             } 

    #Search Mgmt Group First
    if($_mgmtgroup -ne $null)
    {

        return ($_mgmtgroup.DisplayName).trim()

    }

     #Search for Subscription
     $_subscription = ($AzureRmManagementGroup.Children |? {  ($_.ChildId -eq $id) -and
                                                              ($_.ChildType -eq '/subscription')
                                                           })


     if($_subscription -ne $null)
     {
        return ($_subscription.DisplayName).trim()
    
     }
    
    
}



function getParentbyID([string] $id)
{
    #Search Mgmt Group First
    $_mgmtgroup = $AzureRmManagementGroup |? {  ($_.id -eq $id ) -and
                                                ($_.Type -eq '/providers/Microsoft.Management/managementGroups')
                                             } 

    if($_mgmtgroup -ne $null)
    {

        if($_mgmtgroup.ParentId -ne $null)
        {
            return ($_mgmtgroup.ParentId).trim()
        }

    }

     #Search for Subscription
     $_mgmtgroup = ($AzureRmManagementGroup |? {  ($_.Children.ChildId -eq $id) -and
                                                     ($_.Children.ChildType -eq '/subscription')
                                                  })

    if($_mgmtgroup -ne $null)
    {

        return ($_mgmtgroup.id).trim()

    }
    
    
}


function getAllManagementGroupBelowScope ([string] $id)
{
    $_mgmtgroup = $AzureRmManagementGroup |? {  ($_.id -eq $id ) }
    
    $_mgmtgroup.children |? {  ($_.ChildType -eq '/managementGroup')} |% {   

        #getAllManagementGroupBelowScope $_.ChildID
    }
   
    return ($_mgmtgroup.children |? {  ($_.ChildType -eq '/managementGroup')}).ChildID
 
}

function getAllManagementGroupBelowScopeRecursive ([string] $id)
{
    $_mgmtgroup = $AzureRmManagementGroup |? {  ($_.id -eq $id ) }
    
    $_mgmtgroup.children |? {  ($_.ChildType -eq '/managementGroup')} |% {   

        getAllManagementGroupBelowScope $_.ChildID
    }
   
    return ($_mgmtgroup.children |? {  ($_.ChildType -eq '/managementGroup')}).ChildID
 
}



function getAllSubscriptionBelowScope ([string] $id)
{
    $_mgmtgroup = $AzureRmManagementGroup |? {  ($_.id -eq $id ) }
    
    [array] $children = ($_mgmtgroup.children |? {  ($_.ChildType -eq '/subscription')})

    if ($children -ne $null)
    {
        return $children.ChildID
    }
    else
    {
        return $null
    }
    
 
}




function getAccessToken()
{
    $azureRmProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $currentAzureContext = Get-AzureRmContext 
    $profileClient = New-Object Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient($azureRmProfile)
    Write-Verbose "Getting access token"
    Write-Debug ("Getting access token for tenant" + $currentAzureContext.Subscription.TenantId)
    $token = $profileClient.AcquireAccessToken($currentAzureContext.Subscription.TenantId)
    $token = $token.AccessToken
    return  $token

}

#Login as the Account Admin

#Login-AzureRmAccount

# Parameters being passed from Payload
<#
$subscriptionName = "BP-Spoke-NE"
$SubscriptionDisplayName = "BP Spoke for North Europe"
$ManagementGroupName = "BP-Spoke"
#>

function New-AzureIaC4VdcSubsriptionProvisioning(    $subscriptionName = "BP Hub for North Europe", 
                                                     $SubscriptionDisplayName = "BP Hub for North Europe",
                                                     $ManagementGroupName = "BP-Hub",
                                                     $offerType = "MS-AZR-0017P",
                                                     $EnrollmentAccountObjectId = 'b38a3dad-9e2d-4ed7-81be-6851bc292fa9'
                                                 )
{
        $managementGrpName= $ManagementGroupName

        $vstsAAObjectID = (Get-AzureRmADServicePrincipal -SearchString 'iaac4dcm-cd4dcm-bb81881b-d6a7-4590-b14e-bb3c575e42c5').Id

        $subscription = Get-AzureRmSubscription -SubscriptionName "$subscriptionName" -ErrorAction SilentlyContinue

        if($subscription -eq $null)
        {
                        
            Write-Host "Creating new subscription"

            $subscription = New-AzureRmSubscription -Name $subscriptionName -OfferType $offerType -OwnerObjectId $vstsAAObjectID -EnrollmentAccountObjectId (Get-AzureRmEnrollmentAccount)[0].ObjectId

            #$subscription = New-AzureRmSubscriptionDefinition  -Name $subscriptionName  -OfferType $offerType -SubscriptionDisplayName $SubscriptionDisplayName
            Write-Host "Creating new subscription Success!"


            # Assign Subscription to its Management Group .
            # $subscription =Get-AzureRmSubscriptionDefinition -Name $subscriptionName1
            #New-AzureRmManagementGroupSubscription -GroupName $ManagementGroupName -SubscriptionId $subscription.SubscriptionId
        }
        else
        {

             Write-Host "Existing subscription found with ID: $($subscription.Id) Name: $($subscription.Name)"
        }



        $asconfig = @{
             Uri = "https://management.azure.com/subscriptions/$($subscription.SubscriptionId)/providers/Microsoft.Security/register?api-version=2017-05-10"
             Headers = @{
                   Authorization = "Bearer $(getAccessToken)"
                   'Content-Type' = 'application/json'
                   }
                   Method = 'POST'
                   UseBasicParsing = $true
                   Body = ""
                }

        Invoke-WebRequest @asconfig

        #FIX - Subscription not registered
        #Register-AzureRmResourceProvider -ProviderNamespace Microsoft.Security -Debug

        Write-Host "Waiting for 60 seconds to finish registering Microsoft.Security namespaces"
        Start-Sleep -Seconds 60
        Write-Host "Complete! Waiting for 60 seconds to finish registering Microsoft.Security namespaces"
        
        $body = @{

            properties= @{

                workspaceId = "/subscriptions/926ab52d-a877-4db3-b0f9-2e9f8ecbe4c4/resourcegroups/bp-azure-oms/providers/microsoft.operationalinsights/workspaces/bp-ws-1000"
                scope = "/subscriptions/$($subscription.SubscriptionId)"
            }
        } | ConvertTo-Json


        $asconfig = @{
             Uri = "https://management.azure.com/subscriptions/$($subscription.SubscriptionId)/providers/Microsoft.Security/workspaceSettings/default?api-version=2017-08-01-preview"
             Headers = @{
                   Authorization = "Bearer $(getAccessToken)"
                   'Content-Type' = 'application/json'
                   }
                   Method = 'Put'
                   UseBasicParsing = $true
                   Body = $body
                }

        Invoke-WebRequest @asconfig


}

function Ensure-AzureIaC4VDCRoleAssignment ($path = "C:\git\bp\MgmtGroup\b2a0bb8e-3f26-47f8-9040-209289b412a8\BP\", $deleteifNecessary=$false)
{

    Get-ChildItem -Path $path -Recurse -Include RoleAssignment*.json |% {


            ## Role Assignments can be done at subscription level only

            Write-Host "----------------------------------------------------------------"

            [string]$effectiveScope = getScope (get-item $_.PSParentPath)
            Write-Host $effectiveScope
            Write-Host $_.FullName

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

            write-host "Retriving Role Assignments: $asc_uri"

            $response = Invoke-WebRequest -Uri $asc_uri -Method Get -Headers $asc_requestHeader -UseBasicParsing -ContentType "application/json"
            $JsonObject = ($response.content | ConvertFrom-Json).Value

            $RmRoleAssignment = $JsonObject |? {$_.properties.scope -eq $effectiveScope -and 
                                                ($_.properties.roledefinitionid).contains($_roledefinitionid) -and 
                                                  $_.properties.principalId -eq $_objectid}

            write-host "Retriving Role Assignments Successfully: $RmRoleAssignment"

            if(-not $RmRoleAssignment)
            {

                              
                ##############################################################################
                #Work around until RBAC at managemnt group is inherited to subscriotion level#
                ##############################################################################


                if($effectiveScope.StartsWith('/providers/Microsoft.Management/managementGroups/'))
                { 
                    <#
                    ls -Recurse -Directory -Path  (get-item $_.PSParentPath) |%  {

                            
                            [string]$subscriptionScope = getScope (get-item $_.FullName)
                                                    
                            
                            if($subscriptionScope.StartsWith('/subscriptions/'))
                            {
                             
                                Write-Host "Get-AzureRmRoleAssignment -Scope $subscriptionScope -ObjectId $($RoleAssignmentJson.properties.principalId)  -RoleDefinitionId  $_roledefinitionid"
                                
                                #$DebugPreference="Continue"
                                $assignment = Get-AzureRmRoleAssignment -Scope $subscriptionScope -ObjectId $RoleAssignmentJson.properties.principalId  -RoleDefinitionId  $_roledefinitionid 

                                Write-Host "subscriptionScope: $subscriptionScope assignment: $assignment"

                                if($assignment -eq $null)
                                {
                                    Write-Host "Missing AzureRmRoleAssignment for Scope: New-AzureRmRoleAssignment -Scope $subscriptionScope -ObjectId $($RoleAssignmentJson.properties.principalId)  -RoleDefinitionId  $_roledefinitionid " 
                                    
                                    Get-AzureRmContext
                                    New-AzureRmRoleAssignment -Scope $subscriptionScope -ObjectId $RoleAssignmentJson.properties.principalId  -RoleDefinitionId  $_roledefinitionid 

                                    

                                }
                                #copy Assignment file to Subscirption so that it doesnt get deleted

                                copy $model $_.FullName -Force

                            }

                    }
                    #>
                   
                    
                }

                
                else
                {
            
                    Write-Host "Line 389. Get-AzureRmRoleAssignment -Scope $effectiveScope -ObjectId $_objectid  -RoleDefinitionId  $_roledefinitionid"

                    $assignment  = Get-AzureRmRoleAssignment -Scope $effectiveScope -ObjectId $_objectid  -RoleDefinitionId  $_roledefinitionid
                    if($assignment -eq $null)
                    {
                        Write-Host "calling New-AzureRmRoleAssignment -Scope $effectiveScope -ObjectId $_objectid  -RoleDefinitionId  $_roledefinitionid"
                        New-AzureRmRoleAssignment -Scope $effectiveScope -ObjectId $_objectid  -RoleDefinitionId  $_roledefinitionid
                        Write-Host "Success! New-AzureRmRoleAssignment -Scope $effectiveScope -ObjectId $_objectid  -RoleDefinitionId  $_roledefinitionid"
                    }
                    

                }
                
            }
            Write-Host "Success! $($_.FullName)"
    }

    Write-Host "***********************************************"
    Write-host "AzureIaC4VDCRoleAssignment - Push Completed"
    Write-Host "***********************************************"

    [array] $effectivepath  = (Get-Item -Path $path)
    $effectivepath += (Get-ChildItem -Path $path -Recurse -Directory)

    $effectivepath  |% {

        $effectiveScope = getscope (get-item $_.Fullname)

        if($effectiveScope -ne $null)
        {

            $folderlocation = $_.Fullname

            $asc_uri= " https://management.azure.com/$effectiveScope/providers/Microsoft.Authorization/roleAssignments?api-version=2018-01-01-preview"
            $asc_requestHeader = @{
                Authorization = "Bearer $(getAccessToken)"
                'Content-Type' = 'application/json'
            }

            Write-Host "Evaulting Effective Path: $folderlocation"
            Write-Host "Retriving Role Assignment from $asc_uri"

            $response = Invoke-WebRequest -Uri $asc_uri -Method Get -Headers $asc_requestHeader -UseBasicParsing -ContentType "application/json"
            $JsonObject = ($response.content | ConvertFrom-Json).Value
    
                                                                                                                                                                                                                    $JsonObject |? { $_.properties.scope -eq $effectiveScope}  |% {

            #Write-Host "Get-AzureRmADUser -ObjectId $($_.properties.principalId)"

            if($_.properties.principalType -eq 'User' )
            {
            
                $aaduser = (Get-AzureRmADUser -ObjectId $_.properties.principalId).DisplayName
            }
            if($_.properties.principalType -eq 'ServicePrincipal')
            {
                $aaduser = (Get-AzureRmADServicePrincipal -ObjectId $_.properties.principalId).DisplayName
            }

            $roldefinition =  (Get-AzureRmRoleDefinition -id  (($_.properties.roleDefinitionId -split '/' ) | select -Last 1)).Name
            
            $roldefinitionFilePath  = $(join-path  $folderlocation -ChildPath $("RoleAssignment-$($aaduser)-$roldefinition.json"))
            
            
            if($deleteifNecessary -and (Test-Path $roldefinitionFilePath) -eq $false)
            {

                Write-Host "Deleting roleAssignments at scope $effectiveScope name: $($_.Name)"
                $asc_uri= " https://management.azure.com/$effectiveScope/providers/Microsoft.Authorization/roleAssignments/$($_.Name)?api-version=2018-01-01-preview"
                Invoke-WebRequest -Uri $asc_uri -Method DELETE -Headers $asc_requestHeader -UseBasicParsing -ContentType "application/json"


                if($effectiveScope.StartsWith('/providers/Microsoft.Management/managementGroups/'))
                {
                    <#

                    #######################################################################################
                    #Disabling Subscription level deleteion when RBAC is removed at Management group level#
                    #######################################################################################
                    
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
                    #>
                }

            }

            else
            {

                Write-Host "Writing roleAssignments at $roldefinitionFilePath"
                $_ | convertto-json -Depth 100   | % { [System.Text.RegularExpressions.Regex]::Unescape($_) } | out-file -Force -FilePath $roldefinitionFilePath

            }

        } 

            Write-Host "Success! Retriving Role Assignment from $asc_uri"
        }
    }


}


function Ensure-AzureIaC4VDCRoleDefinition ( $path = "C:\git\bp\MgmtGroup\b2a0bb8e-3f26-47f8-9040-209289b412a8\BP\", 
                                            $deleteifNecessary=$false,
                                            $mgmtSubscriptionID = "",
                                            $mgmtSubscriptionPath = "")
{
     #In Theory Roledefintion should only be specified in management subscription level only.
     Get-ChildItem -Path $path -Recurse -Include RoleDefinition-*.json |% {

     [string]$effectiveScope = getScope (get-item $_.PSParentPath)
     Write-Host $effectiveScope
     Write-Host $_.FullName

    #Excluding resource group - 
    if($effectiveScope.Contains('/resourcegroups/') -eq $false)
    {

         #$model = "C:\git\bp\MgmtGroup\b2a0bb8e-3f26-47f8-9040-209289b412a8\BP\bb81881b-d6a7-4590-b14e-bb3c575e42c5\RoleDefintion-BP App DevOps-u4.json"
         $model = $_.FullName
         $subID = Split-Path (Split-Path $model -Parent) -Leaf

         $RoleDefintionJson = Get-Content -Path $model | Out-String | ConvertFrom-Json
          
         #$RoleDefintionJson | ConvertTo-Json |Out-File -FilePath $model -Force
        
            Write-Host "Get-AzureRmRoleDefinition -Scope /subscriptions/$mgmtSubscriptionID -Name $($RoleDefintionJson.Name)"

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

                Invoke-WebRequest -Uri $asc_uri -Method Put -Headers $asc_requestHeader -Body ($myObject | ConvertTo-Json -Depth 100) -UseBasicParsing -ContentType "application/json"

                $RoleDefintion =  Get-AzureRmRoleDefinition -Scope "/subscriptions/$mgmtSubscriptionID" -Name $RoleDefintionJson.Name 

                Write-Host "Role Definition Created Successfully at scope /subscriptions/$mgmtSubscriptionID"
            }
            
            #Existing role defintion but new subscription
            ls -Recurse -Directory -Path $path |%  {
              
                  [string]$subscriptionScope = getScope (get-item $_.FullName)
             
                  if( 
                        ($subscriptionScope.StartsWith('/subscriptions/')) -and 
                        ($subscriptionScope.Contains('/resourcegroups/') -eq $false)
                    )
                  {
                        Write-Host "Adding $subscriptionScope to existing $($RoleDefintion.name)"

                        if(-not $RoleDefintion.AssignableScopes.Contains("$subscriptionScope"))
                        {
                            $RoleDefintion.AssignableScopes += $subscriptionScope
                        }
            
                  }

            }

            $updatedRoleDefinition = Set-AzureRmRoleDefinition -Role $RoleDefintion
            Write-Host "Role Definition Updated Successfully at scope /subscriptions/$mgmtSubscriptionID"
    
            #Updating rolde defintion file to reflect new scopes
            $updatedRoleDefinition | ConvertTo-Json -Depth 100  | % { [System.Text.RegularExpressions.Regex]::Unescape($_) } | Out-File $model  -Force
            Write-Host "Updated Role Definition at scope $model"
     
        }

    }


    #Only focus on AzureRM Roledefinition in managment subscription
    $roledef = Get-AzureRmRoleDefinition  -Scope "/subscriptions/$mgmtSubscriptionID" -Custom
    
    if($roledef -ne $null) 
    {
        $roledef |% {
                
            $RoleDefinitionFileName =  (Join-Path $mgmtSubscriptionPath "RoleDefinition-$($_.Name).json")
                
                
            if($deleteifNecessary -and (Test-Path $RoleDefinitionFileName) -eq $false)
            {

                Write-Host "Deleting RoleDefinition at $RoleDefinitionFileName"
                remove-AzureRmRoleDefinition  -Scope  "/subscriptions/$mgmtSubscriptionID" -Id $_.Id -Confirm:$false -Force 
            }

            else 
            {
                Write-Host "Writing RoleDefinition at $RoleDefinitionFileName"
                $_ | ConvertTo-Json -Depth 100  | % { [System.Text.RegularExpressions.Regex]::Unescape($_) } | Out-File $RoleDefinitionFileName -Force

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
                    $_ | ConvertTo-Json -Depth 100 | Out-File $RoleDefinitionFileName -Force

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
    
        write-host  "Scope: $($effectiveScope)$($policydefinitionID)" 

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
                $_ | convertto-json -Depth 100  | % { [System.Text.RegularExpressions.Regex]::Unescape($_) }  | out-file -Force -FilePath $policyAssignmentFilename
            }

            
    
        }
}


function Ensure-AzureIaC4VDCPolicyAssignments ($path = 'C:\git\bp\MgmtGroup\b2a0bb8e-3f26-47f8-9040-209289b412a8\BP\BP-Spoke', 
                                               $effectiveScope = $(getScope $path) ,
                                                $deleteifNecessary = $false,
                                                $recurse = $true )
{

    #CREATE
    Write-host "Using Path: $path"

    if($recurse)
    {

        $PolicyAssignmentFileList = Get-ChildItem -Path $path -Recurse -Include PolicyAssignment-*.json
    }
    else
    {
        $PolicyAssignmentFileList = Get-ChildItem -Path $path  -Filter PolicyAssignment-*.json
    }
    
    $PolicyAssignmentFileList |% {

        [string]$effectiveScope = getScope (get-item $_.PSParentPath)
        Write-Host $effectiveScope
        Write-Host $_.FullName

        #$model =  get-item "C:\git\bp\MgmtGroup\b2a0bb8e-3f26-47f8-9040-209289b412a8\BP\PolicyAssignment-routeTablePolicy.json"
        $model = $_.FullName
        $model = get-item $model

        $PolicyAssignmentJsonName = $model.BaseName.Replace('PolicyAssignment-','')

        $PolicyAssignmentJson = Get-Content -Path $model | Out-String | ConvertFrom-Json

        $PolicyAssignmentJson.Name = $PolicyAssignmentJsonName
        $PolicyAssignmentJson.Properties.displayName = $PolicyAssignmentJsonName
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

         Invoke-WebRequest -Uri $asc_uri -Method Put -Headers $asc_requestHeader -Body ($PolicyAssignmentJson | ConvertTo-Json -Depth 100) -UseBasicParsing -ContentType "application/json"

    }

    
    Write-Host "***********************************************"
    Write-host "AzureIaC4VDCPolicyAssignments - Push Completed"
    Write-Host "***********************************************"



    #SWEEP
    [array] $effectivepath  = (Get-Item -Path $path)

    if($recurse)
    {
        $effectivepath += (Get-ChildItem -Path $path -Recurse -Directory)
    }

    $effectivepath  |% {

        [string]$effectiveScope = getScope (get-item $_.FullName)
        [string]$localdirectory = $_.FullName

        if($effectiveScope.Contains('/resourcegroups/') -eq $false)
        {
            $asc_uri= "https://management.azure.com/$effectiveScope/providers/Microsoft.Authorization/policyDefinitions?api-version=2018-03-01"
            $asc_requestHeader = @{
                Authorization = "Bearer $(getAccessToken)"
                'Content-Type' = 'application/json'
            }

            $response = Invoke-WebRequest -Uri $asc_uri -Method Get -Headers $asc_requestHeader -UseBasicParsing -ContentType "application/json"
            $policyDefinitions = ($response.content | ConvertFrom-Json).Value

            Write-Host "Retriving Policy Definitions from $asc_uri"
    
 
            $policyDefinitions |% {

                #write-host  "Scope: $($effectiveScope)/$($_.properties.displayName)" 
                Write-PolicyAssignmentAtScope -path (get-item $localdirectory) -effectiveScope $effectiveScope -policydefinitionID $_.id -deleteifNecessary:$deleteifNecessary
    
            }
        } 

    }


}


function Ensure-AzureIaC4VDCPolicyDefinitions ($path = 'C:\git\bp\MgmtGroup\b2a0bb8e-3f26-47f8-9040-209289b412a8\BP\BP-Spoke', $effectiveScope = $(getScope $path), $deleteifNecessary = $false)
{

    Get-ChildItem -Path $path -Recurse -Include PolicyDefinition-*.json |% {

         [string]$effectiveScope = getScope (get-item $_.PSParentPath)
         Write-Host $effectiveScope
         Write-Host $_.FullName

         #$model =  get-item "C:\git\bp\MgmtGroup\b2a0bb8e-3f26-47f8-9040-209289b412a8\BP\PolicyDefintion-routeTablePolicy.json"
         $model = $_.FullName
         $model = get-item $model

         $PolicyDefinitionJson = Get-Content -Path $model | Out-String | ConvertFrom-Json
         $PolicyDefinitionJsonName = $model.BaseName.Replace('PolicyDefinition-','')
     
     
         if (( Get-Member -InputObject $PolicyDefinitionJson -Name Name) -eq $null)
         {
             $PolicyDefinitionJson  | Add-member  -MemberType NoteProperty -Name Name -Value ''
         }
         $PolicyDefinitionJson.Name = $PolicyDefinitionJsonName


         if (( Get-Member -InputObject $PolicyDefinitionJson.properties -Name displayName) -eq $null)
         {
             $PolicyDefinitionJson.Properties  | Add-member  -MemberType NoteProperty -Name displayName -Value ''
         }
         $PolicyDefinitionJson.Properties.displayName = $PolicyDefinitionJsonName

         
         if (( Get-Member -InputObject $PolicyDefinitionJson -Name id) -eq $null)
         {
             $PolicyDefinitionJson  | Add-member  -MemberType NoteProperty -Name id -Value ''
         }   
         $PolicyDefinitionJson.id =  "$effectiveScope/providers/Microsoft.Authorization/policyDefinitions/$PolicyDefinitionJsonName"

           
        $asc_uri= "https://management.azure.com/$effectiveScope/providers/Microsoft.Authorization/policyDefinitions/$($PolicyDefinitionJsonName)?api-version=2018-03-01"
        $asc_requestHeader = @{
            Authorization = "Bearer $(getAccessToken)"
            'Content-Type' = 'application/json'
        }

        Invoke-WebRequest -Uri $asc_uri -Method Put -Headers $asc_requestHeader -Body ($PolicyDefinitionJson | ConvertTo-Json -Depth 100) -UseBasicParsing -ContentType "application/json"
        
    }


    [array] $effectivepath  = (Get-Item -Path $path)

    $effectivepath += (Get-ChildItem -Path $path -Recurse -Directory)

    $effectivepath    |% {


        [string]$effectiveScope = getScope (get-item $_.FullName)
        [string]$localdirectory = $_.FullName

        if($effectiveScope.Contains('/resourcegroups/') -eq $false)
        {

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

             $policyDefinitionFilePath =  $(join-path  $localdirectory -ChildPath $("PolicyDefinition-$policyDefinitionName.json"))

                
            if($deleteifNecessary -and (Test-Path $policyDefinitionFilePath) -eq $false)
            {
                
                    Write-Host "Deleting policyDefinitions at scope $effectiveScope name: $($_.Name)"

                    $asc_uri= "https://management.azure.com/$effectiveScope/providers/Microsoft.Authorization/policyDefinitions/$($_.Name)?api-version=2018-03-01"

                    Invoke-WebRequest -Uri $asc_uri -Method DELETE -Headers $asc_requestHeader -UseBasicParsing -ContentType "application/json"

            }
            else
            {
                 Write-Host "Writing Policy at  $policyDefinitionFilePath"
                 $_ | convertto-json -Depth 100  | % { [System.Text.RegularExpressions.Regex]::Unescape($_) } | out-file -Force -FilePath $policyDefinitionFilePath


            }


        } 
        }
    }
}


function Ensure-AzureIaC4VDCMgmtandSubscriptions($path = '', 
                                                 $pathtoManangementGroup = '',
                                                 $deleteifNecessary = $false, 
                                                 $workspaceId = "/subscriptions/926ab52d-a877-4db3-b0f9-2e9f8ecbe4c4/resourcegroups/bp-azure-oms/providers/microsoft.operationalinsights/workspaces/bp-ws-1000"
                                                 )
{
     ls -Recurse -Directory -Path $pathtoManangementGroup |%    {

                $effectiveScope = getScope $_.fullname

                if($effectiveScope -ne $null)
                {

                    if($_.Name.StartsWith('Mgmt') -eq $true)
                    {

                        if(getParentbyID ($effectiveScope) -ne $null)
                        {

                            $currentMgmtGroupParentName = getNamebyID( getParentbyID ($effectiveScope))

                            $desiredMgmtGroupParentName = ($_.Parent.BaseName -ireplace ('Mgmt-', '') )

                            $mgmtGroupName = ($_.BaseName -ireplace ('Mgmt-', '') )

                            if($currentMgmtGroupParentName -ne $desiredMgmtGroupParentName)
                            {

                                Update-AzureRmManagementGroup -GroupName $mgmtGroupName -ParentId (getParentbyID ($effectiveScope)) -DisplayName $mgmtGroupName -Confirm:$false

                            }
                        }

                    }
                    if($_.Name.StartsWith('Sub') -eq $true)
                    {

                        $desiredMgmtGroupParentName = ($_.Parent.BaseName -ireplace ('Mgmt-', '') )
                        $subscriptionname = ($_.BaseName -ireplace ('Sub-', ''))
                        
                        $currentMgmtGroupParentName = getNamebyID( getParentbyID ($effectiveScope))
                        

                        if($currentMgmtGroupParentName -ne $desiredMgmtGroupParentName)
                        {
                            Write-Host "Chanign Mgmt group from $currentMgmtGroupParentName to $desiredMgmtGroupParentName"
                            $subscriptionid = $effectiveScope -split ('/') | select -Last 1
                            New-AzureRmManagementGroupSubscription -GroupName $desiredMgmtGroupParentName -SubscriptionId $subscriptionid
                            
                        }

                        $subscription = Get-AzureRmSubscription -SubscriptionName $subscriptionname

                        $asconfig = @{
                             Uri = "https://management.azure.com/subscriptions/$($subscription.SubscriptionId)/providers/Microsoft.Security/register?api-version=2017-05-10"
                             Headers = @{
                                   Authorization = "Bearer $(getAccessToken)"
                                   'Content-Type' = 'application/json'
                                   }
                                   Method = 'POST'
                                   UseBasicParsing = $true
                                   Body = ""
                                }

                        Invoke-WebRequest @asconfig

                        #FIX - Subscription not registered
                        #Register-AzureRmResourceProvider -ProviderNamespace Microsoft.Security -Debug

        
        
                        $body = @{

                            properties= @{

                                workspaceId = $workspaceId
                                scope = "/subscriptions/$($subscription.SubscriptionId)"
                            }
                        } | ConvertTo-Json


                        $asconfig = @{
                             Uri = "https://management.azure.com/subscriptions/$($subscription.SubscriptionId)/providers/Microsoft.Security/workspaceSettings/default?api-version=2017-08-01-preview"
                             Headers = @{
                                   Authorization = "Bearer $(getAccessToken)"
                                   'Content-Type' = 'application/json'
                                   }
                                   Method = 'Put'
                                   UseBasicParsing = $true
                                   Body = $body
                                }

                        Invoke-WebRequest @asconfig


                        $subscription = Get-AzureRmSubscription -SubscriptionName $subscriptionname
                        $asconfig = @{
                             Uri = "https://management.azure.com/subscriptions/$($subscription.Id)/providers/Microsoft.Security/policies/default?api-version=2015-06-01-preview" 
                             
                             Headers = @{
                                   Authorization = "Bearer $(getAccessToken)"
                                   'Content-Type' = 'application/json'
                                   }
                                   Method = 'PUT'
                                   UseBasicParsing = $true
                                   Body = $ascpricingtierconfig
                                }

                        Invoke-WebRequest @asconfig



                    }

                }
                else
                {
                    #Create new Mangement Group

                    if($_.Name.StartsWith('Mgmt') -eq $true)
                    {

                        $_mgmtgroupname = ($_.BaseName -ireplace ('Mgmt-', '') )

                        New-AzureRmManagementGroup -GroupName $_mgmtgroupname -DisplayName $_mgmtgroupname -ParentId (getScope ($_.Parent)) -Confirm:$false

                    }

                    #create new subscription
                    if($_.Name.StartsWith('Sub') -eq $true)
                    {

                        $_mgmtgroupname = ($_.Parent.BaseName -ireplace ('Mgmt-', '') )
                        $_subscriptionname = ($_.BaseName -ireplace ('Sub-', ''))

                        Write-Host "Calling: New-AzureIaC4VdcSubsriptionProvisioning -subscriptionName $_subscriptionname -SubscriptionDisplayName $_subscriptionname -ManagementGroupName $_mgmtgroupname"

                        #$DebugPreference="Continue"
                        New-AzureIaC4VdcSubsriptionProvisioning -subscriptionName $_subscriptionname -SubscriptionDisplayName $_subscriptionname -ManagementGroupName $_mgmtgroupname
                        #$DebugPreference="SilentlyContinue"

                    }

                    

                }

                
    }
    
      
     $AzureRmManagementGroup |% { 

        Write-host "====================================================================="

        $mgmtGroup =   $_
        $mgmtGroup
        

        if($mgmtGroup.Name.StartsWith('Mgmt-') -eq $false)
        {
            $mgmtGroupName = "Mgmt-" + $mgmtGroup.DisplayName
        }
        else
        {
             $mgmtGroupName = $mgmtGroup.DisplayName
        }
        
        

        if ($mgmtGroup.ParentId -eq $null)
        {
            #Root Mgmt Group
            $MgmtGroupLocation = mkdir (Join-Path $path $mgmtGroupName) -Force
            
        }

        else
        {

            #Does my parent exists?

            $_parent = $mgmtGroup.ParentDisplayName
           
            
            $parentMgmtGroupName = ""    
            if($_parent.StartsWith('Mgmt-') -eq $false)
            {
                $parentMgmtGroupName = ("Mgmt-" + $_parent)
            }
            else
            {
                $parentMgmtGroupName = $_parent
            }

            
            $parentMgmtGroupLocation = ls $path -Recurse -Directory -Filter $parentMgmtGroupName
            
            if($parentMgmtGroupLocation -ne $null)
            {
                Write-host "Existing Parent Directory Found at : " + $parentMgmtGroupLocation.FullName

                $MgmtGroupLocationPath = (join-path  $parentMgmtGroupLocation.FullName $mgmtGroupName) 

               
            }
            else
            {
               #Parent is not found - creating folder at the root mangement group location to avoid iterating children

               $rootManagementGroup = ($AzureRmManagementGroup|? {$_.ParentId -eq $null}).Id
               $rootManagementGroupLocation = "Mgmt-$(getNamebyID $rootManagementGroup)"

               $MgmtGroupLocationPath = (join-path (Join-Path "$path\$rootManagementGroupLocation" $parentMgmtGroupName) $mgmtGroupName) 
               

            }

            #Avoiding folder overwrite
            if((Test-Path $MgmtGroupLocationPath) -eq $false)
            {

                if($deleteifNecessary)
                {
                    Write-Host "mgmtGroupName: $mgmtGroupName"
                    Remove-AzureRmManagementGroup -GroupName $mgmtGroup.Name -Confirm:$false
                }
                else
                {
                    write-host "MgmtGroupLocationPath : $MgmtGroupLocationPath "
                    $MgmtGroupLocation = mkdir $MgmtGroupLocationPath  -Force 
                }
                
            }
            else
            {
                #Avoiding folder overwrite

                $MgmtGroupLocation = (Get-Item $MgmtGroupLocationPath)
            }          
            

        }

        Write-Host "Mgmt Group Location: $MgmtGroupLocation"

       
                
        $mgmtGroup.children |? {($_.ChildType -eq '/managementGroup') }  |% {
        
                $childMgmtGroupname = ("Mgmt-" + (getNamebyID ($_.ChildId)))

                Write-Host "Parent Name: $($MgmtGroup.ParentDisplayName)"
                Write-Host "MgmtGroup Name: $($MgmtGroup.DisplayName)"
                Write-Host "Children Name: $($_.DisplayName)"
                Write-Host "MgmtGroupLocation Full Name: $($MgmtGroupLocation.FullName)"
                

                $desiredChildMgmtGroupLocation = (Join-Path $MgmtGroupLocation.FullName $childMgmtGroupname)

                $existingChildMgmtGroupLocation= ls $path -Recurse -Directory -Filter $childMgmtGroupname
            
                if( $existingChildMgmtGroupLocation -eq $null)
                {

                    ####################################
                    #Create new Child Mamnagement Group#
                    ####################################


                    if((Test-Path $desiredChildMgmtGroupLocation) -eq $false)
                    {

                        if($deleteifNecessary)
                        {
                            #dont have to handle Mgmt Group Deletion in Children scope

                            Write-Host "Deleting childMgmtGroupname:$(getNamebyID ($_.ChildId))"
                            
                            #Remove-AzureRmManagementGroup -GroupName $(getNamebyID ($_.ChildId)) -Confirm:$false
                        }
                        else
                        {
                             write-host "desiredChildMgmtGroupLocation : $desiredChildMgmtGroupLocation "
                             mkdir  $desiredChildMgmtGroupLocation -Force | out-null
                        }
                
                    }

                }
                else   
                {
                    #Mgmtgroup found elsewhere

                    if(Test-Path -Path $desiredChildMgmtGroupLocation)
                    {
                        Write-Host "Child Mgmt Group is already at right location $desiredChildMgmtGroupLocation)"
                    }
                    else
                    {
                        #Moving Orphan child
                        move-item -Path $existingChildMgmtGroupLocation.FullName -Destination ($MgmtGroupLocation).FullName
                    }


                }
            
        }
        
        #Enumerating subscription
        if( getAllSubscriptionBelowScope -id ($mgmtGroup.id) -ne $null)
        {
       
            getAllSubscriptionBelowScope -id $mgmtGroup.id |% {
        
                $subscriptionName = ("Sub-" + (getNamebyID ($_)))
                $desiredSubscriptionLocation = (Join-Path $MgmtGroupLocation.FullName $subscriptionName)

                $existingSubscription = ls $path -Recurse -Directory -Filter $subscriptionName
            
                if(-not $existingSubscription)
                {

                    ####################################
                    #Create new Folder for Subscription#
                    ####################################

                    Write-Host "desiredSubscriptionLocation : $desiredSubscriptionLocation"
                    mkdir  $desiredSubscriptionLocation -Force | out-null

                }
                else   
                {
                    #subscription found elsewhere

                    if(Test-Path -Path $desiredSubscriptionLocation)
                    {
                        Write-Host "Subscription is already at right location $desiredSubscriptionLocation)"
                    }
                    else
                    {
                        #Moving Orphan child
                        Write-Host "Moving Subscription from $($existingSubscription.FullName) to Destination $($MgmtGroupLocation.FullName)"
                        move-item -Path $existingSubscription.FullName -Destination ($MgmtGroupLocation).FullName
                    }


                }
            }
        }
        
   
    }                 
    
}



function Ensure-AzureIaC4VDCTemplateDeployment ($path = 'C:\git\bp\MgmtGroup', $deleteifNecessary = $false)
{

    
    Get-ChildItem -Path $path -Recurse -Include Deployment-*.json -Exclude *.parameters.json |% {

        
        [string]$effectiveScope = getScope (get-item $_.PSParentPath)
        
        Write-Host $effectiveScope
        Write-Host $_.FullName

        if($effectiveScope.StartsWith('/subscriptions/'))
        {

            #$model =  get-item "C:\git\bp\MgmtGroup\Mgmt-Tenant Root Group\Mgmt-BP\Sub-BP Mgmt Subscription\eastus-bp-oms-northamerica\Deployment-bp-oms-northamerica.json"
            
            $model = get-item $_.FullName
            $tempalteParameterFile =   join-path $_.Directory.FullName "$($model.BaseName).parameters.json"
          

            if(($model.BaseName).split('-').Count -gt 2)
            {

                $location =  ($model.Directory.Name).Split('-')[0]          
                $rgname = ($model.Directory.Name).Replace("$location-" , "")
                
                $asc_uri= "https://management.azure.com/$($effectiveScope.replace("$location-" , ''))?api-version=2017-05-10"
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

                $deploymentname = $(get-date -Format "yy-MM-dd-HH-mm-ss") + $model.BaseName

                $asc_uri= "https://management.azure.com/$($effectiveScope.replace("$location-" , ''))/providers/Microsoft.Resources/deployments/$($deploymentname)?api-version=2017-05-10"
                $asc_requestHeader = @{
                    Authorization = "Bearer $(getAccessToken)"
                    'Content-Type' = 'application/json'
                }

                Invoke-WebRequest -Uri $asc_uri -Method Put -Headers $asc_requestHeader -Body ($myObject | ConvertTo-Json -Depth 100) -UseBasicParsing -ContentType "application/json"
                
            }
            else
            {
                write-host "Invalid Deployment file name: Subscription\%Region%-%ResourceGroupName%\Deployment-template-name.json required. Supplied Name was: $($model.BaseName)"
            }

        }
        else
        {

            #Mgmt Group
            #Get-ChildItem -Recurse -Path $_.PSParentPath -Directory |% { }

        }


    }
    

    Write-Host "***************************************************"
    Write-Host "*Push Completed for AzureIaC4VDCTemplateDeployment*"
    Write-Host "***************************************************"


    $managedsubscriptions = getAllManagementGroupBelowScopeRecursive (getScope (get-item $path))|? {$_ -ne '' -and $_ -ne $null} |% { getAllSubscriptionBelowScope -id $_}
    $managedsubscriptions += getAllSubscriptionBelowScope -id (getScope (get-item $path)) |? {$_ -ne '' -and $_ -ne $null} |% { getScope $_ } 

    #$managedsubscriptions = "/subscriptions/bb81881b-d6a7-4590-b14e-bb3c575e42c5"

    $managedsubscriptions |% {

        $effectiveScope = getScope $_
        $foldername = "Sub-$($(getNamebyID -id $effectiveScope).Trim())"
        $subscriptionfolder = Get-ChildItem $path -Recurse -Directory |? {$_.BaseName -eq $foldername} 

      
        $asc_uri= "https://management.azure.com/$($effectiveScope)/resourcegroups?api-version=2017-05-10"
        $asc_requestHeader = @{
            Authorization = "Bearer $(getAccessToken)"
            'Content-Type' = 'application/json'
        }

        $currentRG = ((Invoke-WebRequest -Uri $asc_uri -Method Get -Headers $asc_requestHeader -UseBasicParsing).content | ConvertFrom-Json).Value

        $currentRG |% {

            $_rgname = $_.name
            $_location = $_.location

            Write-Host "$effectiveScope\$_location-$_rgname"

            $resourcegrouppath = Get-ChildItem $path -Recurse -Directory |? {$_.Name -eq ("$_location-$_rgname") } 


            if($deleteifNecessary -and $resourcegrouppath -eq $null)
            {
                #Delete Resource Group
                Write-Host "Deleting Resource Group $_rgname at $_location"

                $asc_uri= "https://management.azure.com/$($effectiveScope)/resourcegroups/$($_rgname)?api-version=2017-05-10"
                $asc_requestHeader = @{
                    Authorization = "Bearer $(getAccessToken)"
                    'Content-Type' = 'application/json'
                }

                #Invoke-WebRequest -Uri $asc_uri -Method DELETE -Headers $asc_requestHeader -UseBasicParsing
                Write-Host "Success! Deleting Resource Group $_rgname at $_location"
                
            }
            else
            {
                #Potentially we can download template and store it as _Deployment
                if( (test-path -Path (join-path  $subscriptionfolder.FullName  ("$_location-$_rgname"))) -eq $false)
                {
                    Write-Host "Creating Fodler for RG at $(join-path  $subscriptionfolder.FullName  ("$_location-$_rgname"))"
                    mkdir (join-path  $subscriptionfolder.FullName ("$_location-$_rgname")) -Force -Confirm:$false | out-null
                }

            }

        }

    }
    


     
}

#Ensure-AzureIaC4VDCTemplateDeployment -path "C:\git\bp\MgmtGroup\Mgmt-Tenant Root Group\Mgmt-BP\Sub-BP Mgmt Subscription"