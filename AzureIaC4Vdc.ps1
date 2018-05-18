param
(
[switch] $MgmtandSubscriptions,
[switch] $RoleDefinition,
[switch] $RoleAssignment,
[switch] $PolicyDefinition,
[switch] $PolicyAssignment, 
[switch] $TemplateDeployment, 
[bool] $falgDeleteIfNecessary = $false,
[string] $ManangementGroupName = "Mgmt-BP"

)

   

$mgmtroot = 'Mgmt-Tenant Root Group'
$mgmtSubscriptionID = 'bb81881b-d6a7-4590-b14e-bb3c575e42c5'
$omsWorkspaceId = "/subscriptions/926ab52d-a877-4db3-b0f9-2e9f8ecbe4c4/resourcegroups/bp-azure-oms/providers/microsoft.operationalinsights/workspaces/bp-ws-1000"

if($env:BUILD_SOURCESDIRECTORY)
{
    Write-Host "VSTS"
    $path = "$env:BUILD_SOURCESDIRECTORY"

}
elseif ($($MyInvocation.ScriptName) -ne $null -and $($MyInvocation.ScriptName) -ne '')
{
    $path =  Split-Path $myInvocation.ScriptName 

}
else
{
    $path = $pwd
}


Import-Module "$path\Common.psm1" -Force


$pathtoManangementGroup =  Join-Path $path "MgmtGroup\$mgmtroot\$ManangementGroupName"
$mgmtSubscriptionPath = Join-Path  $pathtoManangementGroup "Sub-BP Mgmt Subscription"

Write-Host "Using Current Path: $path"

Write-Host "BUILD_REPOSITORY_LOCALPATH: $env:BUILD_REPOSITORY_LOCALPATH"
Write-Host "BUILD_SOURCESDIRECTORY: $env:BUILD_SOURCESDIRECTORY"
Write-Host "falgDeleteIfNecessary : $falgDeleteIfNecessary"
Write-Host "pathtoManangementGroup : $pathtoManangementGroup"
Write-Host "mgmtSubscriptionPath: $mgmtSubscriptionPath"



if($MgmtandSubscriptions)
{

    Write-Host "AzureIaC4VDCMgmtandSubscriptions : $falgDeleteIfNecessary"
    Ensure-AzureIaC4VDCMgmtandSubscriptions -path "$path\MgmtGroup" -pathtoManangementGroup $pathtoManangementGroup -deleteifNecessary:$falgDeleteIfNecessary -workspaceId:$omsWorkspaceId
}

    
if($RoleDefinition)
{

    Write-Host "AzureIaC4VDCRoleDefintion : $falgDeleteIfNecessary"
    Ensure-AzureIaC4VDCRoleDefinition  -path $pathtoManangementGroup  -deleteifNecessary:$falgDeleteIfNecessary -mgmtSubscriptionID:$mgmtSubscriptionID -mgmtSubscriptionPath:$mgmtSubscriptionPath
}
if($RoleAssignment)
{


    Write-Host "AzureIaC4VDCRoleAssignment : $falgDeleteIfNecessary"
    Ensure-AzureIaC4VDCRoleAssignment  -path $pathtoManangementGroup -deleteifNecessary:$falgDeleteIfNecessary
}

    
if($PolicyDefinition)
{

    Write-Host "AzureIaC4VDCPolicyDefinitions : $falgDeleteIfNecessary"
    Ensure-AzureIaC4VDCPolicyDefinitions -path $pathtoManangementGroup -deleteifNecessary:$falgDeleteIfNecessary
}
if($PolicyAssignment)
{
    Write-Host "AzureIaC4VDCPolicyAssignments : $falgDeleteIfNecessary"
    Ensure-AzureIaC4VDCPolicyAssignments -path $pathtoManangementGroup -deleteifNecessary:$falgDeleteIfNecessary

}

    
if($TemplateDeployment)
{
    Write-Host "AzureIaC4VDCTemplateDeployment : $falgDeleteIfNecessary"
    Ensure-AzureIaC4VDCTemplateDeployment -path $pathtoManangementGroup -deleteifNecessary:$falgDeleteIfNecessary

    

    
 
}