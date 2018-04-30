param
(
[switch] $MgmtandSubscriptions,
[switch] $IAM,
[switch] $Policy, 
[switch] $TemplateDeployment, 
[bool] $falgDeleteIfNecessary

)

   

    $mgmtroot = 'Mgmt-Tenant Root Group'
    $mgmtSubscriptionID = 'bb81881b-d6a7-4590-b14e-bb3c575e42c5'

    if($env:BUILD_SOURCESDIRECTORY)
    {
        Write-Host "VSTS"
        $path = "$env:BUILD_SOURCESDIRECTORY"

    }
    else
    {
        $path = "c:\git\bp"
    }




    Import-Module "$path\Common.psm1" -Force
    $mgmtSubscriptionPath = "$path\MgmtGroup\$mgmtroot\Mgmt-BP\Sub-BP Mgmt Subscription"

    Write-Host "Using Current Path: $path"
    Write-Host "mgmtSubscriptionPath: $mgmtSubscriptionPath"
    Write-Host "BUILD_REPOSITORY_LOCALPATH: $env:BUILD_REPOSITORY_LOCALPATH"
    Write-Host "BUILD_SOURCESDIRECTORY: $env:BUILD_SOURCESDIRECTORY"
    
    Write-Host "falgDeleteIfNecessary : $falgDeleteIfNecessary"

    if($MgmtandSubscriptions)
    {

        Write-Host "AzureIaC4VDCMgmtandSubscriptions : $falgDeleteIfNecessary"
        Ensure-AzureIaC4VDCMgmtandSubscriptions -path  "$path\MgmtGroup" -deleteifNecessary:$falgDeleteIfNecessary
    }

    
    if($IAM)
    {

        Write-Host "AzureIaC4VDCRoleDefintion : $falgDeleteIfNecessary"

        
        Ensure-AzureIaC4VDCRoleDefintion  -path $path\MgmtGroup\$mgmtroot\Mgmt-BP  -deleteifNecessary:$falgDeleteIfNecessary -mgmtSubscriptionID:$mgmtSubscriptionID -mgmtSubscriptionPath:$mgmtSubscriptionPath
        Ensure-AzureIaC4VDCRoleAssignment  -path $path\MgmtGroup\$mgmtroot\Mgmt-BP -deleteifNecessary:$falgDeleteIfNecessary
    }

    
    if($Policy)
    {

        Write-Host "AzureIaC4VDCPolicyDefinitions : $falgDeleteIfNecessary"
        Ensure-AzureIaC4VDCPolicyDefinitions -path $path\MgmtGroup\$mgmtroot\Mgmt-BP -deleteifNecessary:$falgDeleteIfNecessary
        Ensure-AzureIaC4VDCPolicyAssignments -path $path\MgmtGroup\$mgmtroot\Mgmt-BP -deleteifNecessary:$falgDeleteIfNecessary

    }

    
    if($TemplateDeployment)
    {

        Write-Host "Deployment : $falgDeleteIfNecessary"
        Ensure-AzureIaC4VDCTemplateDeployment -path $path\MgmtGroup\$mgmtroot\Mgmt-BP -deleteifNecessary:$falgDeleteIfNecessary
        

    }