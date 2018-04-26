function Get-ScriptDirectory { Split-Path $MyInvocation.ScriptName }

function IsMangementGroup ([System.io.DirectoryInfo] $name) 
{

   
        if ( $name.Name -match("^(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}$") -and
             $name.GetDirectories().Count -eq 0)
        {
            #Subscription
            return $false
        }
        else
        {   
           return $true
        }


}

function IsSubscription ([System.io.DirectoryInfo] $name)
{

   
        if ( $name.Name -match("^(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}$") -and
             $name.GetDirectories().Count -eq 0)
        {
            #Subscription
            return $true
        }
        else
        {   
           return $false
        }


}

function getScope([System.io.DirectoryInfo] $name)
{
    
    if (IsMangementGroup $name)
    {
        return [string]$scope = "/providers/Microsoft.Management/managementGroups/$($name.BaseName)"
        
    }
    if (IsSubscription $name)
    {
        return [string]$scope = $("/subscriptions/$($name.BaseName)")
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
