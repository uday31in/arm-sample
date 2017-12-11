Login-AzureRmAccount

$spokeRG = "Spoke1-RG"
$location = "westcentralus"

# Create user object
$cred = Get-Credential -Message "Enter a username and password for the virtual machine."

New-AzureRmResourceGroup -Name $spokeRG -Location $location

$webAsg = New-AzureRmApplicationSecurityGroup `
  -ResourceGroupName $spokeRG `
  -Name WebServers `
  -Location $location

$appAsg = New-AzureRmApplicationSecurityGroup `
  -ResourceGroupName $spokeRG `
  -Name AppServers `
  -Location $location

$databaseAsg = New-AzureRmApplicationSecurityGroup `
  -ResourceGroupName $spokeRG `
  -Name DatabaseServers `
  -Location $location


  $webRule = New-AzureRmNetworkSecurityRuleConfig `
  -Name "WebRule" `
  -Access Allow `
  -Protocol *  `
  -Direction Inbound `
  -Priority 200 `
  -SourceAddressPrefix Internet `
  -SourcePortRange * `
  -DestinationApplicationSecurityGroupId $webAsg.id `
  -DestinationPortRange *

$appRule = New-AzureRmNetworkSecurityRuleConfig `
  -Name "AppRule" `
  -Access Allow `
  -Protocol * `
  -Direction Inbound `
  -Priority 300 `
  -SourceApplicationSecurityGroupId $webAsg.id `
  -SourcePortRange * `
  -DestinationApplicationSecurityGroupId $appAsg.id `
  -DestinationPortRange * 

$databaseRule = New-AzureRmNetworkSecurityRuleConfig `
  -Name "DatabaseRule" `
  -Access Allow `
  -Protocol * `
  -Direction Inbound `
  -Priority 400 `
  -SourceApplicationSecurityGroupId $appAsg.id `
  -SourcePortRange * `
  -DestinationApplicationSecurityGroupId $databaseAsg.id `
  -DestinationPortRange *

  $webNsg = New-AzureRmNetworkSecurityGroup `
  -ResourceGroupName $spokeRG `
  -Location $location `
  -Name WebNSG `
  -SecurityRules $WebRule

  $appNsg = New-AzureRmNetworkSecurityGroup `
  -ResourceGroupName $spokeRG `
  -Location $location `
  -Name AppNSG `
  -SecurityRules $AppRule

  $dbNsg = New-AzureRmNetworkSecurityGroup `
  -ResourceGroupName $spokeRG `
  -Location $location `
  -Name DBNSG `
  -SecurityRules $DatabaseRule

  $dbSubnet = New-AzureRmVirtualNetworkSubnetConfig `
  -AddressPrefix 10.0.0.0/24 `
  -Name dbSubnet `
  -NetworkSecurityGroup $dbNsg

  $appSubnet = New-AzureRmVirtualNetworkSubnetConfig `
  -AddressPrefix 10.0.1.0/24 `
  -Name appSubnet `
  -NetworkSecurityGroup $appNsg

  $webSubnet = New-AzureRmVirtualNetworkSubnetConfig `
  -AddressPrefix 10.0.2.0/24 `
  -Name webSubnet `
  -NetworkSecurityGroup $webNsg


  $vNet = New-AzureRmVirtualNetwork `
  -Name spoke1-VNet `
  -AddressPrefix '10.0.0.0/16' `
  -Subnet $webSubnet, $appSubnet, $dbSubnet `
  -ResourceGroupName $spokeRG `
  -Location $location

$App1RG = "Spoke1-App1"
New-AzureRmResourceGroup -Name $App1RG -Location $location

$webNic1 = New-AzureRmNetworkInterface `
  -Name webNic1 `
  -ResourceGroupName $App1RG `
  -Location $location `
  -Subnet $vNet.Subnets[0] `
  -ApplicationSecurityGroup $webAsg

$appNic1 = New-AzureRmNetworkInterface `
  -Name appNic1 `
  -ResourceGroupName $App1RG `
  -Location $location `
  -Subnet $vNet.Subnets[1] `
  -ApplicationSecurityGroup $appAsg

$dbNic1 = New-AzureRmNetworkInterface `
  -Name dbNic1 `
  -ResourceGroupName $App1RG `
  -Location $location `
  -Subnet $vNet.Subnets[2] `
  -ApplicationSecurityGroup $databaseAsg



# Create the web server virtual machine configuration and virtual machine.
$webVmConfig = New-AzureRmVMConfig `
  -VMName WebVm1 `
  -VMSize Standard_DS1_V2 | `
Set-AzureRmVMOperatingSystem -Windows `
  -ComputerName WebVm1 `
  -Credential $cred | `
Set-AzureRmVMSourceImage `
  -PublisherName MicrosoftWindowsServer `
  -Offer WindowsServer `
  -Skus 2016-Datacenter `
  -Version latest | `
Add-AzureRmVMNetworkInterface `
  -Id $webNic1.Id
New-AzureRmVM `
  -ResourceGroupName $App1RG `
  -Location $location `
  -VM $webVmConfig

# Create the app server virtual machine configuration and virtual machine.
$appVmConfig = New-AzureRmVMConfig `
  -VMName AppVm1 `
  -VMSize Standard_DS1_V2 | `
Set-AzureRmVMOperatingSystem -Windows `
  -ComputerName AppVm1 `
  -Credential $cred | `
Set-AzureRmVMSourceImage `
  -PublisherName MicrosoftWindowsServer `
  -Offer WindowsServer `
  -Skus 2016-Datacenter `
  -Version latest | `
Add-AzureRmVMNetworkInterface `
  -Id $appNic1.Id
New-AzureRmVM `
  -ResourceGroupName $App1RG `
  -Location $location `
  -VM $appVmConfig

# Create the database server virtual machine configuration and virtual machine.
$databaseVmConfig = New-AzureRmVMConfig `
  -VMName DBVm1 `
  -VMSize Standard_DS1_V2 | `
Set-AzureRmVMOperatingSystem -Windows `
  -ComputerName DBVm1 `
  -Credential $cred | `
Set-AzureRmVMSourceImage `
  -PublisherName MicrosoftWindowsServer `
  -Offer WindowsServer `
  -Skus 2016-Datacenter `
  -Version latest | `
Add-AzureRmVMNetworkInterface `
  -Id $dbNic1.Id
New-AzureRmVM `
  -ResourceGroupName $App1RG `
  -Location $location `
  -VM $databaseVmConfig



