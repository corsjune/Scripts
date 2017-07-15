#
# ModifyAzurePostgresFirewallforAzureIpRanges.ps1
#
#Required Powershelll script MicrosoftAzureDatacenterIPRange to be installed 
#
#https://www.powershellgallery.com/packages/AzurePublicIPAddresses/0.5.1/Content/functions%5CGet-MicrosoftAzureDatacenterIPRange.ps1

$AzureRegion = 'EAST US 2'                   ## See the list defined in PS MicrosoftAzureDatacenterIPRange
$AzureResourceGroup = 'resource'   ##Resource group of the postgres server
$PostgresServer='server'         ##name of Postgres server
$ScriptFirewallRulePrefix = 'Automated'      ##Prefix to use for Firewall Rule Naming
$currenttime=Get-Date -format M.d.yyyy


#Function modified from original
#Original found at https://gallery.technet.microsoft.com/scriptcenter/List-the-IP-addresses-in-a-60c5bb6b#content
#Original function Get-IPrange attributed to BarryCWT 
function Get-IPrange
{
		<# 
 
		  .EXAMPLE 
		   Get-IPrange -ip 192.168.8.3 -cidr 24 
		#> 
 
		param 
		(  
		  [string]$ip,  
		  [int]$cidr 
		) 
 
		function IP-toINT64 () { 
			  param ($ip) 
 
			  $octets = $ip.split(".") 
			  return [int64]([int64]$octets[0]*16777216 +[int64]$octets[1]*65536 +[int64]$octets[2]*256 +[int64]$octets[3]) 
		} 
 
		function INT64-toIP() { 
			  param ([int64]$int) 

			  return (([math]::truncate($int/16777216)).tostring()+"."+([math]::truncate(($int%16777216)/65536)).tostring()+"."+([math]::truncate(($int%65536)/256)).tostring()+"."+([math]::truncate($int%256)).tostring() )
		} 
 
		if ($ip) {$ipaddr = [Net.IPAddress]::Parse($ip)} 
		if ($cidr) {$maskaddr = [Net.IPAddress]::Parse((INT64-toIP -int ([convert]::ToInt64(("1"*$cidr+"0"*(32-$cidr)),2)))) } 
 
		if ($ip) {$networkaddr = new-object net.ipaddress ($maskaddr.address -band $ipaddr.address)} 
		if ($ip) {$broadcastaddr = new-object net.ipaddress (([system.net.ipaddress]::parse("255.255.255.255").address -bxor $maskaddr.address -bor $networkaddr.address))} 
 
		if ($ip) { 
		  $startaddr = IP-toINT64 -ip $networkaddr.ipaddresstostring 
		  $endaddr = IP-toINT64 -ip $broadcastaddr.ipaddresstostring 
		} 


		return $Object = @{
			'StartAddress' = INT64-toIP -int $startaddr 
			'EndAddress' = INT64-toIP -int $endaddr 
			}
  
}

##Note Need to login, modify as suit

az login
$existingRules =( az postgres server firewall-rule list --resource-group $AzureResourceGroup  --server-name $PostgresServer ) | ConvertFrom-Json
 
Foreach ($er in $existingRules) ##delete the existing rules previously created by this script for rerunnability, this will probably break in Web Applications depending on these rules until recreated below
{
 
	##Only delete the rules with our prefix above
	if ($er.Name.StartsWith($ScriptFirewallRulePrefix))
	{
		   az postgres server firewall-rule delete --resource-group $AzureResourceGroup --server $PostgresServer --name $name --yes
		   Write-Host 'Rule ' $er.Name  ' deleted'
	}
} 

##get CIDR blocks for Region
$AllIP =  MicrosoftAzureDatacenterIPRange  -AzureRegion $AzureRegion

##Create Firewall Rules
Foreach ($ip_cidr in $AllIP)
{

    $ip=$ip_cidr.Subnet.Split("/")
    $ranges= Get-IPrange -ip $ip[0] -cidr $ip[1]

	$name = ($ScriptFirewallRulePrefix + '--REGION-' + $AzureRegion  + '--CIDR-' + $ip_cidr.Subnet.Replace("/","_") + '--DATE-' +  $currenttime ).Replace(' ','').Replace('.','_')
 
	Write-Host 'Creating Rule ' $name  
    az postgres server firewall-rule create --resource-group $AzureResourceGroup --server-name $PostgresServer --name $name --start-ip-address $ranges.StartAddress --end-ip-address $ranges.EndAddress
	
}

