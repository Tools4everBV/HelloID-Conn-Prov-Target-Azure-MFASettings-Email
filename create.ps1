#Initialize default properties
$p = $person | ConvertFrom-Json;
$m = $manager | ConvertFrom-Json;
$aRef = $accountReference | ConvertFrom-Json;
$mRef = $managerAccountReference | ConvertFrom-Json;
$success = $False;
$auditLogs = New-Object Collections.Generic.List[PSCustomObject];

# AzureAD Application Parameters #
$config = ConvertFrom-Json $configuration

$AADtenantID = $config.AADtenantID
$AADAppId = $config.AADAppId
$AADAppSecret = $config.AADAppSecret

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

# Change mapping here
$account = [PSCustomObject]@{
    userPrincipalName = $p.Accounts.MicrosoftActiveDirectory.userPrincipalName
    email = $p.Contact.Personal.Email;
};

$aRef = $account.userPrincipalName

try{
    Write-Verbose -Verbose "Generating Microsoft Graph API Access Token.."
    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type      = "client_credentials"
        client_id       = "$AADAppId"
        client_secret   = "$AADAppSecret"
        resource        = "https://graph.microsoft.com"
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token;

    #Add the authorization header to the request
    $authorization = @{
        Authorization = "Bearer $accesstoken";
        'Content-Type' = "application/json";
        Accept = "application/json";
    }

    Write-Verbose -Verbose "Gathering current Email Authentication Methods for $($account.userPrincipalName).."

    $baseUri = "https://graph.microsoft.com/"
    $getEmailAuthenticationMethodUri = $baseUri + "/beta/users/$($account.userPrincipalName)/authentication/emailMethods"

    $getEmailAuthenticationMethodResponse = Invoke-RestMethod -Uri $getEmailAuthenticationMethodUri -Method Get -Headers $authorization -Verbose:$fals
    $getEmailAuthenticationMethodResponseValue = $getEmailAuthenticationMethodResponse.value
    Write-Verbose -Verbose ("Email authentication method: " + ($getEmailAuthenticationMethodResponseValue | Out-String) )
    
    $authenticationMethodSet = $false;
    if( !([string]::IsNullOrEmpty(($getEmailAuthenticationMethodResponseValue | Out-String))) ){
        $authenticationMethodSet = $true;
    }

    if(-Not($dryRun -eq $True)) {

        if($authenticationMethodSet -eq $false){
            Write-Verbose -Verbose "No Email Authentication set. Adding Email Authentication Method : $($account.email) for $($account.userPrincipalName).."
        
            $baseUri = "https://graph.microsoft.com/"
            $addEmailAuthenticationMethodUri = $baseUri + "/beta/users/$($account.userPrincipalName)/authentication/emailMethods"
        
            $body = @{
                "emailAddress" = $($account.email)
            }
            $bodyJson = $body | ConvertTo-Json -Depth 10
        
            $addEmailAuthenticationMethodResponse = Invoke-RestMethod -Uri $addEmailAuthenticationMethodUri -Method Post -Headers $authorization -Body $bodyJson -Verbose:$false
        
            Write-Verbose -Verbose "Successfully updated Email Authentication Method : $($account.email) for $($account.userPrincipalName)"  
        }else{
            $currentEmail = ($getEmailAuthenticationMethodResponseValue | Where-Object {$_.id -eq '3ddfcfc8-9383-446f-83cc-3ab9be4be18f'}).emailAddress
            Write-Verbose -Verbose "Updating current Email Authentication Method : $currentEmail for $($account.userPrincipalName).."

            $previousAccount = [PSCustomObject]@{
                userPrincipalName = $account.userPrincipalName
                email = $currentEmail;
            }            

            $baseUri = "https://graph.microsoft.com/"
            $addEmailAuthenticationMethodUri = $baseUri + "/beta/users/$($account.userPrincipalName)/authentication/emailMethods/3ddfcfc8-9383-446f-83cc-3ab9be4be18f"
        
            $body = @{
                "emailAddress" = $($account.email)
            }
            $bodyJson = $body | ConvertTo-Json -Depth 10
        
            $addEmailAuthenticationMethodResponse = Invoke-RestMethod -Uri $addEmailAuthenticationMethodUri -Method Put -Headers $authorization -Body $bodyJson -Verbose:$false
        
            Write-Verbose -Verbose "Successfully updated Email Authentication Method : $($account.email) for $($account.userPrincipalName)"
        }
    }

    $auditLogs.Add([PSCustomObject]@{
        Action = "CreateAccount"
        Message = "Correlated to and updated Azure MFA settings of account with UPN $($aRef)"
        IsError = $false;
    });

    $success = $true;    
}catch{
    $auditLogs.Add([PSCustomObject]@{
        Action = "CreateAccount"
        Message = "Error correlating to and updating Azure MFA settings of account with UPN $($aRef): $($_)"
        IsError = $True
    });
    Write-Error $_;
}

# Send results
$result = [PSCustomObject]@{
	Success= $success;
	AccountReference= $aRef;
	AuditLogs = $auditLogs;
    Account = $account;
    PreviousAccount = $previousAccount;

    # Optionally return data for use in other systems
    ExportData = [PSCustomObject]@{
        userPrincipalName = $account.userPrincipalName
        email = $account.email;
    };
};

Write-Output $result | ConvertTo-Json -Depth 10;