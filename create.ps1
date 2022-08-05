# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

#Initialize default properties
$p = $person | ConvertFrom-Json
$m = $manager | ConvertFrom-Json
$aRef = $accountReference | ConvertFrom-Json
$mRef = $managerAccountReference | ConvertFrom-Json
$success = $true # Set to true at start, because only when an error occurs it is set to false
$auditLogs = [Collections.Generic.List[PSCustomObject]]::new()

# AzureAD Application Parameters #
$config = ConvertFrom-Json $configuration

$AADtenantID = $config.AADtenantID
$AADAppId = $config.AADAppId
$AADAppSecret = $config.AADAppSecret

# Change mapping here
$account = [PSCustomObject]@{
    userPrincipalName     = $p.Accounts.MicrosoftAzureAD.userPrincipalName
    email                 = $p.Contact.Personal.Email
    onlySetEmailWhenEmpty = $false
}

# Troubleshooting
# $dryRun = $false
# $account = [PSCustomObject]@{
#     userPrincipalName     = 'j.doe@enyoi.org'
#     email                 = 'j.doe@enyoi.nl'
#     onlySetEmailWhenEmpty = $false
# }

# Get current Azure AD user and authentication methods 
try {
    Write-Verbose "Generating Microsoft Graph API Access Token"
    $baseUri = "https://login.microsoftonline.com/"
    $authUri = $baseUri + "$AADTenantID/oauth2/token"

    $body = @{
        grant_type    = "client_credentials"
        client_id     = "$AADAppId"
        client_secret = "$AADAppSecret"
        resource      = "https://graph.microsoft.com"
    }

    $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
    $accessToken = $Response.access_token

    #Add the authorization header to the request
    $authorization = @{
        Authorization  = "Bearer $accesstoken"
        'Content-Type' = "application/json"
        Accept         = "application/json"
    }

    $baseGraphUri = "https://graph.microsoft.com/"
    $searchUri = $baseGraphUri + "v1.0/users/$($account.userPrincipalName)"

    Write-Verbose "Querying Azure AD user with UPN $($account.userPrincipalName)"
    $azureUser = Invoke-RestMethod -Uri $searchUri -Method Get -Headers $authorization -Verbose:$false
    if ($null -ne $azureUser.id) { 
        Write-Verbose "Successfully queried Azure AD user $($azureUser.userPrincipalName) ($($azureUser.id))"
        # Set aRef to use for further actions
        $aRef = $azureUser.id

        Write-Verbose "Gathering current Email Authentication Methods for account with id $($aRef)"
        $baseUri = "https://graph.microsoft.com/"
        $getEmailAuthenticationMethodUri = $baseUri + "/beta/users/$($aRef)/authentication/emailMethods"

        $getEmailAuthenticationMethodResponse = Invoke-RestMethod -Uri $getEmailAuthenticationMethodUri -Method Get -Headers $authorization -Verbose:$fals
        $getEmailAuthenticationMethodResponseValue = $getEmailAuthenticationMethodResponse.value
        Write-Verbose ("Current email authentication method: " + ($getEmailAuthenticationMethodResponseValue | Out-String) )
    }
}
catch {
    $ex = $PSItem
    $verboseErrorMessage = $ex
    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"

    $auditErrorMessage = ($ex | ConvertFrom-Json).error.message
    $success = $false  
    $auditLogs.Add([PSCustomObject]@{
            Action  = "CreateAccount"
            Message = "Error correlating to and updating Azure MFA settings of account with id $($aRef). Error Message: $auditErrorMessage"
            IsError = $True
        })

    if ($auditErrorMessage -Like "*Resource '$($account.userPrincipalName)' does not exist*") {
        if (-Not($dryRun -eq $True)) {
            $success = $false
            $auditLogs.Add([PSCustomObject]@{
                    Action  = "CreateAccount"
                    Message = "No Azure AD user found with UPN $($account.userPrincipalName). Possibly deleted."
                    IsError = $true
                })
        }
        else {
            Write-Warning "DryRun: No Azure AD user found with UPN $($account.userPrincipalName). Possibly deleted."
        }
    }
    else {
        $success = $false  
        $auditLogs.Add([PSCustomObject]@{
                Action  = "CreateAccount"
                Message = "Error correlating to and updating Azure MFA settings of account with id $($aRef). Error Message: $auditErrorMessage"
                IsError = $True
            })
    }
}

if ($null -ne $azureUser.id) { 
    # Set Email Authentication Method
    try {
        if ( ![string]::IsNullOrEmpty($account.email) ) {
            # Microsoft docs: https://docs.microsoft.com/nl-nl/graph/api/emailauthenticationmethod-get?view=graph-rest-beta&tabs=http
            # 3ddfcfc8-9383-446f-83cc-3ab9be4be18f for emailAddress
            $emailTypeId = '3ddfcfc8-9383-446f-83cc-3ab9be4be18f'
            $emailAddress = "$($account.email)"

            $authenticationMethodSet = $false
            if ( !([string]::IsNullOrEmpty(($getEmailAuthenticationMethodResponseValue | Out-String))) ) {
                $authenticationMethodSet = $true
            }

            if ($authenticationMethodSet -eq $false) {
                Write-Verbose "No Email Authentication set. Adding Email Method with value '$($emailAddress)' for account with id $($aRef)"
                
                $baseUri = "https://graph.microsoft.com/"
                $addEmailAuthenticationMethodUri = $baseUri + "/beta/users/$($aRef)/authentication/emailMethods"

                $body = @{
                    "emailAddress" = $($emailAddress)
                }
                $bodyJson = $body | ConvertTo-Json -Depth 10

                if (-Not($dryRun -eq $True)) {
                    $addEmailAuthenticationMethodResponse = Invoke-RestMethod -Uri $addEmailAuthenticationMethodUri -Method Post -Headers $authorization -Body $bodyJson -Verbose:$false
                    
                    $auditLogs.Add([PSCustomObject]@{
                            Action  = "CreateAccount"
                            Message = "Successfully added Email Authentication Method with value '$($emailAddress)' for account with id $($aRef)"
                            IsError = $false
                        })
                }
                else {
                    Write-Warning "DryRun: No Email Authentication set. Adding Email Authentication Method with value '$($emailAddress)' for account with id $($aRef)"
                }
            }        
            else {
                $currentEmail = ($getEmailAuthenticationMethodResponseValue | Where-Object { $_.id -eq $emailTypeId }).emailAddress
            
                if ($account.onlySetEmailWhenEmpty -eq $true) {
                    Write-Warning "Email Authentication Method set to only update when empty. Since this already contains data ($currentEmail), skipped update for account with id $($aRef)"
                }
                else {
                    Write-Verbose "Updating current Email Authentication Method value '$currentEmail' to value '$($emailAddress)' for account with id $($aRef)"

                    $baseUri = "https://graph.microsoft.com/"
                    $addEmailAuthenticationMethodUri = $baseUri + "/beta/users/$($aRef)/authentication/emailMethods/$emailTypeId"

                    $body = @{
                        "emailAddress" = $($emailAddress)
                    }
                    $bodyJson = $body | ConvertTo-Json -Depth 10

                    if (-Not($dryRun -eq $True)) {
                        $addEmailAuthenticationMethodResponse = Invoke-RestMethod -Uri $addEmailAuthenticationMethodUri -Method Put -Headers $authorization -Body $bodyJson -Verbose:$false
                
                        
                        $auditLogs.Add([PSCustomObject]@{
                                Action  = "CreateAccount"
                                Message = "Successfully updated Email Authentication Method value '$currentEmail' to value '$($emailAddress)' for account with id $($aRef)"
                                IsError = $false
                            })
                    }
                    else {
                        Write-Warning "DryRun: Updating current Email Authentication Method value '$currentEmail' to value '$($emailAddress)' for account with id $($aRef)"
                    }
                }
            }
        }
    }
    catch {
        $ex = $PSItem
        $verboseErrorMessage = $ex
        Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($verboseErrorMessage)"

        $auditErrorMessage = ($ex | ConvertFrom-Json).error.message
        $success = $false  
        $auditLogs.Add([PSCustomObject]@{
                Action  = "CreateAccount"
                Message = "Error setting Email Authentication Method with value '$($emailAddress)' for account with id $($aRef). Error message: $($auditErrorMessage)"
                IsError = $True
            })
    }
}

# Send results
$result = [PSCustomObject]@{
    Success          = $success
    AccountReference = $aRef
    AuditLogs        = $auditLogs
    Account          = $account

    # Optionally return data for use in other systems
    ExportData       = [PSCustomObject]@{
        id                = $azureUser.id
        userPrincipalName = $azureUser.userPrincipalName
        email             = $account.email
    }
}

Write-Output $result | ConvertTo-Json -Depth 10