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

# Troubleshooting
# $dryRun = $false
# $aRef = ''

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
    $searchUri = $baseGraphUri + "v1.0/users/$($aRef)"

    Write-Verbose "Querying Azure AD user with UPN $($aRef)"
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
            Action  = "DeleteAccount"
            Message = "Error correlating to and updating Azure MFA settings of account with id $($aRef). Error Message: $auditErrorMessage"
            IsError = $True
        })

    if ($auditErrorMessage -Like "*Resource '$($aRef)' does not exist*") {
        if (-Not($dryRun -eq $True)) {
            $auditLogs.Add([PSCustomObject]@{
                    Action  = "DeleteAccount"
                    Message = "No Azure AD user found with UPN $($aRef). Possibly already deleted, skipping action."
                    IsError = $true
                })
        }
        else {
            Write-Warning "DryRun: No Azure AD user found with UPN $($aRef). Possibly already deleted, skipping action."
        }     
    }
    else {
        $success = $false  
        $auditLogs.Add([PSCustomObject]@{
                Action  = "DeleteAccount"
                Message = "Error correlating to and updating Azure MFA settings of account with id $($aRef). Error Message: $auditErrorMessage"
                IsError = $True
            })
    }
}

if ($null -ne $azureUser.id) {
    # Remove Email Authentication Method
    try {
        # Microsoft docs: https://docs.microsoft.com/nl-nl/graph/api/emailauthenticationmethod-get?view=graph-rest-beta&tabs=http
        # 3ddfcfc8-9383-446f-83cc-3ab9be4be18f for emailAddress
        $emailTypeId = '3ddfcfc8-9383-446f-83cc-3ab9be4be18f'

        $authenticationMethodSet = $false
        if ( !([string]::IsNullOrEmpty(($getEmailAuthenticationMethodResponseValue | Out-String))) ) {
            $authenticationMethodSet = $true
        }

        if ($authenticationMethodSet -eq $false) {
            Write-Verbose "No Email Authentication set for account with id $($aRef). Nothing to delete"
        }
        else {
            $currentEmail = ($getEmailAuthenticationMethodResponseValue | Where-Object { $_.id -eq $emailTypeId }).emailAddress
            Write-Verbose "Deleting current Email Authentication with value '$($currentEmail)' for account with id $($aRef)"

            $baseUri = "https://graph.microsoft.com/"
            $deleteEmailAuthenticationMethodUri = $baseUri + "/beta/users/$($aRef)/authentication/emailMethods/$emailTypeId"

            if (-Not($dryRun -eq $True)) {
                $deleteEmailAuthenticationMethodResponse = Invoke-RestMethod -Uri $deleteEmailAuthenticationMethodUri -Method Delete -Headers $authorization -Body $bodyJson -Verbose:$false

                $auditLogs.Add([PSCustomObject]@{
                        Action  = "DeleteAccount"
                        Message = "Successfully deleted Email Authentication Method with value '$($currentEmail)' for account with id $($aRef)"
                        IsError = $false
                    })
            }
            else {
                Write-Warning "DryRun: Deleting current Email Authentication Method with value '$($currentEmail)' for account with id $($aRef)"
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
                Action  = "DeleteAccount"
                Message = "Error deleting Email Authentication Method with value '$($currentEmail)' for account with id $($aRef). Error Message: $auditErrorMessage"
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
    PreviousAccount  = $previousAccount

    # Optionally return data for use in other systems
    ExportData       = [PSCustomObject]@{
        userPrincipalName = $account.userPrincipalName
        email             = ''
    }
}

Write-Output $result | ConvertTo-Json -Depth 10