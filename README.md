# HelloID-Conn-Prov-Target-Azure-MFASettings-Email

| :information_source: Information |
|:---------------------------|
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.       |
<br />
<p align="center">
  <img src="https://www.tools4ever.nl/connector-logos/azureactivedirectory-logo.png">
</p>

## Versioning
| Version | Description | Date |
| - | - | - |
| 1.1.0   | Updated to support deleted users and improved logging | 2022/08/05  |
| 1.0.0   | Initial release | 2021/05/14  |

<!-- TABLE OF CONTENTS -->
## Table of Contents
- [HelloID-Conn-Prov-Target-Azure-MFASettings-Email](#helloid-conn-prov-target-azure-mfasettings-email)
  - [Versioning](#versioning)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Getting the Azure AD graph API access](#getting-the-azure-ad-graph-api-access)
    - [Application Registration](#application-registration)
    - [Configuring App Permissions](#configuring-app-permissions)
    - [Authentication and Authorization](#authentication-and-authorization)
    - [Prerequisites](#prerequisites)
    - [Remarks](#remarks)
  - [Getting help](#getting-help)
  - [HelloID docs](#helloid-docs)

## Introduction
The interface to communicate with Microsoft Azure AD is through the Microsoft Graph API.

With this connector we can create the set the MFA Phone methods, optionally we can enable the SMS Sign In as well.

> Note that this makes use of beta endpoints of the Microsoft Graph API.

The HelloID connector consists of the template scripts shown in the following table.

| Action                          | Action(s) Performed                                                   | Comment   | 
| ------------------------------- | --------------------------------------------------------------------- | --------- |
| create.ps1                      | Correlate to and add/update MFA email method of AzureAD user  |           |
| update.ps1                      | Update MFA email method of AzureAD user                        |           |
| delete.ps1                      | Delete MFA email method of AzureAD user                        | Be careful when implementing this! There is no way to restore deleted the data. |

<!-- GETTING STARTED -->
## Getting the Azure AD graph API access

By using this connector you will have the ability to manage the Phone Authentication Method for an Azure AD User.

### Application Registration
The first step to connect to Graph API and make requests, is to register a new <b>Azure Active Directory Application</b>. The application is used to connect to the API and to manage permissions.

* Navigate to <b>App Registrations</b> in Azure, and select “New Registration” (<b>Azure Portal > Azure Active Directory > App Registration > New Application Registration</b>).
* Next, give the application a name. In this example we are using “<b>HelloID PowerShell</b>” as application name.
* Specify who can use this application (<b>Accounts in this organizational directory only</b>).
* Specify the Redirect URI. You can enter any url as a redirect URI value. In this example we used http://localhost because it doesn't have to resolve.
* Click the “<b>Register</b>” button to finally create your new application.

Some key items regarding the application are the Application ID (which is the Client ID), the Directory ID (which is the Tenant ID) and Client Secret.

### Configuring App Permissions
The [Microsoft Graph documentation](https://docs.microsoft.com/en-us/graph) provides details on which permission are required for each permission type.

To assign your application the right permissions, navigate to <b>Azure Portal > Azure Active Directory >App Registrations</b>.
Select the application we created before, and select “<b>API Permissions</b>” or “<b>View API Permissions</b>”.
To assign a new permission to your application, click the “<b>Add a permission</b>” button.
From the “<b>Request API Permissions</b>” screen click “<b>Microsoft Graph</b>”.
For this connector the following permissions are used as <b>Application permissions</b>:
*	Read and Write aall user’s authentication methods by using <b><i>UserAuthenticationMethod.ReadWrite.All</i></b>

These permissions are based on the Microsoft docs articles:
*	https://docs.microsoft.com/nl-nl/graph/api/authentication-list-phonemethods?view=graph-rest-beta&tabs=http
*	https://docs.microsoft.com/nl-nl/graph/api/authentication-post-phonemethods?view=graph-rest-beta&tabs=http
*	https://docs.microsoft.com/nl-nl/graph/api/phoneauthenticationmethod-update?view=graph-rest-beta&tabs=http
*	https://docs.microsoft.com/nl-nl/graph/api/phoneauthenticationmethod-delete?view=graph-rest-beta&tabs=http

Some high-privilege permissions can be set to admin-restricted and require an administrators consent to be granted.

To grant admin consent to our application press the “<b>Grant admin consent for TENANT</b>” button.

### Authentication and Authorization
There are multiple ways to authenticate to the Graph API with each has its own pros and cons, in this example we are using the Authorization Code grant type.

*	First we need to get the <b>Client ID</b>, go to the <b>Azure Portal > Azure Active Directory > App Registrations</b>.
*	Select your application and copy the Application (client) ID value.
*	After we have the Client ID we also have to create a <b>Client Secret</b>.
*	From the Azure Portal, go to <b>Azure Active Directory > App Registrations</b>.
*	Select the application we have created before, and select "<b>Certificates and Secrets</b>". 
*	Under “Client Secrets” click on the “<b>New Client Secret</b>” button to create a new secret.
*	Provide a logical name for your secret in the Description field, and select the expiration date for your secret.
*	It's IMPORTANT to copy the newly generated client secret, because you cannot see the value anymore after you close the page.
*	At least we need to get is the <b>Tenant ID</b>. This can be found in the Azure Portal by going to <b>Azure Active Directory > Custom Domain Names</b>, and then finding the .onmicrosoft.com domain.

### Prerequisites
- Azure AD environment
- Registered App Registration in AzureAD with permission to Microsoft Graph API UserAuthenticationMethod.ReadWrite.All. The following values are needed to connect
  - Tenant ID
  - Applciation ID
  - Application Secret

### Remarks
 - We make use of beta endpoints of the Microsoft Graph API. We cannot guarantuee their functionality.

## Getting help
> _For more information on how to configure a HelloID PowerShell connector, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/360012558020-Configure-a-custom-PowerShell-target-system) pages_

> _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_

## HelloID docs
The official HelloID documentation can be found at: https://docs.helloid.com/
