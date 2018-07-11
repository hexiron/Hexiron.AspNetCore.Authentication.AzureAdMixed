# Getting started with ASP.NET Core 2 and Azure AD/B2C

[![Build status](https://ci.appveyor.com/api/projects/status/11r3paicwclfblmc/branch/master?svg=true)](https://ci.appveyor.com/project/mkeymolen/hexiron-aspnetcore-authentication-azureadmixed/branch/master)  [![license](https://img.shields.io/github/license/hexiron/Hexiron.AspNetCore.Authentication.AzureAdMixed.svg?maxAge=2592000)](https://github.com/hexiron/Hexiron.AspNetCore.Authentication.AzureAdMixed/blob/master/LICENSE)  [![NuGet](https://img.shields.io/nuget/v/Hexiron.AspNetCore.Authentication.AzureAdMixed.svg?maxAge=86400)](https://www.nuget.org/packages/Hexiron.AspNetCore.Authentication.AzureAdMixed/)

Hexiron.AspNetCore.Authentication.AzureAdMixed contains an extension on the current Microsoft.AspNetCore.Authentication library that enables  you to use both AzureAD and Azure AD B2C combined.
With this extension you can accept JWT tokens issued by either an Azure AD or Azure B2C tenant. 

You can also define your own authorize attributes with the name of the scopes in Azure B2C and/or Application permissions in Azure AD. This enables you to do fine grained authorization on API method level!

**Features**  

- Validate Azure AD JWT tokens
- Enables the use of Authorization policies with the same name as the Application Permission defined in Azure AD
- Validate Azure AD B2C JWT tokens
- Enables the use of Authorization policies with the same name as the scopes defined in Azure B2C
- TODO: ASPNET.Core OpenIdConnect + authorization flow with Azure B2C for user login

### 1. Create a new ASP.NET Core project ###
In Visual Studio 2017.
### 2. Add dependency in csproj manually or using NuGet ###
Install the latest:

- Hexiron.AspNetCore.Authentication.AzureAdMixed 

in csproj:

```xml

	<PackageReference Include="Hexiron.AspNetCore.Authentication.AzureAdMixed" Version="x.x.x" />
```

### 3. Make sure you register the settings in the startup class.

You have multiple possibilities to load the settings in the startup class so they can be used by the IOptions pattern in the connectors.  
- Add the settings in you appsettings.json file (and corresponding environment files)
- Add the settings in the Azure web application settings online. Recomended for the secrets, so they are not exposed in source code

See example below:

```json

	{
	  "Authentication": {
	    "AzureAd": {
	      "Enabled": true,
	      "Tenant": "tentantname.onmicrosoft.com",
	      "ClientId": "aaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaa",
	      "ClientSecret": "avoid this and get if from azure vault or imediately from appsettings in azure webapp"
	    },
	    "AzureAdB2C": {
	      "Enabled": true,
	      "ClientId": "aaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaa",
	      "Tenant": "tentantname.onmicrosoft.com",
	      "SignUpSignInPolicyId": "defined_Policy_from_Azure",
	      "ResetPasswordPolicyId": "defined_Policy_from_Azure",
	      "EditProfilePolicyId": "defined_Policy_from_Azure",
	      "RedirectUri": "https://.../signin-oidc",
	      "ClientSecret": "avoid this and get if from azure vault or imediately from appsettings in azure webapp"
	    }
	  }
	}
```

```csharp  

	private readonly IConfiguration _configuration;

	public Startup(IConfiguration configuration)
	{
		_configuration = configuration;
	}

    public void ConfigureServices(IServiceCollection services)
    {
		// ...
		// register Azure AD Settings to be able to use the IOptions pattern via DI
		services.Configure<AzureAd>(_configuration.GetSection("Authentication:AzureAd"));
		var azureAdSettings = _configuration.Get<AzureAd>();

		// register Azure B2C Settings to be able to use the IOptions pattern via DI
		services.Configure<AzureAdB2C>(_configuration.GetSection("Authentication:AzureAdB2C"));
		var azureB2CSettings = _configuration.Get<AzureAdB2C>();
		//...
	}
```

### 4. Register the serivice for the middleware
In the startup.cs class, register the middleware:  
You have multiple possibilities:  
- You only register Azure AD JWT validation
- You only register Azure B2C JWT validation
- You register both Azure AD and Azure B2C JWT validation
  
```csharp  

	public void ConfigureServices(IServiceCollection services)  
	{  
		// You can only register for Azure AD
		// services.AddAzureAdJwtBearerAuthentication(azureAd, typeof(Startup).Assembly);
		// You can also only register for Azure B2C
		//services.AddAzureB2CJwtBearerAuthentication(azureB2CSettings, typeof(Startup).Assembly);
	
		// Register for Azure AD and B2C
		services.AddAzureAdAndB2CJwtBearerAuthentication(azureAdSettings, azureB2CSettings, typeof(Startup).Assembly);
	}  
```

### 5. Create your Azure B2C tenant and register you API app
TODO How to create tenant

- Add your tenant id to the settings file (...onmicrosoft.com)
- Create your API app in your B2C tenant. Add the B2C suffix for simplicity later on
- Copy the ApplicationId (=ClientId) to the settingsfiles under the AzureB2CSettings part
- Create a Sign-up/Sign-in policy and select the attributes you want to ask to fill in by the user (Sign-up attributes) and the attributes you want to send to the API (Application claims)
- Copy the name of this sign-up/sign-in policy and add it to the AzureB2CSettings part (SignUpSignInPolicyId)
- Go to "Published scopes" and create the scopes you need to access your APIs (you will add the same scope name as an Authorization policy attribute on your API methods)  
Example: "read:methods"
- Add an Authorization attribute and register this scope as a policy on your API method

```csharp

	[Authorize("read:methods")]
	public IActionResult Methods()
	{
		return Ok();
	}
```

### 6. Register your Azure AD application if you need API to API communication (client credentials flow/ machine to machine communication

- Within the same B2C Active directory tenant in Azure, go to all services -> Azure Active directory
- Go to App registrations and create your API app.  For simplicity, take the same name as the name you've chosen in Azure B2C but remove the B2C suffix
- Copy the ApplicationId (=ClientId) to the settingsfiles under the AzureAdSettings part
- Open the manifest and add the scopes as AppRoles:  
Make sure you create unique identifiers as Id

```json

	"appRoles": [
	    {
	      "allowedMemberTypes": [
	        "Application"
	      ],
	      "displayName": "Read methods",
	      "id": "aaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaa",
	      "isEnabled": true,
	      "description": "Can read methods",
	      "value": "read:methods"
	    },
	    {
	      "allowedMemberTypes": [
	        "Application"
	      ],
	      "displayName": ".....",
	      "id": "aaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaa",
	      "isEnabled": true,
	      "description": ".......",
	      "value": "...:..."
	    }
	]
```

### 7. Register your client apps and give them the permissions to the scopes
TODO How to create tenant

**In Azure AD B2C**
1. Create a new app for your client
2. Go to API Access
3. Add
4. Select your API app
5. Select the scopes you want to give access to

**In Azure Acitive Directory**
1. Create a new app for your client in App registrations
2. Go to Settings
3. Required Permissions
4. Add
5. Select API
6. Fill in the name of your api app without
7. Select the Azure AD app (without the B2C suffix)
8. Select the permissions you want to give access to
9. Don't forget to click on "Grant Permissions"

The scopes will now be added to the JWT token of the client and validated at API side.