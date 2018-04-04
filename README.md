# Getting started with ASP.NET Core 2 and Azure AD/B2C
Hexiron.AspNetCore.Authentication.AzureAdMixed contains an extension on the current Microsoft.AspNetCore.Authentication library that enables token validation for both AzureAd and AzureB2C.

It also scans your controllers for custom policies and will activate them during startup. See the documentation  below for more info.

### 1. Create a new ASP.NET Core project ###
In Visual Studio 2017.
### 2. Add dependency in csproj manually or using NuGet ###
Install the latest:

- Hexiron.AspNetCore.Authentication.AzureAdMixed 

in csproj:

```xml
<PackageReference Include="Hexiron.AspNetCore.Authentication.AzureAdMixed" Version="x.x.x" />
```

### 3. Create an azureauthenticationsettings.json file. 
Create azureauthenticationsettings.json (lowercase all) file in the root of your project.  
In this file, you need to fill in the Azure settings from your Azure AD tenant(s).
We use the following example:

```json
{
  "Enabled": true,
  "AzureAdSettings": {
    "Tenant": "tentantname.onmicrosoft.com",
    "ClientId": "aaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaa"
  },
  "AzureB2CSettings": {
    "ClientId": "aaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaa",
    "Tenant": "tentantname.onmicrosoft.com",
    "SignUpSignInPolicyId": "defined_Policy_from_Azure",
    "ResetPasswordPolicyId": "defined_Policy_from_Azure",
    "EditProfilePolicyId": "defined_Policy_from_Azure",
    "RedirectUri": "https://.../signin-oidc",
    "ClientSecret": "secret"
  }
}
```
### 4. Enable copy to bin folder

Enable copy to bin folder for azureauthenticationsettings.json by changing it properties


or edit `.csproj` file manually and add:
```xml
  <ItemGroup>
    <Content Update="azureauthenticationsettings.json" CopyToOutputDirectory="PreserveNewest" />
  </ItemGroup>
```

### 5. Register the serivice for the middleware
In the startup.cs class, register the following service:
  
```csharp  
public void ConfigureServices(IServiceCollection services)  
    {  
        //...  
        services.AddAzureJwtBearerAuthentication(_hostingEnvironment, typeof(Startup).Assembly);
//...  
    }  
```

Make sure you can inject the IHostingEnvironment interface. This is needed to load the correct settingsfile. You can inject the IHostingEnvironmnet in the startup.cs class by using property injection. The default WebhostBuilder from AspNetCore has already registered the implementation for you.  
Also specify the assembly where your controllers are situated so it can load the correct Authorization policies from you controllers.


```csharp  
private readonly IHostingEnvironment _environment;
        public Startup(IHostingEnvironment environment)
        {
            _environment = environment;
        }
```