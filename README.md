# Hexiron.AspNetCore.Authentication.AzureAdMixed
An extension on the current Microsoft.AspNetCore.Authentication library that enables token validation for both AzureAd and AzureB2C.

It also scans your controllers for custom policies and will activate them during startup. See the documentation  below for more info.

## Usage ##
After installing the nuget package, a new settingsfile named "AzureAuthenticationSettings.json" will be added to the project. In this file, you need to fill in the Azure settings from your Azure AD tenant(s).

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