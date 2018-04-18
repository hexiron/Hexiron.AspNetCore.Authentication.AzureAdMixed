using System;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;

namespace Hexiron.AspNetCore.Authentication.AzureAdMixed
{
    public static class AzureSettingsLoader
    {
        public static IConfigurationRoot LoadAzureAuthenticationSettings(IHostingEnvironment hostingEnvironment)
        {
            var environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
            var builder = new ConfigurationBuilder()
                .SetBasePath(hostingEnvironment.ContentRootPath)
                .AddJsonFile("azureauthenticationsettings.json")
                .AddJsonFile($"azureauthenticationsettings.{environment}.json", optional: true);
            return builder.Build();
        }
    }
}
