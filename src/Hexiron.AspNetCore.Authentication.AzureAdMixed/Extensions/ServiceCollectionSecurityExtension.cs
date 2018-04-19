﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using Hexiron.AspNetCore.Authentication.AzureAdMixed.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Hexiron.AspNetCore.Authentication.AzureAdMixed
{
    public static class ServiceCollectionSecurityExtension
    {
        private static IConfiguration s_azureConfiguration;

        public static AzureAuthenticationSettings RegisterAzureSettings(this IServiceCollection services, IHostingEnvironment hostingEnvironment)
        {
            if (s_azureConfiguration == null)
            {
                s_azureConfiguration = AzureSettingsLoader.LoadAzureAuthenticationSettings(hostingEnvironment);
            }
            services.Configure<AzureAuthenticationSettings>(s_azureConfiguration);
            return s_azureConfiguration.Get<AzureAuthenticationSettings>();
        }

        public static void AddAzureJwtBearerAuthentication(this IServiceCollection services, IHostingEnvironment hostingEnvironment, Assembly controllerAssembly, string policyIdentifier = "")
        {
            if (s_azureConfiguration == null)
            {
                s_azureConfiguration = AzureSettingsLoader.LoadAzureAuthenticationSettings(hostingEnvironment);
            }
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();

            var azureSettings = s_azureConfiguration.Get<AzureAuthenticationSettings>();
            // Setup Authentication
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = AzureJwtSchemes.AZURE_AD_AUTHENTICATION_SCHEME;
            })
                // add Azure AD B2C settings
                .AddJwtBearer(AzureJwtSchemes.AZURE_AD_AUTHENTICATION_SCHEME, options =>
                {
                    options.Authority = azureSettings.AzureB2CSettings.Authority;
                    options.Audience = azureSettings.AzureB2CSettings.ClientId;

                })
                // add Azure AD settings
                .AddJwtBearer(AzureJwtSchemes.AZURE_AD_B2_C_AUTHENTICATION_SCHEME, options =>
                {
                    options.Authority = azureSettings.AzureAdSettings.Authority;
                    options.Audience = azureSettings.AzureAdSettings.ClientId;
                });

            // Setup Authorization
            var customPolicyBuilder = new AuthorizationPolicyBuilder(AzureJwtSchemes.AZURE_AD_B2_C_AUTHENTICATION_SCHEME, AzureJwtSchemes.AZURE_AD_AUTHENTICATION_SCHEME);
            var defaultPolicy = customPolicyBuilder.RequireAuthenticatedUser().Build();

            // scan custom defined policies in Authorization attribute to add as custom policies
            var customDefinedPolicies = FindPolicyNames(controllerAssembly, policyIdentifier);
            // add these custom policies to the authorization process
            services.AddAuthorization(o =>
            {
                o.DefaultPolicy = defaultPolicy;
                customDefinedPolicies.ForEach(customDefinedPolicy => o.AddPolicy(customDefinedPolicy,
                    policy =>
                    {
                        policy.Requirements.Add(new AzurePolicyRequirement(customDefinedPolicy));
                        policy.AuthenticationSchemes.Add(AzureJwtSchemes.AZURE_AD_B2_C_AUTHENTICATION_SCHEME);
                        policy.AuthenticationSchemes.Add(AzureJwtSchemes.AZURE_AD_AUTHENTICATION_SCHEME);
                    }));
            });
        }

        public static List<string> FindPolicyNames(Assembly assembly, string policyIdentifier)
        {
            var authorizeAttributes = new List<AuthorizeAttribute>();
            //filter out only controllers
            var controllerTypes = assembly.GetTypes()
                                          .Where(type => typeof(Controller)
                                          .IsAssignableFrom(type));
            foreach (var controller in controllerTypes)
            {
                // add all class authorize attributes to list
                controller.GetCustomAttributes(typeof(AuthorizeAttribute)).ToList().ForEach(x => authorizeAttributes.Add((AuthorizeAttribute)x));

                // check if there are also authorize attributes on methods
                controller.GetMembers()
                    .Where(x => x.GetCustomAttributes(typeof(AuthorizeAttribute), false).Length > 0)
                    .ToList()
                    .ForEach(method =>
                    {
                        // add all authorize attributes to the list
                        method.GetCustomAttributes(typeof(AuthorizeAttribute)).ToList()
                            .ForEach(x => authorizeAttributes.Add((AuthorizeAttribute)x));
                    });
            }

            var policies = new List<string>();
            // check if policies are starting with the correct policyIdentifier
            authorizeAttributes.ForEach(x =>
            {
                if (!string.IsNullOrEmpty(x.Policy) && x.Policy.StartsWith(policyIdentifier, StringComparison.OrdinalIgnoreCase))
                {
                    policies.Add(x.Policy);
                }
            });
            return policies;
        }
    }
}
