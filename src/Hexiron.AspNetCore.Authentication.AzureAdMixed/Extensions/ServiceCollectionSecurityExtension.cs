using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Threading.Tasks;
using Hexiron.AspNetCore.Authentication.AzureAdMixed.Models;
using Hexiron.Azure.ActiveDirectory.Connectors.Interfaces;
using Hexiron.Azure.ActiveDirectory.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Identity.Client;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Hexiron.AspNetCore.Authentication.AzureAdMixed
{
    public static class ServiceCollectionSecurityExtension
    {
        public static void AddAzureAdJwtBearerAuthentication(this IServiceCollection services, AzureAdOptions azureAdOptions, Assembly controllerAssembly, string policyIdentifier = "")
        {
            // Setup Authentication
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = AzureJwtSchemes.AZURE_AD_AUTHENTICATION_SCHEME;
            }).AddAzureAdJwtBearer(azureAdOptions);

            // Setup Authorization
            var customPolicyBuilder = new AuthorizationPolicyBuilder(AzureJwtSchemes.AZURE_AD_AUTHENTICATION_SCHEME);
            var defaultPolicy = customPolicyBuilder.RequireAuthenticatedUser().Build();

            // scan custom defined policies in Authorization attribute to add as custom policies
            var customDefinedPolicies = FindAuthorizationPolicies(controllerAssembly, policyIdentifier);
            // add these custom policies to the authorization process
            services.AddAuthorization(o =>
            {
                o.DefaultPolicy = defaultPolicy;
                customDefinedPolicies.ForEach(customDefinedPolicy => o.AddPolicy(customDefinedPolicy,
                    policy =>
                    {
                        policy.Requirements.Add(new AzurePolicyRequirement(customDefinedPolicy));
                        policy.AuthenticationSchemes.Add(AzureJwtSchemes.AZURE_AD_AUTHENTICATION_SCHEME);
                    }));
            });
        }

        public static void AddAzureB2CJwtBearerAuthentication(this IServiceCollection services, AzureAdB2COptions azureB2COptions, Assembly controllerAssembly, string policyIdentifier = "")
        {
            // Setup Authentication
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = AzureJwtSchemes.AZURE_AD_AUTHENTICATION_SCHEME;
            }).AddAzureB2CJwtBearer(azureB2COptions);

            // Setup Authorization
            var customPolicyBuilder = new AuthorizationPolicyBuilder(AzureJwtSchemes.AZURE_AD_B2_C_AUTHENTICATION_SCHEME);
            var defaultPolicy = customPolicyBuilder.RequireAuthenticatedUser().Build();

            // scan custom defined policies in Authorization attribute to add as custom policies
            var customDefinedPolicies = FindAuthorizationPolicies(controllerAssembly, policyIdentifier);
            // add these custom policies to the authorization process
            services.AddAuthorization(o =>
            {
                o.DefaultPolicy = defaultPolicy;
                customDefinedPolicies.ForEach(customDefinedPolicy => o.AddPolicy(customDefinedPolicy,
                    policy =>
                    {
                        policy.Requirements.Add(new AzurePolicyRequirement(customDefinedPolicy));
                        policy.AuthenticationSchemes.Add(AzureJwtSchemes.AZURE_AD_B2_C_AUTHENTICATION_SCHEME);
                    }));
            });
        }

        public static void AddAzureAdAndB2CJwtBearerAuthentication(this IServiceCollection services, AzureAdOptions azureAdOptions, AzureAdB2COptions azureB2COptions, Assembly controllerAssembly, string policyIdentifier = "")
        {
            // Setup Authentication
            services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = AzureJwtSchemes.AZURE_AD_AUTHENTICATION_SCHEME;
                })
                .AddAzureB2CJwtBearer(azureB2COptions)
                .AddAzureAdJwtBearer(azureAdOptions);

            // Setup Authorization
            var customPolicyBuilder = new AuthorizationPolicyBuilder(AzureJwtSchemes.AZURE_AD_B2_C_AUTHENTICATION_SCHEME, AzureJwtSchemes.AZURE_AD_AUTHENTICATION_SCHEME);
            var defaultPolicy = customPolicyBuilder.RequireAuthenticatedUser().Build();

            // scan custom defined policies in Authorization attribute to add as custom policies
            var customDefinedPolicies = FindAuthorizationPolicies(controllerAssembly, policyIdentifier);
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

        public static AuthenticationBuilder AddAzureB2CCookieAuthentication(this IServiceCollection services, AzureAdB2COptions azureAdB2CSettings, string resetPasswordUrl,  bool requestAccessToken, bool loadMemberGroupsAsRoles = false)
        {
            services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromMinutes(20);
                // no javascript calls to cookie
                options.Cookie.HttpOnly = true;
            });
            return services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                })
                .AddCookie()
                .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options => 
                {
                    options.ClientId = azureAdB2CSettings.ClientId;
                    // Set the authority to your Azure domain
                    options.Authority = azureAdB2CSettings.Authority;

                    options.UseTokenLifetime = true;
                    options.TokenValidationParameters = new TokenValidationParameters() { NameClaimType = "name" };

                    options.Events = new OpenIdConnectEvents
                    {
                        OnRedirectToIdentityProvider = (context) =>
                        {
                            // pass language (adds ui_locales to query string)
                            var requestCulture = context.HttpContext.Features.Get<IRequestCultureFeature>();
                            var lang = requestCulture?.RequestCulture.Culture.TextInfo.ToTitleCase(
                                requestCulture.RequestCulture.Culture.TwoLetterISOLanguageName);
                            if (lang != null)
                            {
                                context.ProtocolMessage.UiLocales = lang;
                            }
                            
                            // no explict policy or default policy passed - just continue
                            var defaultPolicy = azureAdB2CSettings.DefaultPolicy;
                            if (!context.Properties.Items.TryGetValue(AzureAdB2COptions.POLICY_AUTHENTICATION_PROPERTY, out var policy) || policy.Equals(defaultPolicy))
                            {
                                if (requestAccessToken)
                                {
                                    context.ProtocolMessage.Scope += $" offline_access {String.Join(" ", azureAdB2CSettings.ApiScopes)}";
                                    context.ProtocolMessage.ResponseType = OpenIdConnectResponseType.CodeIdToken;
                                }
                            }
                            else
                            {
                                // explict policy set in context => see AuthenticationProperties.Items.Add("Policy", desired policy_name)
                                // example --> custom policy has been set to reset password
                                context.ProtocolMessage.Scope = OpenIdConnectScope.OpenIdProfile;
                                context.ProtocolMessage.ResponseType = OpenIdConnectResponseType.IdToken;
                                context.ProtocolMessage.IssuerAddress = context.ProtocolMessage.IssuerAddress.ToLower().Replace($"/{defaultPolicy.ToLower()}/", $"/{policy.ToLower()}/");
                                context.Properties.Items.Remove(AzureAdB2COptions.POLICY_AUTHENTICATION_PROPERTY);
                            }
                            return Task.CompletedTask;
                        },
                        OnRemoteFailure = (context) =>
                        {
                            context.HandleResponse();
                            // Handle the error code that Azure AD B2C throws when trying to reset a password from the login page 
                            // because password reset is not supported by a "sign-up or sign-in policy"
                            if (context.Failure is OpenIdConnectProtocolException && context.Failure.Message.Contains("AADB2C90118"))
                            {
                                // If the user clicked the reset password link, redirect to the reset password route
                                context.Response.Redirect(resetPasswordUrl);
                            }
                            else if (context.Failure is OpenIdConnectProtocolException && context.Failure.Message.Contains("access_denied"))
                            {
                                context.Response.Redirect("/");
                            }
                            else
                            {
                                throw context.Failure;
                            }
                            return Task.FromResult(0);
                        },
                        OnAuthorizationCodeReceived = async (context) =>
                        {
                            // Use MSAL to swap the code for an access token
                            // Extract the code from the response notification
                            var auhtorizationCode = context.ProtocolMessage.Code;

                            string signedInUserId = context.Principal.FindFirst(ClaimTypes.NameIdentifier).Value;
                            var userTokenCache = new MsalSessionCache(signedInUserId, context.HttpContext).GetMsalCacheInstance();
                            var clientApplication = new ConfidentialClientApplication(azureAdB2CSettings.ClientId, azureAdB2CSettings.Authority, azureAdB2CSettings.RedirectUri, new ClientCredential(azureAdB2CSettings.ClientSecret), userTokenCache, null);

                            try
                            {
                                var result = await clientApplication.AcquireTokenByAuthorizationCodeAsync(auhtorizationCode, azureAdB2CSettings.ApiScopes);
                                context.HandleCodeRedemption(result.AccessToken, result.IdToken);
                            }
                            catch (Exception e)
                            {
                                throw new Exception("AcquireTokenByAuthorizationCodeAsync failed", e);
                            }
                        },
                        // handle the logout redirection 
                        OnRedirectToIdentityProviderForSignOut = (context) =>
                        {
                            var logoutUri = $"{azureAdB2CSettings.Domain}/v2/logout?client_id={azureAdB2CSettings.ClientId}";

                            var postLogoutUri = context.Properties.RedirectUri;
                            if (!string.IsNullOrEmpty(postLogoutUri))
                            {
                                if (postLogoutUri.StartsWith("/"))
                                {
                                    // transform to absolute
                                    var request = context.Request;
                                    postLogoutUri = request.Scheme + "://" + request.Host + request.PathBase +
                                                    postLogoutUri;
                                }
                                logoutUri += $"&returnTo={Uri.EscapeDataString(postLogoutUri)}";
                            }
                            // set the audience parameter to get also an access token back after login to be able to call APIs of this application
                            context.ProtocolMessage.SetParameter("audience", azureAdB2CSettings.ClientId);
                            context.Response.Redirect(logoutUri);
                            context.HandleResponse();

                            return Task.CompletedTask;
                        }
                    };
                    if (loadMemberGroupsAsRoles)
                    {
                        //Check via Azure Graph API if user is in correct group
                        options.Events.OnTokenValidated = context =>
                        {
                            var serviceProvider = services.BuildServiceProvider();
                            // resolve GraphApiConnector
                            var graphApiConnector = serviceProvider.GetService<IGraphApiConnector>();
                            if (graphApiConnector == null)
                            {
                                throw new Exception("No implementation has been registered for IGraphApiConnector");
                            }
                            // Get membergroups for user from AzureAd
                            var signedInUserId = context.Principal.FindFirst(ClaimTypes.NameIdentifier).Value;
                            var memberGroups = graphApiConnector.GetMemberGroupsForUser(signedInUserId).GetAwaiter()
                                .GetResult();
                            // create roleclaim
                            var roleClaims = memberGroups.Select(x => new Claim(ClaimTypes.Role, x));
                            // Add RoleClaim to useridentity
                            ((ClaimsIdentity) context.Principal.Identity).AddClaims(roleClaims);

                            return Task.FromResult(0);
                        };
                    }
                });
        }

        public static List<string> FindAuthorizationPolicies(this Assembly assembly, string policyIdentifier)
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

        private static AuthenticationBuilder AddAzureAdJwtBearer(this AuthenticationBuilder authenticationBuilder, AzureAdOptions azureAdOptions)
        {
            // add Azure AD settings
            return authenticationBuilder
                .AddJwtBearer(AzureJwtSchemes.AZURE_AD_AUTHENTICATION_SCHEME, options =>
                {
                    options.Authority = azureAdOptions.Authority;
                    options.Audience = azureAdOptions.ClientId;
                });
        }

        private static AuthenticationBuilder AddAzureB2CJwtBearer(this AuthenticationBuilder authenticationBuilder, AzureAdB2COptions azureB2COptions)
        {
            // add Azure AD B2C settings
            return authenticationBuilder
                .AddJwtBearer(AzureJwtSchemes.AZURE_AD_B2_C_AUTHENTICATION_SCHEME, options =>
                {
                    options.Authority = azureB2COptions.Authority;
                    options.Audience = azureB2COptions.ClientId;

                });
        }

    }
}
