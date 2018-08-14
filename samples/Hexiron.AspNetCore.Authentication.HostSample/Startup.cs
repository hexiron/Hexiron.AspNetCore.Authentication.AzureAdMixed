using Hexiron.AspNetCore.Authentication.AzureAdMixed;
using Hexiron.Azure.ActiveDirectory.Connectors;
using Hexiron.Azure.ActiveDirectory.Connectors.Interfaces;
using Hexiron.Azure.ActiveDirectory.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Hexiron.AspNetCore.Authentication.HostSample
{
    public class Startup
    {
        private readonly IConfiguration _configuration;

        public Startup(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            var azureAdB2CSection = _configuration.GetSection("Authentication:AzureAdB2C");
            services.Configure<AzureAdB2COptions>(azureAdB2CSection);
            var azureAdB2CSettings = azureAdB2CSection.Get<AzureAdB2COptions>();
            // Register cookieauthentication
            services.AddAzureB2CCookieAuthentication(azureAdB2CSettings, "/account/reset", true);
            // Register MVC
            // Set authorizations
            services.AddAuthorization();
            services.AddMvc(config =>
            {
                var policy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();
                config.Filters.Add(new AuthorizeFilter(policy));
            });

            services.AddHttpContextAccessor();
            services.AddTransient<IAzureAdB2CSecuredApiConnector, AzureAdB2CSecuredApiConnector>();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseSession();
            app.UseAuthentication();
            app.UseMvcWithDefaultRoute();
        }
    }
}
