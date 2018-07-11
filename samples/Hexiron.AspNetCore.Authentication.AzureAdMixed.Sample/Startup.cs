using System.Linq;
using Hexiron.Azure.ActiveDirectory.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Hexiron.AspNetCore.Authentication.AzureAdMixed.Sample
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
            // register Azure AD Settings to be able to use the IOptions pattern via DI
            services.Configure<AzureAd>(_configuration.GetSection("Authentication:AzureAd"));
            var azureAdSettings = _configuration.Get<AzureAd>();

            // register Azure B2C Settings to be able to use the IOptions pattern via DI
            services.Configure<AzureAdB2C>(_configuration.GetSection("Authentication:AzureAdB2C"));
            var azureAdB2CSettings = _configuration.Get<AzureAdB2C>();

            // Add JwtBearerAuthentication for Azure AD and B2C
            services.AddAzureAdAndB2CJwtBearerAuthentication(azureAdSettings, azureAdB2CSettings, typeof(Startup).Assembly);

            // You can also only register for Azure AD
            // services.AddAzureAdJwtBearerAuthentication(azureAdSettings, typeof(Startup).Assembly);

            // You can also only register for Azure B2C
            //services.AddAzureB2CJwtBearerAuthentication(azureAdB2CSettings, typeof(Startup).Assembly);

            var filterCollection = new FilterCollection();
            if (!azureAdSettings.Enabled)
            {
                // No authentication
                filterCollection.Add(new AllowAnonymousFilter());
            }
            // Register MVC
            services.AddMvc(options =>
            {
                filterCollection.ToList().ForEach(filter => options.Filters.Add(filter));
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            app.UseMvc();
        }
    }
}
