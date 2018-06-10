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
            services.Configure<AzureAdSettings>(_configuration.GetSection("AzureAdSettings"));
            var azureAdSettings = _configuration.Get<AzureAdSettings>();

            // register Azure B2C Settings to be able to use the IOptions pattern via DI
            services.Configure<AzureB2CSettings>(_configuration.GetSection("AzureB2CSettings"));
            var azureB2CSettings = _configuration.Get<AzureB2CSettings>();

            // Add JwtBearerAuthentication for Azure AD and B2C
            services.AddAzureAdAndB2CJwtBearerAuthentication(azureAdSettings, azureB2CSettings, typeof(Startup).Assembly);

            // You can also only register for Azure AD
            // services.AddAzureAdJwtBearerAuthentication(azureAdSettings, typeof(Startup).Assembly);

            // You can also only register for Azure B2C
            //services.AddAzureB2CJwtBearerAuthentication(azureB2CSettings, typeof(Startup).Assembly);

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
