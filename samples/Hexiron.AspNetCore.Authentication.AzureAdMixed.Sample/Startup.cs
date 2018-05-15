using System.Linq;
using Hexiron.Azure.ActiveDirectory;
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
        private readonly IHostingEnvironment _environment;
        public Startup(IHostingEnvironment environment)
        {
            _environment = environment;
        }
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            // register Azure Settings
            var azureConfiguration = AzureSettingsLoader.LoadAzureAdConfiguration(_environment);
            // register Azure Settings
            services.Configure<AzureAuthenticationSettings>(azureConfiguration);
            var azureSettings = azureConfiguration.Get<AzureAuthenticationSettings>();


            // Add JwtBearerAuthentication
            services.AddAzureJwtBearerAuthentication(azureSettings, typeof(Startup).Assembly);

            
            var filterCollection = new FilterCollection();
            if (!azureSettings.Enabled)
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
