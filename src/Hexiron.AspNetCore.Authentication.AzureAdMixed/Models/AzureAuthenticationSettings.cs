namespace Hexiron.AspNetCore.Authentication.AzureAdMixed.Models
{
    public class AzureAuthenticationSettings
    {
        public bool Enabled { get; set; }
        public AzureB2CSettings AzureB2CSettings { get; set; }
        public AzureAdSettings AzureAdSettings { get; set; }
    }
}
