namespace Hexiron.AspNetCore.Authentication.AzureAdMixed.Models
{
    public class AzureB2CSettings
    {
        //public const string POLICY_AUTHENTICATION_PROPERTY = "Policy";
        private readonly string _azureB2CInstance;

        public AzureB2CSettings()
        {
            _azureB2CInstance = "https://login.microsoftonline.com/tfp";
        }
        public string ClientId { get; set; }
        public string Tenant { get; set; }
        public string SignUpSignInPolicyId { get; set; }
        
        //public string SignInPolicyId { get; set; }
        //public string SignUpPolicyId { get; set; }
        //public string ResetPasswordPolicyId { get; set; }
        //public string EditProfilePolicyId { get; set; }
        //public string RedirectUri { get; set; }

        public string Authority => $"{Domain}/{SignUpSignInPolicyId}/v2.0";
        public string Domain => $"{_azureB2CInstance}/{Tenant}";

        //public string ClientSecret { get; set; }
        
        // a space seperated list of necessary scopes for accessing the api 
       // public string ApiScopes { get; set; }
    }
}
