using System;
using System.Linq;
using System.Security.Authentication;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;

namespace Hexiron.AspNetCore.Authentication.AzureAdMixed
{
    public class AzurePolicyRequirement : AuthorizationHandler<AzurePolicyRequirement>, IAuthorizationRequirement
    {
        private readonly string _permission;
        public AzurePolicyRequirement(string permission)
        {
            _permission = permission;
        }
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AzurePolicyRequirement requirement)
        {
            var user = context.User;
            if (user.Identity.IsAuthenticated)
            {
                // if identity is coming from Azure AD classic it should contain the required role
                if (user.IsInRole(_permission))
                {
                    context.Succeed(requirement);
                    return Task.CompletedTask;
                }

                // if identity is coming from Azure AD B2C it should contain the required scope
                // Split the scopes string into an array
                var scopes = context.User.FindFirst(c => c.Type == Claims.SCOPE)?.Value?.Split(' ');
                // Succeed if the scope array contains the required scope
                if (scopes != null && scopes.Any(s => s == _permission))
                {
                    context.Succeed(requirement);
                    return Task.CompletedTask;
                }
            }
            throw new UnauthorizedAccessException("You do not have the right permissions to perform this action. Ask the owner to check your permissions please.");
        }
    }
}
