using IdentityModel;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OpenIdConnect;
using Owin;
using System.Security.Claims;

namespace UmbracoIdentity.IdentityServer
{
    public static class AppBuilderExtensions
    {
        public static void UseIdentityServerAuthentication(this IAppBuilder app,
            string authority,
            string clientId,
            string redirectUri)
        {
            app.UseOpenIdConnectAuthentication(openIdConnectOptions: new OpenIdConnectAuthenticationOptions
            {
                Authority = authority,
                ClientId = "umbraco",
                RedirectUri = redirectUri,
                ResponseType = "id_token",
                Scope = "openid profile email",
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    SecurityTokenValidated = async n =>
                    {
                        //Applies "claims transformation", as seen: https://identityserver.github.io/Documentation/docsv2/overview/mvcGettingStarted.html
                        //So that only the necessary claims are kept for the user's ticket

                        var id = n.AuthenticationTicket.Identity;

                        // we want to keep first name, last name, subject and roles
                        var email = id.FindFirst(JwtClaimTypes.Email);
                        var givenName = id.FindFirst(JwtClaimTypes.GivenName);
                        var familyName = id.FindFirst(JwtClaimTypes.FamilyName);
                        var sub = id.FindFirst(JwtClaimTypes.Subject);

                        // create new identity and set name and role claim type
                        var nid = new ClaimsIdentity(
                            id.AuthenticationType,
                            JwtClaimTypes.GivenName,
                            JwtClaimTypes.Role);

                        nid.AddClaim(email);
                        nid.AddClaim(givenName);
                        nid.AddClaim(familyName);
                        nid.AddClaim(sub);

                        // keep the id_token for logout
                        nid.AddClaim(new Claim("id_token", n.ProtocolMessage.IdToken));

                        nid.AddClaim(new Claim(ClaimTypes.NameIdentifier
                            , sub.Value, "http://www.w3.org/2001/XMLSchema#string", DefaultAuthenticationTypes.ExternalCookie));

                        n.AuthenticationTicket = new AuthenticationTicket(
                            nid,
                            n.AuthenticationTicket.Properties);


                    }
                }
            });


        }
    }
}