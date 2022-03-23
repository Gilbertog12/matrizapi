using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Threading.Tasks;
using System.Security.Claims;
using Microsoft.Owin;
using System.Configuration;
using System.Web.Configuration;
using MatrizRiesgos.Controllers;
using System.Net;
using System.Net.Http;
using System.IO;

namespace MatrizRiesgos
{
    /* Historia
    * 2022-03-22 v2.09 Se agrega metodo para obtener el password sin econding.
    */
    public class MyAythorizationServerProvider : OAuthAuthorizationServerProvider
    {

        public static string PASSWORD = "password=";
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            context.Validated();
            //return base.ValidateClientAuthentication(context);
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
            string requestBody = GetRequestBody();
            string rawPassword = GetBodyPassword(requestBody);
            try
            {
                //context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });
                var identity = new ClaimsIdentity(context.Options.AuthenticationType);

                AuthenticatorService.AuthenticatorService auth = new AuthenticatorService.AuthenticatorService();
                auth.Url = WebConfigurationManager.AppSettings["EllService"] + "AuthenticatorService";
                AuthenticatorService.OperationContext op = new AuthenticatorService.OperationContext();

                IFormCollection parameters = await context.Request.ReadFormAsync();
                var district = parameters.Get("district");
                var position = parameters.Get("position");

                /*if (string.IsNullOrEmpty(district))
                {
                    DataController data = new DataController();
                    Util.HttpResponse<List<Util.EllRow>> resp = data.GetDefaultDistrictByGroovy(context.UserName);
                    district = resp.data[0].atts[0].name;
                    //district = GetForPositions(context.UserName, context.Password);
                }

                if (string.IsNullOrEmpty(position))
                {
                    DataController data = new DataController();
                    Util.HttpResponse<List<Util.EllRow>> resp = data.GetDefaultPositionByGroovy(context.UserName);
                    position = resp.data[0].atts[0].name;
                    //position = GetDefaultPosition(context.UserName, context.Password);
                }*/

                EllipseWebServicesClient.ClientConversation.username = context.UserName; 
                if (!string.IsNullOrEmpty(rawPassword))
                    EllipseWebServicesClient.ClientConversation.password = rawPassword;
                else
                    EllipseWebServicesClient.ClientConversation.password = context.Password;

                op.district = district;
                op.position = position;

                auth.authenticate(op);
                identity.AddClaim(new Claim(ClaimTypes.Role, "admin"));
                identity.AddClaim(new Claim("username", context.UserName));
                identity.AddClaim(new Claim("pwd", context.Password));
                identity.AddClaim(new Claim("district", district));
                identity.AddClaim(new Claim("position", position));
                context.Validated(identity);
            }
            catch (Exception ex)
            {
                context.SetError("invalid_grant", ex.Message);
            }

        }

        private string GetBodyPassword(string requestBody)
        {
            if (requestBody != null)
            {
                foreach (string param in requestBody.Split('&'))
                {
                    if (param.Contains(PASSWORD))
                    {
                        try
                        {
                            return param.Split('=')[1];
                        } catch (Exception)
                        {
                            return "";
                        }
                    }
                }
            }

            return "";
        }

        public static string GetRequestBody()
        {
            var bodyStream = new StreamReader(HttpContext.Current.Request.InputStream);
            bodyStream.BaseStream.Seek(0, SeekOrigin.Begin);
            var bodyText = bodyStream.ReadToEnd();
            return bodyText;
        }

        public String GetDefaultPosition(String username, String password)
        {
            AuthenticatorService.AuthenticatorService authService = new AuthenticatorService.AuthenticatorService();
            AuthenticatorService.OperationContext oc = new AuthenticatorService.OperationContext();

            EllipseWebServicesClient.ClientConversation.username = username;
            EllipseWebServicesClient.ClientConversation.password = password;

            try
            {
                AuthenticatorService.NameValuePair[] pairs = authService.getPositions(oc);
                foreach (AuthenticatorService.NameValuePair pair in pairs)
                {
                    return pair.name;

                }
                return null;
            }
            catch (Exception)
            {
                return null;
            }

        }

        public String GetDefaultDistrict(String username, String password)
        {
            AuthenticatorService.AuthenticatorService authService = new AuthenticatorService.AuthenticatorService();
            AuthenticatorService.OperationContext oc = new AuthenticatorService.OperationContext();

            EllipseWebServicesClient.ClientConversation.username = username;
            EllipseWebServicesClient.ClientConversation.password = password;

            try
            {
                AuthenticatorService.NameValuePair[] pairs = authService.getDistricts(oc);
                foreach (AuthenticatorService.NameValuePair pair in pairs)
                {
                    return pair.name;

                }

                return "";
            }
            catch (Exception)
            {
                return null;
            }

        }
    }
}