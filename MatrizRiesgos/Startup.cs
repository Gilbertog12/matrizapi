using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;
using Microsoft.Owin.Security.OAuth;
using System.Web.Http;
using System.Web.Configuration;

[assembly: OwinStartup(typeof(MatrizRiesgos.Startup))]

namespace MatrizRiesgos
{
    public partial class Startup
    {
        public string GetTimeOut()
        {
            string timeOut = "12";
            try
            {
                timeOut = WebConfigurationManager.AppSettings["TimeOut"];
            } catch (Exception)
            {

            }

            return timeOut;
        }

        public void Configuration(IAppBuilder app)
        {
            // Para obtener más información acerca de cómo configurar su aplicación, visite http://go.microsoft.com/fwlink/?LinkID=316888

            app.UseCors(Microsoft.Owin.Cors.CorsOptions.AllowAll);
            var myProvider = new MyAythorizationServerProvider();
            OAuthAuthorizationServerOptions options = new OAuthAuthorizationServerOptions
            {
                AllowInsecureHttp = true,
                TokenEndpointPath = new PathString("/token"),
                AccessTokenExpireTimeSpan = TimeSpan.FromHours(Int32.Parse(GetTimeOut())),
                Provider = myProvider
            };

            app.Use(async (context, next) =>
            {
                IOwinRequest req = context.Request;
                IOwinResponse res = context.Response;
                if (req.Path.StartsWithSegments(new PathString("/Token")))
                {
                    var origin = req.Headers.Get("Origin");
                    if (!string.IsNullOrEmpty(origin))
                    {
                        res.Headers.Set("Access-Control-Allow-Origin", origin);
                    }
                    if (req.Method == "OPTIONS")
                    {
                        res.StatusCode = 200;
                        res.Headers.AppendCommaSeparatedValues("Access-Control-Allow-Origin", "GET", "POST");
                        res.Headers.AppendCommaSeparatedValues("Access-Control-Allow-Origin", "authorization", "content-type");
                        return;
                    }

                }

                await next();

            });

            app.UseOAuthAuthorizationServer(options);
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());
            //app.UseCors(Microsoft.Owin.Cors.CorsOptions.AllowAll);
            //ConfigureAuth(app);
            HttpConfiguration config = new HttpConfiguration();
        }
    }
}
