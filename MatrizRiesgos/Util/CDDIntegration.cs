using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Web;

namespace MatrizRiesgos.Util
{
    public class CDDIntegration
    {
        public string AuthURL { set; get; }
        public string TenantID { set; get; }
        public string Token { set; get; }

        public Dictionary<string, string> CddAttributes
        {
            set { cddAttributes = value; }
            get { return cddAttributes; }
        } 

        private Dictionary<string, string> cddAttributes = new Dictionary<string, string>
        {
            { "authUrl", "https://login.microsoftonline.com" },
            { "tenantID", "d7bfe7d4-f40c-48a3-ae1d-df323b98d4ef" },
            { "client_id", "efd32114-6121-49e2-b9f1-7709433fc942" },
            { "username", "_GCPAPP@collahuasi.cl" },
            { "password", "Hac88.##$1" },
            { "scope", "user.read%20openid%20profile%20offline_access" },
            { "response_type", "token%20id_token" },
            { "grant_type", "password" },
            { "x-client-SKU", "msal.js.node" },
            { "client_secret", "UJd8Q~KyPhwBX9ely4_YTJyrGq~zjFobCc7Stb1h" }
        };

        public CDDIntegration(string definition)
        {
            foreach (string element in definition.Split(';'))
            {
                string key = "";
                string value = "";

                try
                {
                    key = element.Split('=')[0];
                    value = element.Split('=')[1];
                    if (cddAttributes.ContainsKey(key))
                    {
                        cddAttributes[key] = value;
                    }
                }
                catch (Exception )
                {

                }
            }

            if (cddAttributes.ContainsKey("authUrl"))
            {
                AuthURL = cddAttributes["authUrl"];
            }

            if (cddAttributes.ContainsKey("tenantId"))
            {
                TenantID = cddAttributes["tenantId"];
            }
        }

        public string GetBodyParams()
        {
            string bodyParams = "";
            foreach (string attributeKey in cddAttributes.Keys)
            {
                if (!attributeKey.Equals("tenantId") && !attributeKey.Equals("authUrl"))
                {
                    bodyParams = attributeKey + "=" + cddAttributes[attributeKey] + "&";
                }
            }

            return bodyParams;
        }

        public void Login()
        {
        }

        public void upload()
        {
            throw new NotImplementedException();
        }

    }
}