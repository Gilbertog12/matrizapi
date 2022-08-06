using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Web;

namespace MatrizRiesgos.Util
{
    public class APIRequest
    {
        public string Method { set; get; }
        public string UrlAPI { set; get; }
        public string BodyParams { set; get; }
        public string ContentType { set; get; }
        public string Accept { set; get; }
        public Boolean ErrorFound { set; get; }
        public string ErrorMessage { set; get; }

        private Dictionary<string, string> HeaderParams = new Dictionary<string, string>();
        public void AddHeaderParam(string key, string value)
        {
            HeaderParams.Add(key, value);
        }

        public JObject SendRequest()
        {
            WebRequest request = WebRequest.Create(UrlAPI);
            request.ContentType = ContentType;
            request.Method = Method;
            foreach (string key in HeaderParams.Keys) {
                request.Headers.Add(key, HeaderParams[key]);
            }

            using (StreamWriter stOut = new StreamWriter(request.GetRequestStream(), System.Text.Encoding.ASCII))
            {
                stOut.Write(BodyParams);
                stOut.Close();
            }

            try
            {
                WebResponse webResponse = request.GetResponse();
                Stream webStream = webResponse.GetResponseStream();
                StreamReader reader = new StreamReader(webStream);
                string data = reader.ReadToEnd();
                ErrorFound = false;
                ErrorMessage = "";
                return JObject.Parse(data);
            }
            catch (Exception ex)
            {
                ErrorFound = true;
                ErrorMessage = ex.Message;
                return null;
            }

        }
    }
}