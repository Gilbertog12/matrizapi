using System;
using System.Collections.Generic;
using System.Web.Configuration;
using System.Text;
using System.Net;
using Newtonsoft.Json;
using System.IO;
using Newtonsoft.Json.Linq;

namespace MatrizRiesgos.Util
{
    public class ConnectionPowerBI
    {
        public string Url
        {
            set; get;
        }

        public string Method
        {
            set; get;
        }

        public ConnectionPowerBI()
        {
        }

        public bool sendNotification(string json)
        {
            WebRequest request = WebRequest.Create(Url);
            request.Method = this.Method;
            byte[] byteArray = Encoding.UTF8.GetBytes(json);

            request.ContentType = "application/json";
            request.ContentLength = byteArray.Length;

            Stream reqStream = request.GetRequestStream();
            reqStream.Write(byteArray, 0, byteArray.Length);

            WebResponse response = request.GetResponse();
            Stream respStream = response.GetResponseStream();
            StreamReader reader = new StreamReader(respStream);
            
            string data = reader.ReadToEnd();
            return true;

        }
    }
}