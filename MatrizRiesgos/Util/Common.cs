using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace MatrizRiesgos.Util
{
    public class Credentials
    {
        public string username { get; set; }
        public string password { get; set; }
        public string district { get; set; }
        public string position { get; set; }
    }

    public class BodyParams
    {
        public string username { get; set; }
        public string pwd { get; set; }
        public string district { get; set; }
        public string position { get; set; }
        public List<Attribute> atts { get; set; }
        public string script_name { get; set; }
    }

    public class Attribute
    {
        public string name { get; set; }
        public string value { get; set; }
    }

    public class EllRow
    {
        public List<Attribute> atts { get; set; }
    }

    public class HttpResponse<R>
    {
        public bool? redirect { get; set; }
        public bool success { get; set; }
        public string message { get; set; }
        public R data { get; set; }
    }
}