namespace EllipseWebServicesClient
{
    using System;

    internal class QName
    {
        public string name;
        public string uri;

        public QName(string name, string uri)
        {
            this.name = name;
            this.uri = uri;
        }
    }
}

