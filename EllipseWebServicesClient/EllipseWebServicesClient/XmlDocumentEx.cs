namespace EllipseWebServicesClient
{
    using System;
    using System.Xml;

    internal class XmlDocumentEx
    {
        private XmlDocument xDoc;

        public XmlDocumentEx(XmlDocument xDoc)
        {
            this.xDoc = xDoc;
        }

        public XmlNodeEx AppendChild(XmlNode parent, EllipseWebServicesClient.QName qname)
        {
            XmlElement newChild = this.xDoc.CreateElement(qname.name, qname.uri);
            parent.InsertBefore(newChild, parent.FirstChild);
            return new XmlNodeEx(this, newChild);
        }
    }
}

