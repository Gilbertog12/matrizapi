namespace EllipseWebServicesClient
{
    using System;
    using System.Xml;

    internal class XmlNodeEx
    {
        private XmlDocumentEx doc;
        private XmlElement node;

        public XmlNodeEx(XmlDocumentEx doc, XmlElement node)
        {
            this.doc = doc;
            this.node = node;
        }

        public XmlNodeEx AppendChild(EllipseWebServicesClient.QName qname)
        {
            return this.doc.AppendChild(this.node, qname);
        }

        public void SetAttribute(string name, string value)
        {
            this.node.SetAttribute(name, value);
        }

        public void SetNode(EllipseWebServicesClient.QName qname, string value)
        {
            this.AppendChild(qname).node.InnerText = value;
        }
    }
}

