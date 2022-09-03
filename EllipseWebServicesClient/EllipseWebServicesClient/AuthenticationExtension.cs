namespace EllipseWebServicesClient
{
    using System;
    using System.IO;
    using System.Web.Services.Protocols;
    using System.Xml;

    internal class AuthenticationExtension : SoapExtension
    {
        private Stream inwardStream;
        private Stream outwardStream;

        private void afterSerialize()
        {
            XmlDocument xDoc = new XmlDocument();
            this.inwardStream.Position = 0L;
            StreamReader txtReader = new StreamReader(this.inwardStream);
            StreamWriter writer = new StreamWriter(this.outwardStream);
            xDoc.Load(txtReader);
            XmlDocumentEx ex = new XmlDocumentEx(xDoc);
            string namespaceURI = "http://schemas.xmlsoap.org/soap/envelope/";
            string uri = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
            XmlNodeList elementsByTagName = xDoc.GetElementsByTagName("Envelope", namespaceURI);
            XmlNodeEx ex2 = ex.AppendChild(elementsByTagName[0], new EllipseWebServicesClient.QName("Header", namespaceURI)).AppendChild(new EllipseWebServicesClient.QName("Security", uri)).AppendChild(new EllipseWebServicesClient.QName("UsernameToken", uri));
            ex2.SetNode(new EllipseWebServicesClient.QName("Username", uri), ClientConversation.username);
            ex2.SetNode(new EllipseWebServicesClient.QName("Password", uri), ClientConversation.password);
            string innerXml = xDoc.InnerXml;
            writer.Write(innerXml);
            writer.Flush();
        }

        private void beforeDeserialize()
        {
            StreamReader reader = new StreamReader(this.outwardStream);
            StreamWriter writer = new StreamWriter(this.inwardStream);
            string str = reader.ReadToEnd();
            writer.Write(str);
            writer.Flush();
            this.inwardStream.Position = 0L;
        }

        public override Stream ChainStream(Stream stream)
        {
            this.outwardStream = stream;
            this.inwardStream = new MemoryStream();
            return this.inwardStream;
        }

        public override object GetInitializer(Type serviceType)
        {
            return null;
        }

        public override object GetInitializer(LogicalMethodInfo methodInfo, SoapExtensionAttribute attribute)
        {
            return null;
        }

        public override void Initialize(object initializer)
        {
        }

        public override void ProcessMessage(SoapMessage message)
        {
            if (message is SoapClientMessage)
            {
                switch (message.Stage)
                {
                    case SoapMessageStage.AfterSerialize:
                        this.afterSerialize();
                        break;

                    case SoapMessageStage.BeforeDeserialize:
                        this.beforeDeserialize();
                        break;
                }
            }
        }
    }
}

