namespace EllipseWebServicesClient
{
    using System;
    using System.IO;
    using System.ServiceModel;
    using System.ServiceModel.Channels;
    using System.ServiceModel.Dispatcher;
    using System.Text;
    using System.Web.Services.Protocols;
    using System.Xml;

    public class AuthenticationExtensionWCF : IClientMessageInspector
    {
        public string LastRequestXML { get; private set; }
        public string LastResponseXML { get; private set; }

        object IClientMessageInspector.BeforeSendRequest(ref Message request, IClientChannel channel)
        {
            request = TransformOne(request);
            return null;
        }

        private Message TransformOne(Message reply)
        {
            Message newReply;
            using (var ms = new MemoryStream())
            {
                XmlDictionaryWriter writer = XmlDictionaryWriter.CreateTextWriter(ms);
                reply.WriteMessage(writer);
                writer.Flush();
                ms.Position = 0;
                var doc = new XmlDocument();
                doc.Load(ms);
                if (doc.InnerXml.Contains("Header"))
                {
                    XmlDocumentEx ex = new XmlDocumentEx(doc);
                    string namespaceURI = "http://schemas.xmlsoap.org/soap/envelope/";
                    string uri = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
                    XmlNodeList elementsByTagName = doc.GetElementsByTagName("Header", namespaceURI);
                    elementsByTagName[0].RemoveAll();
                    XmlNodeEx ex2 = ex.AppendChild(elementsByTagName[0], new EllipseWebServicesClient.QName("Security", uri)).AppendChild(new EllipseWebServicesClient.QName("UsernameToken", uri));
                    ex2.SetNode(new EllipseWebServicesClient.QName("Username", uri), ClientConversation.username);
                    ex2.SetNode(new EllipseWebServicesClient.QName("Password", uri), ClientConversation.password);

                    LastRequestXML = doc.InnerXml;

                    var nms = new MemoryStream();
                    XmlDictionaryWriter newWriter = XmlDictionaryWriter.CreateTextWriter(nms);
                    doc.WriteTo(newWriter);
                    newWriter.Flush();
                    nms.Position = 0;

                    var reader = XmlDictionaryReader.CreateTextReader(nms, XmlDictionaryReaderQuotas.Max);
                    newReply = Message.CreateMessage(reader, int.MaxValue, reply.Version);
                }
                else
                {
                    newReply = reply;
                }
            }
            return newReply;
        }


        void IClientMessageInspector.AfterReceiveReply(ref Message reply, object correlationState)
        {
            //No action Required
        }
    }
}

