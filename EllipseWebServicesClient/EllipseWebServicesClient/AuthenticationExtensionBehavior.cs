using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceModel.Description;
using System.ServiceModel.Dispatcher;
using System.Text;
using System.Threading.Tasks;

namespace EllipseWebServicesClient
{
    
    public class AuthenticationExtensionBehavior : IEndpointBehavior
    {
        public string LastRequestXML
        {
            get
            {
                return inspector.LastRequestXML;
            }
        }

        public string LastResponseXML
        {
            get
            {
                return inspector.LastResponseXML;
            }
        }


        private AuthenticationExtensionWCF inspector = new AuthenticationExtensionWCF();
        public void AddBindingParameters(ServiceEndpoint endpoint, System.ServiceModel.Channels.BindingParameterCollection bindingParameters)
        {

        }

        public void ApplyDispatchBehavior(ServiceEndpoint endpoint, EndpointDispatcher endpointDispatcher)
        {

        }

        public void Validate(ServiceEndpoint endpoint)
        {

        }


        public void ApplyClientBehavior(ServiceEndpoint endpoint, ClientRuntime clientRuntime)
        {
            clientRuntime.MessageInspectors.Add(inspector);
        }
    }

}
