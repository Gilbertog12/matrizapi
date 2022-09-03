namespace EllipseWebServicesClient
{
    using System;

    public class ClientConversation
    {
        public static string password;
        public static string username;

        public static void authenticate(string username, string password)
        {
            ClientConversation.username = username;
            ClientConversation.password = password;
        }
    }
}

