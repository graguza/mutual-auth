namespace MutualSslDemo.Server
{
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Net.Sockets;
    using System.Security.Authentication;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;

    class Program
    {
        private const int Port = 54000;
        private const string CertificatePath = "MyServer.pfx";
        private const string CertificatePassword = "password";

        static void Main(string[] args)
        {
            var certificate = new X509Certificate2(CertificatePath, CertificatePassword);
            ServicePointManager.ServerCertificateValidationCallback += new RemoteCertificateValidationCallback(OnRemoteCertificateValidationCallback);
            SslTcpServer.RunServer(Port, certificate);
        }

        static bool OnRemoteCertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return (sslPolicyErrors == SslPolicyErrors.None);
        }

        public sealed class SslTcpServer
        {
            // The certificate parameter specifies the name of the file 
            // containing the machine certificate.
            public static void RunServer(int serverPort, X509Certificate2 certificate)
            {
                // Create a TCP/IP (IPv4) socket and listen for incoming connections.
                var listener = new TcpListener(IPAddress.Any, serverPort);
                listener.Start();

                while (true)
                {
                    Console.WriteLine("Waiting for a client...");
                    var client = listener.AcceptTcpClient();
                    ProcessClient(client, certificate);
                }
            }

            static void ProcessClient(TcpClient client, X509Certificate certificate)
            {
                // SslStream using the client's stream.
                var sslStream = new SslStream(client.GetStream(), false);

                try
                {
                    // Authenticate the server and requires the client to authenticate.
                    sslStream.AuthenticateAsServer(certificate, true, SslProtocols.Default, true);
                    LogCertificateDetails(sslStream);
                    sslStream.ReadTimeout = 5000;
                    sslStream.WriteTimeout = 5000;
                    Console.WriteLine("Waiting for client message...");
                    string messageData = ReadMessage(sslStream);
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("Received: {0}", messageData);
                    Console.ResetColor();

                    var message = GetMessage();
                    Console.WriteLine("Sending hello message.");

                    sslStream.Write(message);
                    sslStream.Flush();
                }
                catch (AuthenticationException e)
                {
                    Console.WriteLine("Exception: {0}", e.Message);
                    if (e.InnerException != null)
                    {
                        Console.WriteLine("Inner exception: {0}", e.InnerException.Message);
                    }
                    Console.WriteLine("Authentication failed - closing the connection.");
                    sslStream.Close();
                    client.Close();
                    return;
                }
                finally
                {
                    // The client stream will be closed with the sslStream
                    // because we specified this behavior when creating
                    // the sslStream.
                    sslStream.Close();
                    client.Close();
                }
            }

            private static byte[] GetMessage()
            {
                //we create message that looks like http response
                var sb = new StringBuilder();
                sb.AppendLine("HTTP/1.1 200 OK");
                sb.AppendLine("Host: localhost: 54000");
                sb.AppendLine("Content-Length: 27");
                sb.AppendLine();
                sb.AppendLine("Hello from the server.<EOF>");

                byte[] message = Encoding.UTF8.GetBytes(sb.ToString());
                return message;
            }

            static string ReadMessage(SslStream sslStream)
            {
                // Read the  message sent by the client.
                // The client signals the end of the message using the
                // "<EOF>" marker.
                byte[] buffer = new byte[2048];
                StringBuilder messageData = new StringBuilder();
                int bytes = -1;
                do
                {
                    // Read the client's message.
                    bytes = sslStream.Read(buffer, 0, buffer.Length);
                    var decoder = Encoding.UTF8.GetDecoder();
                    char[] chars = new char[decoder.GetCharCount(buffer, 0, bytes)];
                    decoder.GetChars(buffer, 0, bytes, chars, 0);
                    messageData.Append(chars);
                    // Check for EOF or an empty message.
                    if (messageData.ToString().IndexOf("<EOF>") != -1)
                    {
                        break;
                    }
                } while (bytes != 0);

                return messageData.ToString();
            }

            static void LogCertificateDetails(SslStream stream)
            {
                if (stream.LocalCertificate != null)
                {
                    Console.WriteLine("LocalCertificate subject {0} valid from {1} to {2}.",
                        stream.LocalCertificate.Subject,
                        stream.LocalCertificate.GetEffectiveDateString(),
                        stream.LocalCertificate.GetExpirationDateString());
                }

                if (stream.RemoteCertificate == null)
                {
                    return;
                }

                Console.WriteLine("RemoteCertificate subject {0} valid from {1} to {2}.",
                      stream.RemoteCertificate.Subject,
                      stream.RemoteCertificate.GetEffectiveDateString(),
                      stream.RemoteCertificate.GetExpirationDateString());

            }
        }
    }
}
