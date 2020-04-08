namespace MyCoreClient
{
    using System;
    using System.Net.Http;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading.Tasks;

    class Program
    {
        private const string CertificatePath = "MyClient.pfx";
        private const string CertificatePassword = "password";
        private const string Host = "https://localhost:54000";

        public static async Task Main(string[] args)
        {
            //reads certificate from file
            var certificate = new X509Certificate2(CertificatePath, CertificatePassword);
            var handler = new HttpClientHandler
            {
                //this callback validates server certificate
                //server certificate should be issued by trusted issuer
                ServerCertificateCustomValidationCallback = (sender, cert, chain, errors) => errors == System.Net.Security.SslPolicyErrors.None,
            };
            handler.ClientCertificates.Add(certificate);
            using var client = new HttpClient(handler);

            try
            {
                byte[] messsage = Encoding.UTF8.GetBytes("Hello from the client.<EOF>");
                // Send hello message to the server. 

                Console.WriteLine("sending");
                using var httpRequest = new HttpRequestMessage(HttpMethod.Post, Host)
                {
                    Content = new ByteArrayContent(messsage)
                };

                using var response = await client.SendAsync(httpRequest);
                var message = await response.Content.ReadAsStringAsync();
                Console.WriteLine(message);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

            Console.ReadKey();
        }
    }
}
