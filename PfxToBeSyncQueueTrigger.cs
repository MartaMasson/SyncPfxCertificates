using System;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Azure.Security.KeyVault.Certificates;
using Azure.Identity;
using System.Text.Json;
using System.Threading.Tasks;
using Azure.Core;
using Microsoft.Extensions.Azure;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using Azure.Security.KeyVault.Secrets;
//Using System.Runtime.InteropServices.RuntimeInformation;

namespace Company.Function
{
    public class PfxToBeSyncQueueTrigger
    {
        [FunctionName("PfxToBeSyncQueueTrigger")]
        public async Task RunAsync([QueueTrigger("synceastus2", Connection = "sakvsyncpfxeastus_STORAGE")]string myQueueItem, ILogger log)
        {
            log.LogInformation($"C# Queue trigger function processed - Oi gente: {myQueueItem}");

            // The message content is a JSON string
            var jsonContent = myQueueItem.ToString();

            // Get the VaultName and CertificateName from the JSON message
            JsonDocument doc = JsonDocument.Parse(jsonContent);
            string vaultName = doc.RootElement.GetProperty("data").GetProperty("VaultName").GetString();
            string certificateName = doc.RootElement.GetProperty("data").GetProperty("ObjectName").GetString();
            log.LogInformation($"C# Queue trigger function - VaultName {vaultName}  CertificateName {certificateName}...");

            //Connecting to the key vault source of the change in the pfx
            log.LogInformation($"C# Queue trigger function - Connecting in the source VaultName {vaultName}...");
            var keyVaultUriOrigin = new Uri("https://kv-pfx-eastus.vault.azure.net");
            var credentialOrigin  = new DefaultAzureCredential();
            var certificateClientOrigin = new CertificateClient(keyVaultUriOrigin, credentialOrigin);
            log.LogInformation($"C# Queue trigger function - Connected into source key vault source to retrieve pfx to be sync ...");

            /*
            X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.MachineKeySet;
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    keyStorageFlags |= X509KeyStorageFlags.EphemeralKeySet;
                }

            DownloadCertificateOptions options = new DownloadCertificateOptions(certificateName)
            {
                KeyStorageFlags = keyStorageFlags
            };

            using X509Certificate2 certificate = client.DownloadCertificate(options);
            */
            log.LogInformation($"C# Queue trigger function - Donwloading the certificate ...");
            using X509Certificate2 certificate = certificateClientOrigin.DownloadCertificate(certificateName);
            log.LogInformation($"C# Queue trigger function - Getting the private key ...");
            using RSA key = certificate.GetRSAPrivateKey();
            log.LogInformation($"C# Queue trigger function - Getting the hash ...");
            byte[] hash = certificate.GetCertHash();
            log.LogInformation($"C# Queue trigger function - Getting the signature ...");
            byte[] signature = key.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            log.LogInformation($"C# Queue trigger function - Signature: {Convert.ToBase64String(signature)} ...");
        }
    }
}


