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

            // Extract the PFX file from the destination Key Vault. If does not exist or they are different, import the certificate from Origin Key Vault into the destination Key Vault
            log.LogInformation($"C# Queue trigger function - Connecting in the destination VaultName pfx-eastus2...");
            var keyVaultUrlDestination = new Uri("https://kv-pfx-eastus2.vault.azure.net");
            var credentialDestination = new DefaultAzureCredential();
            var certificateClientDestination = new CertificateClient(keyVaultUrlDestination, credentialDestination);
            log.LogInformation($"C# Queue trigger function - Connected into the destination key vault destination where pfx will be sync...");

            // Get the certificate from the origin Key Vault
            log.LogInformation($"C# Queue trigger function - Retrieving the Certificate {certificateName}...");
            KeyVaultCertificateWithPolicy certificateOrigin= await certificateClientOrigin.GetCertificateAsync(certificateName);
            var certificationPolicyOrigin = certificateClientOrigin.GetCertificatePolicy(certificateName);

            byte[] keyVaultX509ThumbprintDestination = null;
            try
                {
                    //Checking if certificate altready exists in the destination Key Vault
                    KeyVaultCertificateWithPolicy certificateDestination = await certificateClientDestination.GetCertificateAsync(certificateName);
                    log.LogInformation($"C# Queue trigger function - Connected into key vault to retrieve pfx at destination...");
                    keyVaultX509ThumbprintDestination =  certificateDestination.Properties.X509Thumbprint;
                }
            catch (Azure.RequestFailedException ex) when (ex.Status == 404)
                {
                    log.LogInformation($"C# Queue trigger function - Certificate {certificateName} does not exist in the destination Key Vault, so sync it importing a new version.");
            }
            // If the certificate does not exist in the destination Key Vault or the versions are different, import a new version
            if ( (keyVaultX509ThumbprintDestination == null) ||  (keyVaultX509ThumbprintDestination != certificateOrigin.Properties.X509Thumbprint))
            {
                // Download the certificate with private key from the origin Key Vault
                //log.LogInformation($"C# Queue trigger function - Downloading the certification at the source...");
                //X509Certificate2 certificateWithPrivateKey = await certificateClientOrigin.DownloadCertificateAsync(certificateName);

                // Extract the PFX file from the certificate
                //log.LogInformation($"C# Queue trigger function - Transforming pfx into bytes ...");
                //byte[] pfxBytes = certificateWithPrivateKey.Export(X509ContentType.Pfx);
                //log.LogInformation($"C# Queue trigger function - pfx: {pfxBytes.ToString}");

                //Testando alternativa 2
                log.LogInformation($"C# Queue trigger function - Segredo do Certificado...");
                var client = new SecretClient(new Uri("https://kv-pfx-eastus.vault.azure.net"), credentialOrigin);

                log.LogInformation($"C# Queue trigger function - Pegando o segredo...");
                KeyVaultSecret secret = client.GetSecret(certificateName);

                log.LogInformation($"C# Queue trigger function - Pegando o certificado...");
                byte[] certificate = Convert.FromBase64String(secret.Value);

                log.LogInformation($"C# Queue trigger function - Gerando X509..");
                X509Certificate2 x509 = new X509Certificate2(certificate);
                byte[] pfxBytes2 = x509.Export(X509ContentType.Pfx);

                // Import the certificate into the destination Key Vault
                log.LogInformation($"C# Queue trigger function - Importing certification options...");
                var importCertificateOptions = new ImportCertificateOptions(certificateName, pfxBytes2)
                {
                    //Policy = certificationPolicyOrigin.Value,
                };
                log.LogInformation($"C# Queue trigger function - Importing the certification to the destination...");
                await certificateClientDestination.ImportCertificateAsync(importCertificateOptions);
                log.LogInformation($"C# Queue trigger function - Certification synched from Primary Region with Secondary region successfully!");
            }
            else
            {
                // Certificate exists and they are already sync. Nothing to do.
                log.LogInformation($"Certificate {certificateName} PFX already synched in primary and secondary regions.");
            }
        }
    }
}


