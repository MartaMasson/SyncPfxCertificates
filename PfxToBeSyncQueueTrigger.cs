using System;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Azure.Security.KeyVault.Certificates;
using Azure.Identity;
using System.Text.Json;
using System.Threading.Tasks;

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

            // Deserialize the JSON string into a custom object
            var messageObject = JsonSerializer.Deserialize<GridMessageObject>(jsonContent);

            // Extract values from the message
            string vaultName = messageObject.gridMessageDataObject.VaultName;
            string certificateName = messageObject.gridMessageDataObject.ObjectName;
            log.LogInformation($"C# Queue trigger function - VaultName {vaultName}  CertificateName {certificateName}...");

            //Connecting to the key vault where the change originated
            var keyVaultUriOrigin = new Uri("https://kv-pfx-eastus.vault.azure.net");
            var credentialOrigin  = new DefaultAzureCredential();
            var certificateClientOrigin = new CertificateClient(keyVaultUriOrigin, credentialOrigin);
            log.LogInformation($"C# Queue trigger function - Connected into key vault to retrieve pfx to be sync (Origin)...");

            KeyVaultCertificateWithPolicy certificateOrigin= await certificateClientOrigin.GetCertificateAsync(certificateName);
            log.LogInformation($"C# Queue trigger function - Connected into key vault where change originated...");

            // Extract the PFX file from the destination Key Vault. If does not exist or they are different, import the certificate from Origin Key Vault into the destination Key Vault
            var keyVaultUrlDestination = new Uri("https://kv-pfx-eastus2.vault.azure.net");
            var credentialDestination = new DefaultAzureCredential();
            var certificateClientDestination = new CertificateClient(keyVaultUrlDestination, credentialDestination);

            KeyVaultCertificateWithPolicy certificateDestination = await certificateClientDestination.GetCertificateAsync(certificateName);
            log.LogInformation($"C# Queue trigger function - Connected into key vault to retrieve pfx at destination...");
            
            if ((certificateDestination == null) || (certificateDestination.Properties.X509Thumbprint != certificateOrigin.Properties.X509Thumbprint))
            {
                byte[] pfxBytes = certificateOrigin.Cer;
                string keyid = certificateOrigin.KeyId.ToString();

                log.LogInformation($"C# Queue trigger function - File went to bytes...\n");
                log.LogInformation($"The file in bytes: {pfxBytes.ToString().Length}");
                log.LogInformation($"The key: {keyid.ToString().Length}");

                // Import the PFX file into the Key Vault as a certificate
                var importOptions = new ImportCertificateOptions(certificateName, pfxBytes)
                {
                    Password = keyid.ToString() // Check if the password is really needed
                };
                await certificateClientDestination.ImportCertificateAsync(importOptions);
                log.LogInformation($"Certificate {certificateName} does not exist in the destination Key Vault or the versions are different, so sync it importing a new version.");
            }
            else
            {
                // Certificate exists and they are already sync. Nothing to do.
            }
        }
    }

    // Custom object to deserialize the JSON message

    public class GridMessageDataObject
    {
        public string VaultName { get; set; }
        public string ObjectName { get; set; }
    } 

    public class GridMessageObject
    {
        public GridMessageDataObject gridMessageDataObject { get; set; }
    }

}


