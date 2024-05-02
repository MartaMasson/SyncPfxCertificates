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
            var keyVaultUrlOrigin = "https://kv-pfx-eastus.vault.azure.net";
            var credentialOrigin  = new DefaultAzureCredential();
            var certificateClientOrigin = new CertificateClient(keyVaultUrlOrigin, credentialOrigin);
            log.LogInformation($"C# Queue trigger function - Connected into key vault to retrieve pfx to be sync (Origin)...");

            CertificateWithPolicy certificateOrigin= await certificateClientOrigin.GetCertificateAsync(certificateName);
            log.LogInformation($"C# Queue trigger function - Connected into key vault where change originated...");

            // Extract the PFX file from the destination Key Vault. If does not exist or they are different, import the certificate from Origin Key Vault into the destination Key Vault
            var keyVaultUrlDestination = "https://kv-pfx-eastus.vault.azure.net";
            var credentialDestination = new DefaultAzureCredential();
            var certificateClientDestination = new CertificateClient(keyVaultUrlDestination, credentialDestination);

            CertificateWithPolicy certificateDestination = await certificateClientDestination.GetCertificateAsync(certificateName);
            log.LogInformation($"C# Queue trigger function - Connected into key vault to retrieve pfx at destination...");

            if (certificateDestination == null || certificateDestination.Value.X509Thumbprint != certificateOrigin.Value.X509Thumbprint)
            {
                await keyVaultClient.ImportCertificateAsync(keyVaultUrlDestination, certificateName, certificateOrigin);
                log.LogInformation($"Certificate {certificateName} does not exist in the destination Key Vault or the versions are different, so sync it importing a new version.");
            }
            else
            {
                // Certificate exists and they are already sync. Nothing to do.
            }


            // Create a CertificateClient to connect and access the Key Vault
            var keyVaultUri = new Uri($"https://kv-vm-test-mmg.vault.azure.net/");
            var credential = new DefaultAzureCredential();
            var certificateClient = new CertificateClient(keyVaultUri, credential);
            log.LogInformation($"C# Queue trigger function - Connected into key vault...");

            // Import the PFX file into the Key Vault as a certificate
            var importOptions = new ImportCertificateOptions(certificateName, pfxBytes)
            {
                Password = pfxPassword // Check if the password is really needed
            };
            await certificateClient.ImportCertificateAsync(importOptions);

            log.LogInformation($"C# Queue trigger function - Imported into key vault...");


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


