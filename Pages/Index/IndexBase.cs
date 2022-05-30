using Microsoft.AspNetCore.Components;
using System.Security.Cryptography;

namespace EncryptionHelper.Pages.Index
{
    public class IndexBase : ComponentBase
    {
        protected string PublicKey { get; set; } = "";
        protected string PrivateKey { get; set; } = "";

        protected void GenerateKeyPair()
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                PublicKey = rsa.ToXmlString(false);
                PrivateKey = rsa.ToXmlString(true);
            }
        }

        protected async void Copy(string value)
        {
            await Clipboard.SetTextAsync(value);
        }
    }
}
