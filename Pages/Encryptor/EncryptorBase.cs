using EncryptionHelper.Utilities;
using Microsoft.AspNetCore.Components;
using MudBlazor;
using System.Security.Cryptography;
using System.Text;

namespace EncryptionHelper.Pages.Encryptor
{
    public class EncryptorBase : ComponentBase
    {
        [Inject]
        private ISnackbar _snackbar { get; set; }

        protected string Text { get; set; } = "";
        protected string Key { get; set; } = "";
        protected string Result { get; set; } = "";

        protected async void Copy()
        {
            await Clipboard.SetTextAsync(Result);
        }

        protected void Decrypt()
        {
            try
            {
                if (string.IsNullOrEmpty(Text) || string.IsNullOrEmpty(Key))
                    throw new Exception("Text and Key are required!");

                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    RSAUtility.FromXmlString(rsa, Key);
                    byte[] encryptedKeyBytes = Convert.FromBase64String(Text);
                    byte[] decryptedKeyBytes = rsa.Decrypt(encryptedKeyBytes, false);
                    Result = Encoding.ASCII.GetString(decryptedKeyBytes);
                }
            }
            catch (Exception ex)
            {
                Result = "";
                _snackbar.Add(ex.Message, Severity.Error);
            }
        }

        protected void Encrypt()
        {
            try
            {
                if (string.IsNullOrEmpty(Text) || string.IsNullOrEmpty(Key))
                    throw new Exception("Text and Key are required!");

                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    RSAUtility.FromXmlString(rsa, Key);
                    byte[] plainKeyBytes = Encoding.ASCII.GetBytes(Text);
                    byte[] encryptedKeyBytes = rsa.Encrypt(plainKeyBytes, false);
                    Result = Convert.ToBase64String(encryptedKeyBytes);
                }
            }
            catch (Exception ex)
            {
                Result = "";
                _snackbar.Add(ex.Message, Severity.Error);
            }
        }
    }
}
