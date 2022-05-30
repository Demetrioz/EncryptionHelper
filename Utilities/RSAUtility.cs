using System.Security.Cryptography;
using System.Xml;

namespace EncryptionHelper.Utilities
{
    public static class RSAUtility
    {
        public static void FromXmlString(this RSACryptoServiceProvider rsa, string xmlString)
        {
            try
            {
                RSAParameters parameters = new();

                XmlDocument xmlDoc = new();
                xmlDoc.LoadXml(xmlString);

                if (xmlDoc.DocumentElement == null)
                    throw new NullReferenceException("No XML Document Element");

                if (xmlDoc.DocumentElement.Name.Equals("RSAKeyValue"))
                {
                    foreach (XmlNode node in xmlDoc.DocumentElement.ChildNodes)
                    {
                        switch (node.Name)
                        {
                            case "Modulus": parameters.Modulus = Convert.FromBase64String(node.InnerText); break;
                            case "Exponent": parameters.Exponent = Convert.FromBase64String(node.InnerText); break;
                            case "P": parameters.P = Convert.FromBase64String(node.InnerText); break;
                            case "Q": parameters.Q = Convert.FromBase64String(node.InnerText); break;
                            case "DP": parameters.DP = Convert.FromBase64String(node.InnerText); break;
                            case "DQ": parameters.DQ = Convert.FromBase64String(node.InnerText); break;
                            case "InverseQ": parameters.InverseQ = Convert.FromBase64String(node.InnerText); break;
                            case "D": parameters.D = Convert.FromBase64String(node.InnerText); break;
                        }
                    }

                    rsa.ImportParameters(parameters);
                }
                else
                {
                    throw new Exception("Invalid XML RSA key.");
                }
            }
            catch (Exception)
            {
            }
        }

        public static string ToXmlString(this RSACryptoServiceProvider rsa, bool includePrivateParameters = false)
        {
            RSAParameters parameters = rsa.ExportParameters(includePrivateParameters);

            if (includePrivateParameters)
            {
                return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
                    Convert.ToBase64String(parameters.Modulus ?? Array.Empty<byte>()),
                    Convert.ToBase64String(parameters.Exponent ?? Array.Empty<byte>()),
                    Convert.ToBase64String(parameters.P ?? Array.Empty<byte>()),
                    Convert.ToBase64String(parameters.Q ?? Array.Empty<byte>()),
                    Convert.ToBase64String(parameters.DP ?? Array.Empty<byte>()),
                    Convert.ToBase64String(parameters.DQ ?? Array.Empty<byte>()),
                    Convert.ToBase64String(parameters.InverseQ ?? Array.Empty<byte>()),
                    Convert.ToBase64String(parameters.D ?? Array.Empty<byte>()));
            }

            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent></RSAKeyValue>",
                Convert.ToBase64String(parameters.Modulus ?? Array.Empty<byte>()),
                Convert.ToBase64String(parameters.Exponent ?? Array.Empty<byte>()));

        }

        public static void ExportPublicKey(RSACryptoServiceProvider csp, TextWriter outputStream)
        {
            var parameters = csp.ExportParameters(false);
            using (var stream = new MemoryStream())
            {
                var writer = new BinaryWriter(stream);
                writer.Write((byte)0x30); // SEQUENCE
                using (var innerStream = new MemoryStream())
                {
                    var innerWriter = new BinaryWriter(innerStream);
                    innerWriter.Write((byte)0x30); // SEQUENCE
                    EncodeLength(innerWriter, 13);
                    innerWriter.Write((byte)0x06); // OBJECT IDENTIFIER
                    var rsaEncryptionOid = new byte[] { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
                    EncodeLength(innerWriter, rsaEncryptionOid.Length);
                    innerWriter.Write(rsaEncryptionOid);
                    innerWriter.Write((byte)0x05); // NULL
                    EncodeLength(innerWriter, 0);
                    innerWriter.Write((byte)0x03); //BIT STRING
                    using (var bitStringStream = new MemoryStream())
                    {
                        var bitStringWriter = new BinaryWriter(bitStringStream);
                        bitStringWriter.Write((byte)0x00); // # of unused bits
                        bitStringWriter.Write((byte)0x30); // SEQUENCE
                        using (var paramsStream = new MemoryStream())
                        {
                            var paramsWriter = new BinaryWriter(paramsStream);
                            EncodeIntegerBigEndian(paramsWriter, parameters.Modulus ?? Array.Empty<byte>());
                            EncodeIntegerBigEndian(paramsWriter, parameters.Exponent ?? Array.Empty<byte>());
                            var paramsLength = (int)paramsStream.Length;
                            EncodeLength(bitStringWriter, paramsLength);
                            bitStringWriter.Write(paramsStream.GetBuffer(), 0, paramsLength);
                        }
                        var bitStringLength = (int)bitStringStream.Length;
                        EncodeLength(innerWriter, bitStringLength);
                        innerWriter.Write(bitStringStream.GetBuffer(), 0, bitStringLength);
                    }
                    var length = (int)innerStream.Length;
                    EncodeLength(writer, length);
                    writer.Write(innerStream.GetBuffer(), 0, length);
                }

                var base64 = Convert.ToBase64String(stream.GetBuffer(), 0, (int)stream.Length).ToCharArray();

                for (var i = 0; i < base64.Length; i += 64)
                    outputStream.Write(base64, i, Math.Min(64, base64.Length - i));
            }
        }

        private static void EncodeIntegerBigEndian(BinaryWriter stream, byte[] value, bool forceUnsigned = true)
        {
            stream.Write((byte)0x02); // INTEGER
            var prefixZeros = 0;
            for (var i = 0; i < value.Length; i++)
            {
                if (value[i] != 0) break;
                prefixZeros++;
            }
            if (value.Length - prefixZeros == 0)
            {
                EncodeLength(stream, 1);
                stream.Write((byte)0);
            }
            else
            {
                if (forceUnsigned && value[prefixZeros] > 0x7f)
                {
                    // Add a prefix zero to force unsigned if the MSB is 1
                    EncodeLength(stream, value.Length - prefixZeros + 1);
                    stream.Write((byte)0);
                }
                else
                {
                    EncodeLength(stream, value.Length - prefixZeros);
                }
                for (var i = prefixZeros; i < value.Length; i++)
                {
                    stream.Write(value[i]);
                }
            }
        }

        private static void EncodeLength(BinaryWriter stream, int length)
        {
            if (length < 0) throw new ArgumentOutOfRangeException(nameof(length), "Length must be non-negative");
            if (length < 0x80)
            {
                // Short form
                stream.Write((byte)length);
            }
            else
            {
                // Long form
                var temp = length;
                var bytesRequired = 0;
                while (temp > 0)
                {
                    temp >>= 8;
                    bytesRequired++;
                }
                stream.Write((byte)(bytesRequired | 0x80));
                for (var i = bytesRequired - 1; i >= 0; i--)
                {
                    stream.Write((byte)(length >> (8 * i) & 0xff));
                }
            }
        }
    }
}
