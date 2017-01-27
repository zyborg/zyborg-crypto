using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace Zyborg.Security.Cryptography
{
    /// <summary>
    /// This a form of <see cref="SecretSharingAlgorithm">Secret Sharing</see>
    /// that is based on a layering multiple applications of an asymmetric
    /// algorithm with distinct keys.  It has a threshold equal to the number
    /// of keys/layers.
    /// </summary>
    /// <remarks>
    /// This implementation is derived from the example described as
    /// <i>secure secret sharing</i> in <see
    /// cref="https://en.wikipedia.org/wiki/Secret_sharing#.22Secure.22_versus_.22insecure.22_secret_sharing"
    /// >this narrative</see>.  The major distinction is that this implementation
    /// couples the application of the asymmetric algorithm with a symmetric
    /// algorithm in order to support arbitrary length secrets.  Specifically,
    /// at each layer, a random AES key and IV is generated and a random RSA
    /// key-pair is generated.  AES is used to encrypt the secret data within
    /// that layer, and RSA is used to encrypt the AES key.
    /// <para>
    /// In reality, this may not be a practical or useful implementation
    /// as compared to <see cref="ShamirsSecretSharing">other</a> secret
    /// sharing algorithms, partly due to the fact that it suffers from
    /// the requirement that it needs all of the shares to reconstruct the
    /// secret, however it is useful to demonstrate alternative implementations
    /// of the <see cref="SecretSharingAlgorithm">general interface</see> to
    /// secret sharing algorithms.
    /// </para>
    /// </remarks>
    public class LayeredAsymmetricSecretSharing : SecretSharingAlgorithm
    {
        public LayeredAsymmetricSecretSharing()
        { }

        public override byte[] Split(byte[] secretClear, int shareCount)
        {
            var rsaPrivateList = new List<byte[]>();
            var secretCrypt = secretClear;
            using (var aes = Aes.Create())
            {
                for (int index = 0; index < shareCount; ++index)
                {
                    aes.GenerateKey();
                    aes.GenerateIV();
                    using (var rsa = RSA.Create())
                    {
                        using (var encryptor = aes.CreateEncryptor())
                        {
                            secretCrypt = encryptor.TransformFinalBlock(secretCrypt, 0, secretCrypt.Length);
                        }
                        var aesKey = rsa.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA256);
                        rsaPrivateList.Add(Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(
                                new LayeredAsymmetricShare
                                {
                                    Index = index,
                                    AesKeyEncrypted = aesKey,
                                    AesIv = aes.IV,
                                    PrivateParams = rsa.ExportParameters(true),
                                })));
                    }
                }
            }

            Shares = rsaPrivateList;

            return secretCrypt;
        }

        public override byte[] Combine(byte[] secretCrypt)
        {
            var layeredSharesList = new List<LayeredAsymmetricShare>();
            foreach (var sh in Shares)
            {
                layeredSharesList.Add(JsonConvert.DeserializeObject<LayeredAsymmetricShare>(
                        Encoding.UTF8.GetString(sh)));
            }

            var secretClear = secretCrypt;
            using (var aes = Aes.Create())
            {
                foreach (var layeredShare in  layeredSharesList.OrderByDescending(x => x.Index))
                {
                    using (var rsa = RSA.Create())
                    {
                        rsa.ImportParameters(layeredShare.PrivateParams);
                        var aesKey = rsa.Decrypt(layeredShare.AesKeyEncrypted,
                                RSAEncryptionPadding.OaepSHA256);
                        using (var decryptor = aes.CreateDecryptor(aesKey, layeredShare.AesIv))
                        {
                            secretClear = decryptor.TransformFinalBlock(secretClear, 0, secretClear.Length);
                        }
                    }
                }
            }

            return secretClear;
        }

        public class LayeredAsymmetricShare
        {
            public int Index
            { get; set; }

            public byte[] AesKeyEncrypted
            { get; set; }

            public byte[] AesIv
            { get; set; }

            public RSAParameters PrivateParams
            { get; set; }
        }
    }
}
