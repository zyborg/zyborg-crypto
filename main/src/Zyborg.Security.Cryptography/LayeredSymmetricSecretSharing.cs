using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace Zyborg.Security.Cryptography
{
    /// <summary>
    /// This a form of <see cref="SecretSharingAlgorithm">Secret Sharing</see>
    /// that is based on a layering multiple applications of a ymmetric
    /// algorithm with distinct keys.  It has a threshold equal to the number
    /// of keys/layers.
    /// </summary>
    /// <remarks>
    /// This implementation is based on the example described as
    /// <i>secure secret sharing</i> in <see
    /// cref="https://en.wikipedia.org/wiki/Secret_sharing#.22Secure.22_versus_.22insecure.22_secret_sharing"
    /// >this narrative</see> with the exception that it uses a symmetric
    /// algorithm to secure each layer instead of the asymmetric approach
    /// described in the example.  At each layer a random AES key and IV
    /// is generated and used to encrypt the secret data at that layer.
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
    public class LayeredSymmetricSecretSharing : SecretSharingAlgorithm
    {
        private static readonly  int INT_ARR_LEN = sizeof(int);

        public LayeredSymmetricSecretSharing()
        { }

        public override byte[] Split(byte[] secretClear, int shareCount)
        {
            var shares = new List<byte[]>();
            var secretCrypt = secretClear;
            using (var aes = Aes.Create())
            {
                for (int index = 0; index < shareCount; ++index)
                {
                    aes.GenerateKey();
                    aes.GenerateIV();
                    using (var enc = aes.CreateEncryptor())
                    {
                        secretCrypt = enc.TransformFinalBlock(secretCrypt, 0, secretCrypt.Length);
                    }

                    var keyLen = aes.Key.Length;
                    var ivLen = aes.IV.Length;

                    var indexArr = BitConverter.GetBytes(index);
                    var keyLenArr = BitConverter.GetBytes(keyLen);

                    var share = new byte[INT_ARR_LEN * 2 + keyLen + ivLen];

                    Array.Copy(indexArr, 0, share, 0, INT_ARR_LEN);
                    Array.Copy(keyLenArr, 0, share, INT_ARR_LEN, INT_ARR_LEN);
                    Array.Copy(aes.Key, 0, share, INT_ARR_LEN * 2, keyLen);
                    Array.Copy(aes.IV, 0, share, INT_ARR_LEN * 2 + keyLen, ivLen);
                    shares.Add(share);
                }
            }

            Shares = shares;

            return secretCrypt;
        }

        public override byte[] Join(byte[] secretCrypt)
        {
            var shares = new List<Tuple<int, byte[], byte[]>>();
            foreach (var sh in Shares)
            {
                var index = BitConverter.ToInt32(sh, 0);
                var keyLen = BitConverter.ToInt32(sh, INT_ARR_LEN);
                var key = new byte[keyLen];
                var iv = new byte[sh.Length - INT_ARR_LEN * 2 - keyLen];
                Array.Copy(sh, INT_ARR_LEN * 2, key, 0, keyLen);
                Array.Copy(sh, INT_ARR_LEN * 2 + keyLen, iv, 0, iv.Length);
                shares.Add(Tuple.Create(index, key, iv));
            }

            var secretClear = secretCrypt;
            using (var aes = Aes.Create())
            {
                foreach (var layeredShare in shares.OrderByDescending(x => x.Item1))
                {
                    using (var dec = aes.CreateDecryptor(layeredShare.Item2, layeredShare.Item3))
                    {
                        secretClear = dec.TransformFinalBlock(secretClear, 0, secretClear.Length);
                    }
                }
            }

            return secretClear;
        }
    }
}
