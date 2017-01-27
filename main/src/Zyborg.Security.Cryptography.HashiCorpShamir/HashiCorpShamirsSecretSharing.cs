using System;
using System.Linq;
using System.Security.Cryptography;

namespace Zyborg.Security.Cryptography
{
    public class HashiCorpShamirsSecretSharing : ThresholdSecretSharingAlgorithm
    {
        public override byte[] Split(byte[] secretClear, int shareCount)
        {
            return Split(secretClear, shareCount, shareCount);
        }

        public override byte[] Split(byte[] secretClear, int shareCount, int threshold)
        {
            Shares = HashiCorpShamir.Split(secretClear, shareCount, threshold);

            // All encoded data is contained within the encoded shares,
            // so there is no transformed form of the secret to return
            return new byte[0];
        }

        public override byte[] Combine(byte[] secretCrypt)
        {
            return HashiCorpShamir.Combine(Shares.ToArray());
        }
    }
}