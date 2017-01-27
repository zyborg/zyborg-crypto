using System;
using System.Security.Cryptography;

namespace Zyborg.Security.Cryptography
{
    public class HashiCorpShamirsSecretSharing : SecretSharingAlgorithm, IThresholdSecretSharingAlgorithm
    {
        // ShareOverhead is the byte size overhead of each share
        // when using Split on a secret. This is caused by appending
        // a one byte tag to the share.
        public const int SharedOverhead = 1;

        public override byte[] Split(byte[] secretClear, int shareCount)
        {
            throw new NotImplementedException();
        }

        public byte[] Split(byte[] secretClear, int shareCount, int threshold)
        {
            throw new NotImplementedException();
        }

        public override byte[] Join(byte[] secretCrypt)
        {
            throw new NotImplementedException();
        }
    }
}