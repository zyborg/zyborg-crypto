using System;
using System.Security.Cryptography;
using System.Text;
using Xunit;

namespace Zyborg.Security.Cryptography
{
    public class HashiCorpShamirSecretSharingTests
    {
        [Fact]
        public void TestAllShares()
        {
            var r = new Random();
            for (int i = 0; i < 10; ++i)
            {
                var secret = new byte[r.Next(50)];
                var shareCount = r.Next(255);
                Console.WriteLine("Secret.Length = " + secret.Length);
                Console.WriteLine("Share Count = " + shareCount);

                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(secret);
                }
                var shamir1 = SecretSharingAlgorithm.Create("HashiCorpShamir");
                var shamir2 = SecretSharingAlgorithm.Create("HashiCorpShamir");

                var crypt = shamir1.Split(secret, shareCount);
                var shares = shamir1.Shares;

                shamir2.Shares = shares;
                var clear = shamir2.Combine(crypt);

                Assert.Equal(secret, clear);
            }
        }

        [Fact]
        public void TestSharesAndThresholds()
        {
            var r = new Random();
            for (int i = 0; i < 10; ++i)
            {
                var secret = new byte[r.Next(2, 50)];
                var shareCount = r.Next(2, 15);
                var threshold = r.Next(2, shareCount);
                Console.WriteLine("Secret.Length = " + secret.Length);
                Console.WriteLine("Share Count = " + shareCount);
                Console.WriteLine("Threshold = " + threshold);

                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(secret);
                }
                var shamir1 = ThresholdSecretSharingAlgorithm.Create("HashiCorpShamir");
                var shamir2 = ThresholdSecretSharingAlgorithm.Create("HashiCorpShamir");

                var crypt = shamir1.Split(secret, shareCount, threshold);
                var shares = shamir1.Shares;

                shamir2.Shares = shares;
                var clear = shamir2.Combine(crypt);

                Assert.Equal(secret, clear);
            }
        }
    }
}
