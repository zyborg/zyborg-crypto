using System.Linq;
using System.Security.Cryptography;
using Xunit;

namespace Zyborg.Security.Cryptography
{
    public class BigIntShamirsSecretSharingTests
    {
        [Theory(Skip = "Needs Revision")]
      //[InlineData(10, 1)]
        [InlineData(10, 2, 1)]
        // [InlineData(10, 5)]
        // [InlineData(100, 1)]
        // [InlineData(100, 2)]
        // [InlineData(100, 10)]
        public void TestSplitJoin_SameInstance(int secretSize, int shareCount, int threshold)
        {
            var secret = new byte[secretSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(secret);
            }
            var ss1 = new BigIntShamirsSecretSharing();
            var crypt = ss1.Split(secret, shareCount);
            var shares = ss1.Shares.ToArray();

            var ss2 = ss1; //new ShamirsSecretSharing();
            ss2.Shares = shares.Take(threshold);
            var clear = ss2.Combine(crypt);

            Assert.Equal(secret, clear);         
        }
    }
}