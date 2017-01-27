using System.Linq;
using System.Security.Cryptography;
using Xunit;

namespace Zyborg.Security.Cryptography
{
    public class LayeredSymmetricSecretSharingTests
    {
        [Theory]
        [InlineData(10, 1)]
        [InlineData(10, 2)]
        [InlineData(10, 5)]
        [InlineData(100, 1)]
        [InlineData(100, 2)]
        [InlineData(100, 10)]
        public void TestLayers(int secretSize, int shareCount)
        {
            var secret = new byte[secretSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(secret);
            }
            var ss1 = new LayeredSymmetricSecretSharing();
            var crypt = ss1.Split(secret, shareCount);
            var shares = ss1.Shares.ToArray();

            var ss2 = new LayeredSymmetricSecretSharing();
            ss2.Shares = shares;
            var clear = ss2.Join(crypt);

            Assert.Equal(secret, clear);         
        }
    }
}