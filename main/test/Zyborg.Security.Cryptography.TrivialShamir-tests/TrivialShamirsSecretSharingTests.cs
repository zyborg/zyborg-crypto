using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using Xunit;
using Zyborg.Security.Cryptography;

namespace Tests
{
    public class TrivialShamirsSecretSharingTests
    {
        [Fact]
        public void TestTrivialFixed() 
        {
            
            var sss = new TrivialFixedShamirsSecretSharing();

            var sh = sss.Split(129, 6, 3); /* split the secret value 129 into 6 components - at least 3 of which will be needed to figure out the secret value */

            var newshares = new List<Tuple<int, int>>();

            // newshares.Add(sh[1]);
            // newshares.Add(sh[3]);
            // newshares.Add(sh[4]); //[sh[1], sh[3], sh[4]]; /* pick any selection of 3 shared keys from sh */

            newshares.Add(sh[1]);
            newshares.Add(sh[2]);
            newshares.Add(sh[3]); //[sh[1], sh[3], sh[4]]; /* pick any selection of 3 shared keys from sh */


            Assert.Equal(129, sss.Join(newshares));
        }

        [Theory]
        // [InlineData( 1,  1)]
        // [InlineData( 2,  1)]
        // [InlineData(10,  3)]
        [InlineData( 6,  3)]
        public void TestTrivialFixed_Matches_Trivial(int available, int needed)
        {
            var sss1 = new TrivialFixedShamirsSecretSharing();
            var sss2 = new TrivialShamirsSecretSharing();

            var secretInt = 129;
            var split1 = sss1.Split(secretInt, available, needed);
            var shares1 = split1.Select(x =>
            {
                var bytes = new byte[sizeof(int) * 2];

                Array.Copy(BitConverter.GetBytes(x.Item1), 0, bytes, 0, sizeof(int));
                Array.Copy(BitConverter.GetBytes(x.Item2), 0, bytes, sizeof(int), sizeof(int));

                return bytes;
            });

            var split2 = sss2.Split(secretInt, available, needed);
            var shares2 = sss2.Shares;

          //Assert.Equal(shares1, shares2);

            var rand = new Random();
            var indexOrder = split1.OrderBy(x => rand.Next()).Select(x => x.Item1 - 1).Take(needed);
            // var joinShares1 = split1.Where(x => indexOrder.Contains(x.Item1));
            // var joinShares2 = split2.Where(x => indexOrder.Contains(x.Item1));

            var joinShares1 = indexOrder.Select(x => split1.ElementAt(x));
            var joinShares2 = indexOrder.Select(x => split2.ElementAt(x));

Console.WriteLine($"Indexes : " + string.Join(",", indexOrder));
Console.WriteLine($"Indexes1: {joinShares1.Count()} " + string.Join(",", joinShares1.Select(x => x.Item1 - 1)));
Console.WriteLine($"Indexes2: {joinShares2.Count()} " + string.Join(",", joinShares2.Select(x => x.Item1 - 1)));

            var join1 = sss1.Join(joinShares1.ToList());
            var join2 = sss2.Join(joinShares2.ToArray());
            Assert.Equal(secretInt, join1);
            // Assert.Equal(join1, join2);
        }

        [Theory]
        [InlineData( 1,  1)]
        [InlineData( 2,  1)]
      //[InlineData( 2,  2)]
        [InlineData( 6,  3)]
        [InlineData( 6,  5)]
      //[InlineData( 6,  6)]
        [InlineData(10,  1)]
        [InlineData(10,  3)]
        [InlineData(10,  5)]
        [InlineData(10,  7)]
        [InlineData(10,  9)]
      //[InlineData(10, 10)]
        public void TestSplitJoin_FixedValue_SameInstance_CustomInterface(int shareCount, int threshold)
        {
            var secretInt = 129;

            var ss1 = new TrivialShamirsSecretSharing();
            var shares = ss1.Split(secretInt, shareCount, threshold);

            var joinShares = shares.Take(threshold);

            var ss2 = ss1;
            var clear = ss2.Join(joinShares.ToArray());

            Assert.Equal(secretInt, clear);
        }

        [Theory]
        [InlineData( 1,  1)]
        [InlineData( 2,  1)]
      //[InlineData( 2,  2)]
        [InlineData( 6,  3)]
        [InlineData( 6,  5)]
      //[InlineData( 6,  6)]
        [InlineData(10,  1)]
        [InlineData(10,  3)]
        [InlineData(10,  5)]
        [InlineData(10,  7)]
        [InlineData(10,  9)]
      //[InlineData(10, 10)]
        public void TestSplitJoin_FixedValue_DiffInstance_CustomInterface(int shareCount, int threshold)
        {
            var secretInt = 129;

            var ss1 = new TrivialShamirsSecretSharing();
            var shares = ss1.Split(secretInt, shareCount, threshold);

            var joinShares = shares.Take(threshold);

            var ss2 = new TrivialShamirsSecretSharing();
            var clear = ss2.Join(joinShares.ToArray());

            Assert.Equal(secretInt, clear);
        }

        [Theory]
        [InlineData( 1,  1)]
        [InlineData( 2,  1)]
      //[InlineData( 2,  2)]
        [InlineData( 6,  3)]
        [InlineData( 6,  5)]
      //[InlineData( 6,  6)]
        [InlineData(10,  1)]
        [InlineData(10,  3)]
        [InlineData(10,  5)]
        [InlineData(10,  7)]
        [InlineData(10,  9)]
       //[InlineData(10, 10)]
        public void TestSplitJoin_FixedValue_SameInstance(int shareCount, int threshold)
        {
            var secretInt = 129;

            var ss1 = new TrivialShamirsSecretSharing();
            //var rawShares = ss1.Split(secretInt, shareCount, threshold);
            ss1.Split(BitConverter.GetBytes(secretInt), shareCount, threshold);

            var shares = ss1.Shares;
            var joinShares = shares.Take(threshold);
            ss1.Shares = joinShares;

            var ss2 = ss1;
            var clearInt = ss2.Join();
            //var clearInt = BitConverter.ToInt32(clear, 0);

            Assert.Equal(secretInt, clearInt);
        }

        [Theory]
        [InlineData( 1,  1)]
        [InlineData( 2,  1)]
      //[InlineData( 2,  2)]
        [InlineData( 6,  3)]
        [InlineData( 6,  5)]
      //[InlineData( 6,  6)]
        [InlineData(10,  1)]
        [InlineData(10,  3)]
        [InlineData(10,  5)]
        [InlineData(10,  7)]
        [InlineData(10,  9)]
      //[InlineData(10, 10)]
        public void TestSplitJoin_SameInstance(int shareCount, int threshold)
        {
            int secretInt;
            // using (var rng = RandomNumberGenerator.Create())
            // {
            //     var arr = new byte[sizeof(int)];
            //     rng.GetBytes(arr);
            //     secretInt = BitConverter.ToUInt16(arr, 0);
            // }
            secretInt = 256;

            var secret = BitConverter.GetBytes(secretInt);

            var ss1 = new TrivialShamirsSecretSharing();
            var crypt = ss1.Split(secret, shareCount, threshold);
            var shares = ss1.Shares.ToArray();

            var ss2 = new TrivialShamirsSecretSharing();
            ss2.Shares = shares.Take(threshold);

            var clear = ss2.Combine(crypt);
            var value = BitConverter.ToInt32(clear, 0);

            Assert.Equal(secret, clear);
            Assert.Equal(secretInt, value);
        }
    }
}
