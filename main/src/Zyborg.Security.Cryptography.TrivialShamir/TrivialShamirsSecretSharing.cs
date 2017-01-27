using System;
using System.Collections.Generic;
using System.Linq;

namespace Zyborg.Security.Cryptography
{
    public class TrivialShamirsSecretSharing : ThresholdSecretSharingAlgorithm
    {
        public const int prime = 257;

        public override byte[] Split(byte[] secretClear, int shareCount)
        {
            return Split(secretClear, shareCount, shareCount);
        }

        public override byte[] Split(byte[] secretClear, int shareCount, int threshold)
        {
            if (secretClear.Length != sizeof(int))
                throw new ArgumentOutOfRangeException("secretClear",
                        "only trivial secrets (32-bit integers) are supported");
            
            var secretInt = BitConverter.ToInt32(secretClear, 0);
            Split(secretInt, shareCount, threshold);
            
            return new byte[0];
        }

        public override byte[] Combine(byte[] secretCrypt)
        {
            var secretInt = Join();
            return BitConverter.GetBytes(secretInt);
        }

        // /* Split number into the shares */
        // function split(number, available, needed) {
        //     var coef = [number, 166, 94], x, exp, c, accum, shares = [];
        //     /* Normally, we use the line:
        //     * for(c = 1, coef[0] = number; c < needed; c++)
        //           coef[c] = Math.floor(Math.random() * (prime  - 1));
        //     * where (prime - 1) is the maximum allowable value.
        //     * However, to follow this example, we hardcode the values:
        //     * coef = [number, 166, 94];
        //     * For production, replace the hardcoded value with the random loop
        //     * For each share that is requested to be available, run through the formula
        //       plugging the corresponding coefficient
        //     * The result is f(x), where x is the byte we are sharing (in the example, 1234)
        //     */
        //     for(x = 1; x <= available; x++) {
        //         /* coef = [1234, 166, 94] which is 1234x^0 + 166x^1 + 94x^2 */
        //         for(exp = 1, accum = coef[0]; exp < needed; exp++)
        //             accum = (accum + (coef[exp] * (Math.pow(x, exp) % prime) % prime)) % prime;
        //         /* Store values as (1, 132), (2, 66), (3, 188), (4, 241), (5, 225) (6, 140) */
        //         shares[x - 1] = [x, accum];
        //     }
        //     return shares;
        // }
        public Tuple<int, int>[] Split(int number, int available, int needed)
        {
Console.WriteLine($"ARGS: {number}, {available}, {needed}");
            var rand = new Random();
            var coef = new int[needed];
            coef[0] = number;
            for (int c = 1; c < needed; ++c)
                coef[c] = (int)Math.Floor(rand.NextDouble() * (prime - 1));
          //coef = new[] { number, 166, 94 };
Console.WriteLine($"COEF: {string.Join(",", coef)}");
            
            var shares = new Tuple<int, int>[available];
            for (var x = 1; x <= available; ++x)
            {
                var accum = coef[0];
                for (int exp = 1; exp < needed; ++exp)
                {
                    accum = (accum + (coef[exp] * ((int)Math.Pow(x, exp) % prime) % prime)) % prime;
                }
                shares[x - 1] = Tuple.Create(x, accum);
            }

            Shares = Convert(shares);

            return shares;
        }

        public static IEnumerable<byte[]> Convert(IEnumerable<Tuple<int, int>> shares)
        {
            return shares.Select(x =>
            {
                var bytes = new byte[sizeof(int) * 2];
                Array.Copy(BitConverter.GetBytes(x.Item1), 0, bytes, 0, sizeof(int));
                Array.Copy(BitConverter.GetBytes(x.Item2), 0, bytes, sizeof(int), sizeof(int));
                return bytes;
            });
        }

        public static IEnumerable<Tuple<int, int>> Convert(IEnumerable<byte[]> shares)
        {
            return shares.Select(x =>
            {
                var index = BitConverter.ToInt32(x, 0);
                var share = BitConverter.ToInt32(x, sizeof(int));
                return Tuple.Create(index, share);
            });            
        }

        public int Join()
        {
            return Join(Convert(Shares).ToArray());
        }

        // /* Join the shares into a number */
        // function join(shares) {
        //     var accum, count, formula, startposition, nextposition, value, numerator, denominator;
        //     for(formula = accum = 0; formula < shares.length; formula++) {
        //         /* Multiply the numerator across the top and denominators across the bottom to do
        //            Lagrange's interpolation
        //         * Result is x0(2), x1(4), x2(5) -> -4*-5 and (2-4=-2)(2-5=-3), etc for l0, l1, l2...
        //         */
        //         for(count = 0, numerator = denominator = 1; count < shares.length; count++) {
        //             if(formula == count)
        //                 continue; // If not the same value
        //             startposition = shares[formula][0];
        //             nextposition = shares[count][0];
        //             numerator = (numerator * -nextposition) % prime;
        //             denominator = (denominator * (startposition - nextposition)) % prime;
        //         }
        //         value = shares[formula][1];
        //         accum = (prime + accum + (value * numerator * modInverse(denominator))) % prime;
        //     }
        //     return accum;
        // }
        public int Join(Tuple<int, int>[] shares)
        {
            var accum = 0;
            for (int formula = 0; formula < shares.Length; ++formula)
            {
                var numerator = 1;
                var denominator = 1;
                for (int count = 0; count < shares.Length; ++count)
                {
                    if (formula == count)
                        continue;

                    var startposition = shares[formula].Item1;
                    var nextposition = shares[count].Item1;
                    numerator = (numerator * -nextposition) % prime;
                    denominator = (denominator * (startposition - nextposition)) % prime;
                }
                var value = shares[formula].Item2;
                accum = (prime + accum + (value * numerator * ModInverse(denominator))) % prime;
            }
            return accum;
        }

        // /* Gives the multiplicative inverse of k mod prime.
        //    In other words (k * modInverse(k)) % prime = 1 for all prime > k >= 1  */
        // function modInverse(k) { 
        //     k = k % prime;
        //     var r = (k < 0)
        //         ? -gcdD(prime,-k)[2]
        //         : gcdD(prime,k)[2];
        //     return (prime + r) % prime;
        // }
        public int ModInverse(int k)
        {
            k = k % prime;
            var r = (k < 0)
                ? -GcdD(prime, -k).Item3
                : GcdD(prime, k).Item3;
            return (prime + r) % prime;
        }

        // /* Gives the decomposition of the gcd of a and b.
        //    Returns [x,y,z] such that x = gcd(a,b) and y*a + z*b = x */
        // function gcdD(a,b) { 
        //     if (b == 0) return [a, 1, 0]; 
        //     else { 
        //         var n = Math.floor(a/b);
        //         var c = a % b;
        //         var r = gcdD(b,c); 
        //         return [r[0], r[2], r[1]-r[2]*n];
        //     }
        // }
        public Tuple<int, int, int> GcdD(int a, int b)
        {
            if (b == 0)
            {
                return Tuple.Create(a, 1, 0);
            }
            else
            {
                // var da = (double)a;
                // var db = (double)b;
                // var n = (int)Math.Floor(da / db);
                var n = a / b;
                var c = a % b;
                var r = GcdD(b, c);

                return Tuple.Create(r.Item1, r.Item3, r.Item2 - r.Item3 * n);
            }
        }
    }
}