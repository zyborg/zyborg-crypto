using System;
using System.Collections.Generic;

namespace Zyborg.Security.Cryptography
{
    public class TrivialFixedShamirsSecretSharing : SecretSharingAlgorithm
    {
        public const int prime = 257;

        // /* Split number into the shares */
        // function split(number, available, needed) {
        //     var coef = [number, 166, 94], x, exp, c, accum, shares = [];
        //     /* Normally, we use the line:
        //     * for(c = 1, coef[0] = number; c < needed; c++) coef[c] = Math.floor(Math.random() * (prime  - 1));
        //     * where (prime - 1) is the maximum allowable value.
        //     * However, to follow this example, we hardcode the values:
        //     * coef = [number, 166, 94];
        //     * For production, replace the hardcoded value with the random loop
        //     * For each share that is requested to be available, run through the formula plugging the corresponding coefficient
        //     * The result is f(x), where x is the byte we are sharing (in the example, 1234)
        //     */
        //     for(x = 1; x <= available; x++) {
        //         /* coef = [1234, 166, 94] which is 1234x^0 + 166x^1 + 94x^2 */
        //         for(exp = 1, accum = coef[0]; exp < needed; exp++) accum = (accum + (coef[exp] * (Math.pow(x, exp) % prime) % prime)) % prime;
        //         /* Store values as (1, 132), (2, 66), (3, 188), (4, 241), (5, 225) (6, 140) */
        //         shares[x - 1] = [x, accum];
        //     }
        //     return shares;
        // }
        public List<Tuple<int, int>> Split(int number, int available, int needed)
        {
Console.WriteLine($"ARGS: {number}, {available}, {needed}");
            var coef = new[] { number, 166, 94 };
            var shares = new List<Tuple<int, int>>();
Console.WriteLine($"COEF: {string.Join(",", coef)}");

            for (var x = 1; x <= available; ++x)
            {
                shares.Add(null);
                var accum = coef[0];
                for (int exp = 1; exp < needed; ++exp)
                {
                    accum = (accum + (coef[exp] * ((int)Math.Pow(x, exp) % prime) % prime)) % prime;
                }
                shares[x - 1] = Tuple.Create(x, accum);
            }

            return shares;
        }


        // /* Join the shares into a number */
        // function join(shares) {
        //     var accum, count, formula, startposition, nextposition, value, numerator, denominator;
        //     for(formula = accum = 0; formula < shares.length; formula++) {
        //         /* Multiply the numerator across the top and denominators across the bottom to do Lagrange's interpolation
        //         * Result is x0(2), x1(4), x2(5) -> -4*-5 and (2-4=-2)(2-5=-3), etc for l0, l1, l2...
        //         */
        //         for(count = 0, numerator = denominator = 1; count < shares.length; count++) {
        //             if(formula == count) continue; // If not the same value
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
        public int Join(List<Tuple<int, int>> shares)
        {
            var accum = 0;
            for (int formula = 0; formula < shares.Count; ++formula)
            {
                var numerator = 1;
                var denominator = 1;
                for (int count = 0; count < shares.Count; ++count)
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

        // /* Gives the decomposition of the gcd of a and b.  Returns [x,y,z] such that x = gcd(a,b) and y*a + z*b = x */
        // function gcdD(a,b) { 
        //     if (b == 0) return [a, 1, 0]; 
        //     else { 
        //         var n = Math.floor(a/b), c = a % b, r = gcdD(b,c); 
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
                var n = (int)Math.Floor((double)a / b);
                var c = a % b;
                var r = GcdD(b, c);

                return Tuple.Create(r.Item1, r.Item3, r.Item2 - r.Item3 * n);
            }
        }

        // /* Gives the multiplicative inverse of k mod prime.  In other words (k * modInverse(k)) % prime = 1 for all prime > k >= 1  */
        // function modInverse(k) { 
        //     k = k % prime;
        //     var r = (k < 0) ? -gcdD(prime,-k)[2] : gcdD(prime,k)[2];
        //     return (prime + r) % prime;
        // }
        public int ModInverse(int k)
        {
            k = k % prime;
            var r = (k < 0) ? -GcdD(prime, -k).Item3 : GcdD(prime, k).Item3;
            return (prime + r) % prime;
        }

        public override byte[] Split(byte[] secretClear, int shareCount)
        {
            throw new NotImplementedException();
        }

        public override byte[] Join(byte[] secretCrypt)
        {
            throw new NotImplementedException();
        }
    }
}