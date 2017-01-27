using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using Zyborg.Numerics;

namespace Zyborg.Security.Cryptography
{
    public class BigIntShamirsSecretSharing : ThresholdSecretSharingAlgorithm
    {
        public const int INT_ARR_LEN = sizeof(int);

        private BigInteger _prime;

        public BigIntShamirsSecretSharing()
        {
            GeneratePrime();
        }

        public void GeneratePrime()
        {
            _prime = new BigInteger(ComputeRandomePrime());
        }

        public override byte[] Split(byte[] secretClear, int shareCount)
        {
            return Split(secretClear, shareCount, shareCount);
        }

        public override byte[] Split(byte[] secretClear, int shareCount, int threshold)
        {
            // var primeArr = ComputeRandomePrime();
            // var prime = new BigInteger(primeArr);
            var primeMinusOne = _prime - 1;
            var number = new BigInteger(secretClear);

            var coef = new BigInteger[threshold];
            coef[0] = number;

            // TODO: rewrite this to use cryptographically-secure RNG
            var rng = new Random();
            var pmo = new BigRational(primeMinusOne);
            for (int c = 1; c < threshold; ++c)
            {
                coef[c] = BigRational.Multiply(pmo, new BigRational(rng.NextDouble())).GetWholePart();
            }

            var shares = new Tuple<int, BigInteger>[shareCount];
            for (var x = 1; x <= shareCount; ++x)
            {
System.Console.WriteLine("X: " + x);
                var accum = coef[0];
                for (int exp = 1; exp < threshold; ++exp)
                {
                    // accum = (accum + (coef[exp] * (Math.pow(x, exp) % prime) % prime)) % prime;
                    var a = new BigInteger(Math.Pow(x, exp)) % _prime; // (Math.pow(x, exp) % prime)
                    var b = (coef[exp] * a) % _prime; // (coef[exp] * a % prime)
                    var c = (accum + b) % _prime; // (accum + b) % prime;

                    accum = c;
                }

                shares[x - 1] = Tuple.Create(x, accum);
            }

            Shares = shares.Select(x => {
                var index = BitConverter.GetBytes(x.Item1);
                var biarr = x.Item2.ToByteArray();
                var bytes = new byte[INT_ARR_LEN + biarr.Length];
                Array.Copy(index, 0, bytes, 0, INT_ARR_LEN);
                Array.Copy(biarr, 0, bytes, INT_ARR_LEN, biarr.Length);
                return bytes;
            });

            // The original secret value is fully encoded in the distributed shares so there
            // is no need to return any version of the original secreted in encrypted form
            return new byte[0];
        }

        public override byte[] Combine(byte[] secretCrypt)
        {
            var accum = BigInteger.Zero;
            var shares = new List<Tuple<int, BigInteger>>();
            
            foreach (var sh in Shares)
            {
                var index = BitConverter.ToInt32(sh, 0);
                var biarr = new byte[sh.Length - INT_ARR_LEN];
                Array.Copy(sh, INT_ARR_LEN, biarr, 0, biarr.Length);
                shares.Add(Tuple.Create(index, new BigInteger(biarr)));
            }

            for (int formula = 0; formula < shares.Count; ++formula)
            {
                var numerator = BigInteger.One;
                var denominator = BigInteger.One;
                for (int count = 0; count < shares.Count; ++count)
                {
                    if (formula == count)
                        continue;
                    var startPosition = shares[formula].Item1;
                    var nextPosition = shares[count].Item1;
                    numerator = (numerator * -nextPosition) % _prime;
                    denominator = (denominator * (startPosition - nextPosition)) % _prime;
                }

                var value = shares[formula].Item2;
                accum = (_prime + accum + (value * numerator * ModInverse(denominator))) % _prime;
            }

            return accum.ToByteArray();
        }

        protected static byte[] ComputeRandomePrime()
        {
            // TODO:  THIS IS A MAJOR HACK!
            // For now we just use one of the two generated prime numbers
            // of the RSA Asymmetric Algorithm (P or Q), CLEAN THIS UP!!!
            using (var rsa = RSA.Create())
            {
                var rsaParams = rsa.ExportParameters(true);
                return rsaParams.P;
            }
        }

        protected Tuple<BigInteger, BigInteger, BigInteger> GcdD(BigInteger a, BigInteger b)
        {
            if (b.IsZero)
            {
                return Tuple.Create(a, BigInteger.One, BigInteger.Zero);
            }
            else
            {
                BigInteger c;
                var n = BigInteger.DivRem(a, b, out c);
                var r = GcdD(b, c);

                return Tuple.Create(r.Item1, r.Item3,
                        BigInteger.Multiply(BigInteger.Subtract(r.Item2, r.Item3), n));
            }            
        }

        protected BigInteger ModInverse(BigInteger k)
        {
            k = BigInteger.Remainder(k, _prime);
            var r = (k.Sign < 0)
                ? - GcdD(_prime, BigInteger.Negate(k)).Item3
                : GcdD(_prime, k).Item3;
            
            return BigInteger.Remainder(BigInteger.Add(_prime, r), _prime);
        }
    }
}