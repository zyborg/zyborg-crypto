using System;
using System.Text;
using Xunit;

namespace Zyborg.Security.Cryptography
{
    public class HashiCorpShamirTests
    {
        [Fact]
        public void TestTables()
        {
            for (int i = 1; i < 256; i++)
            {
                var logV = HashiCorpShamir.LOG_TABLE[i];
                var expV = HashiCorpShamir.EXP_TABLE[logV];
                
                Assert.Equal(expV, (byte)i);
            }
        }

        [Fact]
        public void TestSplit_invalid()
        {
            var secret = Encoding.UTF8.GetBytes("test");

            Assert.ThrowsAny<ArgumentException>(
                    () => HashiCorpShamir.Split(secret, 0, 0));

            Assert.ThrowsAny<ArgumentException>(
                    () => HashiCorpShamir.Split(secret, 2, 3));

            Assert.ThrowsAny<ArgumentException>(
                    () => HashiCorpShamir.Split(secret, 1000, 3));

            Assert.ThrowsAny<ArgumentException>(
                    () => HashiCorpShamir.Split(secret, 10, 1));

            Assert.ThrowsAny<ArgumentException>(
                    () => HashiCorpShamir.Split(new byte[0], 3, 2));

            Assert.ThrowsAny<ArgumentException>(
                    () => HashiCorpShamir.Split(null, 3, 2));

            // if _, err := Split(secret, 0, 0); err == nil {
            //     t.Fatalf("expect error")
            // }

            // if _, err := Split(secret, 2, 3); err == nil {
            //     t.Fatalf("expect error")
            // }

            // if _, err := Split(secret, 1000, 3); err == nil {
            //     t.Fatalf("expect error")
            // }

            // if _, err := Split(secret, 10, 1); err == nil {
            //     t.Fatalf("expect error")
            // }

            // if _, err := Split(nil, 3, 2); err == nil {
            //     t.Fatalf("expect error")
            // }
        }

        [Fact]
        public void TestSplit()
        {
            var secret = Encoding.UTF8.GetBytes("test");

            var ret = HashiCorpShamir.Split(secret, 5, 3);

            Assert.Equal(5, ret.Length);

            foreach (var share in ret)
            {
                Assert.Equal(share.Length, secret.Length + 1);
            }
        }

        [Fact]
        public void TestCombine_invalid()
        {
            // Not enough parts
            Assert.ThrowsAny<ArgumentException>(
                    () => HashiCorpShamir.Combine(null));

            // Mis-match in length
            var parts = new byte[][]
            {
                Encoding.UTF8.GetBytes("foo"),
                Encoding.UTF8.GetBytes("ba"),
            };
            Assert.ThrowsAny<ArgumentException>(
                    () => HashiCorpShamir.Combine(parts));

            //Too short
            parts = new byte[][]
            {
                Encoding.UTF8.GetBytes("f"),
                Encoding.UTF8.GetBytes("b"),
            };
            Assert.ThrowsAny<ArgumentException>(
                    () => HashiCorpShamir.Combine(parts));

            parts = new byte[][]
            {
                Encoding.UTF8.GetBytes("foo"),
                Encoding.UTF8.GetBytes("foo"),
            };
            Assert.ThrowsAny<InvalidOperationException>(
                    () => HashiCorpShamir.Combine(parts));
        }

        [Fact]
        public void TestCombine()
        {
            var secret = Encoding.UTF8.GetBytes("test");

            var ret = HashiCorpShamir.Split(secret, 5, 3);

            // There is 5*4*3 possible choices,
            // we will just brute force try them all
            for (int i = 0; i < 5; i++)
            {
                for (var j = 0; j < 5; j++)
                {
                    if (j == i)
                        continue;

                    for (var k = 0; k < 5; k++)
                    {
                        if (k == i || k == j)
                            continue;

                        var parts = new byte[][] { ret[i], ret[j], ret[k] };
                        var recomb = HashiCorpShamir.Combine(parts);

                        Assert.Equal(recomb, secret);
                        // if !bytes.Equal(recomb, secret) {
                        //     t.Errorf("parts: (i:%d, j:%d, k:%d) %v", i, j, k, parts)
                        //     t.Fatalf("bad: %v %v", recomb, secret)
                        // }
                    }
                }
            }
        }

        [Fact]
        public void TestField_Add()
        {
            Assert.Equal(0, HashiCorpShamir.Add(16, 16));

            Assert.Equal(7, HashiCorpShamir.Add(3, 4));
        }

        [Fact]
        public void TestField_Mult()
        {
            Assert.Equal(9, HashiCorpShamir.Mult(3, 7));

            Assert.Equal(0, HashiCorpShamir.Mult(3, 0));

            Assert.Equal(0, HashiCorpShamir.Mult(0, 3));
        }

        [Fact]
        public void TestField_Divide()
        {
            Assert.Equal(0, HashiCorpShamir.Div(0, 7));

            Assert.Equal(1, HashiCorpShamir.Div(3, 3));

            Assert.Equal(2, HashiCorpShamir.Div(6, 3));
        }

        [Fact]
        public void TestPolynomial_Random()
        {
            var p = HashiCorpShamir.MakePolynomial(42, 2);

            Assert.Equal(42, p.Coefficients[0]);
        }

        [Fact]
        public void TestPolynomial_Eval()
        {
            var p = HashiCorpShamir.MakePolynomial(42, 1);

            Assert.Equal(42, p.Evaluate(0));            

            // out := p.evaluate(1)
            // exp := add(42, mult(1, p.coefficients[1]))
            // if out != exp {
            //     t.Fatalf("bad: %v %v %v", out, exp, p.coefficients)
            // }

            var ret = p.Evaluate(1);
            var exp = HashiCorpShamir.Add(42,
                    HashiCorpShamir.Mult(1, p.Coefficients[1]));
            Assert.Equal(ret, exp);
        }

        [Fact]
        public void TestInterpolate_Rand()
        {
            for (int i = 0; i < 256; i++)
            {
                var p = HashiCorpShamir.MakePolynomial((byte)i, 2);

                var x_vals = new byte[] { 1, 2, 3 };
                var y_vals = new byte[] { p.Evaluate(1), p.Evaluate(2), p.Evaluate(3) };

                // out := interpolatePolynomial(x_vals, y_vals, 0)
                // if out != uint8(i) {
                //     t.Fatalf("Bad: %v %d", out, i)
                // }

                Assert.Equal((byte)i,
                        HashiCorpShamir.InterpolatePolynomial(x_vals, y_vals, 0));
            }
        }
    }
}