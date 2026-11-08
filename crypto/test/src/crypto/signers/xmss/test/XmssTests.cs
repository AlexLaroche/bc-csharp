using System;
using System.Collections.Generic;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    using Xmss = XmssHarnessTests.Xmss;

    /// <summary>Test cases for the XMSS signer, over the harness key holder.</summary>
    /// <remarks>
    /// The signature vectors are compared byte for byte; those longer than 4096 hex characters are loaded from
    /// <c>crypto/test/data/xmss/XmssTests.*.hex</c>.
    /// </remarks>
    [TestFixture]
    public class XmssTests
    {
        [Test]
        [Explicit] // slow: ~24s
        public void TestAuthPath()
        {
            XmssParameters xmssParams = new XmssParameters(10, new Sha256Digest());
            Xmss xmss = new Xmss(xmssParams, new XmssHarnessTests.NullPrng());
            xmss.GenerateKeys();
            string[] expectedAuthPath = {
                "e0e81477f50e2b8719d1d9a3c1a55d5460711b88eb4f2c8df8d17d38832de9d4",
                "251142aa2cdb5a9d81a0c7a98e2c3c95bf96e73c68c78d467186eeac1dffce38",
                "53a6a544a1331bf650758d64bb8fab1104170824894fdd8a284d281aec9d6270",
                "5683d8f8de11a5845b9d1b5cedb7fd0bd76da3341e75ddd05f261520228664d0",
                "16b265f881e4b7bd303b7c38b8adcf31a7c211bcddb5260080105c1b70c41ee9",
                "9d421eefaf1e51d762f245853cc36250bfbb3f547770303dc8a38d03dec2d0a7",
                "233b634f83a2456f279126c7fcb47f9301cb2d5e8db69f4721f68000d78cffb3",
                "9317371748b85e824bd82284875b7bb65604c94ff0b8816cef677ade31963bd5",
                "14ba59e3d998735a963d018b840a80be11a52ccdadaceb7ed45f0763e6cd49ca",
                "6af97f6bde85e4569178192bab4fd59d8c2b1fec181f27a8fa2c17552c16e3b5"
            };
            byte[] signature = xmss.Sign(new byte[1024]);
            XmssSignature sig = new XmssSignature.Builder(xmssParams).WithSignature(signature).Build();

            Assert.AreEqual(NistObjectIdentifiers.IdSha256, xmssParams.TreeDigestOid);

            IList<XmssNode> authPath = sig.AuthPath;
            Assert.AreEqual(expectedAuthPath.Length, authPath.Count);
            for (int i = 0; i < authPath.Count; i++)
            {
                Assert.AreEqual(expectedAuthPath[i], Hex.ToHexString(authPath[i].GetValue()));
            }
        }

        [Test]
        [Explicit] // slow: ~14s
        public void TestGenKeyPairSha256()
        {
            XmssParameters xmssParams = new XmssParameters(10, new Sha256Digest());
            Xmss xmss = new Xmss(xmssParams, new XmssHarnessTests.NullPrng());
            xmss.GenerateKeys();
            byte[] privateKey = xmss.ExportPrivateKey().GetEncoded();
            byte[] publicKey = xmss.ExportPublicKey().GetEncoded();
            string expectedPrivateKey =
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                    + "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                    + "0000000073c3fc6de1195aa5d69f9dafc9db8504aa8059115e8319ca15cf58a1c83c0de3";
            string expectedPublicKey =
                "0000000173c3fc6de1195aa5d69f9dafc9db8504aa8059115e8319ca15cf58a1c83c0de3000000000000000000000000"
                    + "0000000000000000000000000000000000000000";
            byte[] strippedPrivateKey = Arrays.CopyOfRange(privateKey, 0, Hex.Decode(expectedPrivateKey).Length);

            Assert.AreEqual(Hex.Decode(expectedPrivateKey), strippedPrivateKey);
            Assert.AreEqual(Hex.Decode(expectedPublicKey), publicKey);
        }

        [Test]
        [Explicit] // slow: ~76s
        public void TestGenKeyPairSha512()
        {
            XmssParameters xmssParams = new XmssParameters(10, new Sha512Digest());
            Xmss xmss = new Xmss(xmssParams, new XmssHarnessTests.NullPrng());
            xmss.GenerateKeys();
            byte[] privateKey = xmss.ExportPrivateKey().GetEncoded();
            byte[] publicKey = xmss.ExportPublicKey().GetEncoded();
            string expectedPrivateKey =
                "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                    + "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                    + "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                    + "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                    + "00000000f48df90f8e217076d8af6327691321bdcf63668c4bd28d021d49f2334eca845fa3073991049286c0eef5dc7f"
                    + "23ec0b31f5c1bd1e5b8edb2403ae02f292f6f30e";
            string expectedPublicKey =
                "00000004f48df90f8e217076d8af6327691321bdcf63668c4bd28d021d49f2334eca845fa3073991049286c0eef5dc7f"
                    + "23ec0b31f5c1bd1e5b8edb2403ae02f292f6f30e00000000000000000000000000000000000000000000000000000000"
                    + "000000000000000000000000000000000000000000000000000000000000000000000000";
            byte[] strippedPrivateKey = Arrays.CopyOfRange(privateKey, 0, Hex.Decode(expectedPrivateKey).Length);

            Assert.AreEqual(Hex.Decode(expectedPrivateKey), strippedPrivateKey);
            Assert.AreEqual(Hex.Decode(expectedPublicKey), publicKey);
        }

        [Test]
        public void TestSignSha256()
        {
            XmssParameters parameters = new XmssParameters(10, new Sha256Digest());
            Xmss xmss = new Xmss(parameters, new XmssHarnessTests.NullPrng());
            xmss.GenerateKeys();
            byte[] message = new byte[1024];
            byte[] sig1 = xmss.Sign(message);
            byte[] sig2 = xmss.Sign(message);
            byte[] sig3 = xmss.Sign(message);

            Assert.AreEqual(XmssTestData.LoadHex("XmssTests.SignSha256.Sig1.hex"), sig1);
            Assert.AreEqual(XmssTestData.LoadHex("XmssTests.SignSha256.Sig2.hex"), sig2);
            Assert.AreEqual(XmssTestData.LoadHex("XmssTests.SignSha256.Sig3.hex"), sig3);
        }

        [Test]
        public void TestSignSha256CompleteEvenHeight1()
        {
            int height = 4;
            XmssParameters parameters = new XmssParameters(height, new Sha256Digest());
            Xmss xmss = new Xmss(parameters, new XmssHarnessTests.NullPrng());
            xmss.GenerateKeys();
            for (int i = 0; i < (1 << height); i++)
            {
                byte[] signature = xmss.Sign(new byte[1024]);
                Assert.AreEqual(XmssTestData.LoadHex("XmssTests.SignSha256CompleteEvenHeight1.Sig"
                    + i.ToString("D2") + ".hex"), signature, "signature " + i);
            }

            Assert.Throws<ExhaustedPrivateKeyException>(() => xmss.Sign(new byte[1024]));
        }

        /// <remarks>
        /// The Java method lists the second vector under case 0x0822, an index a tree of height 10 does not have, so
        /// it never compares it. The vector itself opens with index 0x00000082, which is what it is compared at here.
        /// </remarks>
        [Test]
        [Explicit] // slow: ~72s
        public void TestSignSha256CompleteEvenHeight2()
        {
            int[] indices = new int[]{ 0x005b, 0x0082, 0x00b0, 0x016d, 0x0189, 0x01f9, 0x02a1, 0x038b, 0x03fe, 0x03ff };
            Dictionary<int, byte[]> signatures = new Dictionary<int, byte[]>();
            for (int k = 0; k != indices.Length; k++)
            {
                signatures.Add(indices[k], XmssTestData.LoadHex("XmssTests.SignSha256CompleteEvenHeight2.Sig" + k
                    + ".hex"));
            }

            int height = 10;
            XmssParameters parameters = new XmssParameters(height, new Sha256Digest());
            Xmss xmss = new Xmss(parameters, new XmssHarnessTests.NullPrng());
            xmss.GenerateKeys();
            int compared = 0;
            for (int i = 0; i < (1 << height); i++)
            {
                byte[] signature = xmss.Sign(new byte[1024]);
                if (signatures.TryGetValue(i, out byte[] expected))
                {
                    Assert.AreEqual(expected, signature, "signature " + i);
                    compared++;
                }
            }
            Assert.AreEqual(indices.Length, compared);

            Assert.Throws<ExhaustedPrivateKeyException>(() => xmss.Sign(new byte[1024]));
        }

        [Test]
        [Explicit] // slow: ~33s
        public void TestSignSha512()
        {
            XmssParameters parameters = new XmssParameters(10, new Sha512Digest());
            Xmss xmss = new Xmss(parameters, new XmssHarnessTests.NullPrng());
            xmss.GenerateKeys();
            byte[] message = new byte[1024];
            byte[] sig1 = xmss.Sign(message);
            byte[] sig2 = xmss.Sign(message);
            byte[] sig3 = xmss.Sign(message);

            Assert.AreEqual(XmssTestData.LoadHex("XmssTests.SignSha512.Sig1.hex"), sig1);
            Assert.AreEqual(XmssTestData.LoadHex("XmssTests.SignSha512.Sig2.hex"), sig2);
            Assert.AreEqual(XmssTestData.LoadHex("XmssTests.SignSha512.Sig3.hex"), sig3);
        }

        [Test]
        public void TestVerifySignatureSha256()
        {
            CheckVerifySignature(new XmssParameters(4, new Sha256Digest()));
        }

        [Test]
        public void TestVerifySignatureSha512()
        {
            CheckVerifySignature(new XmssParameters(4, new Sha512Digest()));
        }

        private static void CheckVerifySignature(XmssParameters parameters)
        {
            Xmss xmss = new Xmss(parameters, new XmssHarnessTests.NullPrng());
            xmss.GenerateKeys();
            byte[] msg1 = new byte[1024];

            for (int i = 0; i < 3; i++)
            {
                byte[] publicKey = xmss.ExportPublicKey().GetEncoded();
                xmss.Sign(msg1);
                byte[] signature = xmss.Sign(msg1);
                Assert.IsTrue(xmss.VerifySignature(msg1, signature, publicKey));
                byte[] msg2 = new byte[1024];
                msg2[0] = 0x01;
                Assert.IsFalse(xmss.VerifySignature(msg2, signature, publicKey));
            }
        }

        [Test]
        public void TestImportStateSha256()
        {
            CheckImportState(new XmssParameters(4, new Sha256Digest()));
        }

        [Test]
        public void TestImportKeysSha512()
        {
            CheckImportState(new XmssParameters(4, new Sha512Digest()));
        }

        private static void CheckImportState(XmssParameters parameters)
        {
            Xmss xmss1 = new Xmss(parameters, new XmssHarnessTests.NullPrng());
            xmss1.GenerateKeys();
            byte[] msg1 = new byte[1024];
            byte[] msg2 = new byte[2048];
            byte[] msg3 = new byte[3096];
            Arrays.Fill(msg1, 0xaa);
            Arrays.Fill(msg2, 0xbb);
            Arrays.Fill(msg3, 0xcc);
            byte[] signature1 = xmss1.Sign(msg1);
            byte[] signature2 = xmss1.Sign(msg2);
            byte[] exportedPrivateKey = xmss1.ExportPrivateKey().GetEncoded();
            byte[] exportedPublicKey = xmss1.ExportPublicKey().GetEncoded();
            byte[] signature3 = xmss1.Sign(msg3);

            Xmss xmss2 = new Xmss(parameters, new XmssHarnessTests.NullPrng());

            xmss2.ImportState(exportedPrivateKey, exportedPublicKey);

            byte[] signature4 = xmss2.Sign(msg3);
            Assert.IsTrue(Arrays.AreEqual(signature3, signature4));
            xmss2.GenerateKeys();
            Assert.IsTrue(xmss2.VerifySignature(msg1, signature1, exportedPublicKey));
            Assert.IsTrue(xmss2.VerifySignature(msg2, signature2, exportedPublicKey));
            Assert.IsTrue(xmss2.VerifySignature(msg3, signature3, exportedPublicKey));
            Assert.IsFalse(xmss2.VerifySignature(msg1, signature3, exportedPublicKey));
            Assert.IsFalse(xmss2.VerifySignature(msg2, signature3, exportedPublicKey));
        }

        [Test]
        public void TestRandom()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha512Digest());
            Xmss xmss1 = new Xmss(parameters, new SecureRandom());
            xmss1.GenerateKeys();
            byte[] publicKey = xmss1.ExportPublicKey().GetEncoded();
            byte[] message = new byte[1024];

            for (int i = 0; i < 5; i++)
            {
                xmss1.Sign(message);
            }
            byte[] signature = xmss1.Sign(message);
            Assert.IsTrue(Arrays.AreEqual(publicKey, xmss1.ExportPublicKey().GetEncoded()));
            xmss1.VerifySignature(message, signature, publicKey);
            Assert.IsTrue(Arrays.AreEqual(publicKey, xmss1.ExportPublicKey().GetEncoded()));
            xmss1.Sign(message);
            byte[] privateKey7 = xmss1.ExportPrivateKey().GetEncoded();
            xmss1.VerifySignature(message, signature, publicKey);
            Assert.IsTrue(Arrays.AreEqual(privateKey7, xmss1.ExportPrivateKey().GetEncoded()));
            byte[] signature7 = xmss1.Sign(message);

            xmss1.ImportState(privateKey7, publicKey);

            byte[] signature7AfterImport = xmss1.Sign(message);
            Assert.IsTrue(Arrays.AreEqual(signature7AfterImport, signature7));

            XmssParameters params2 = new XmssParameters(4, new Sha512Digest());
            Xmss xmss2 = new Xmss(params2, new SecureRandom());
            Assert.IsTrue(xmss2.VerifySignature(message, signature7, publicKey));
            Assert.IsTrue(xmss2.VerifySignature(message, signature, publicKey));

            Xmss xmss3 = new Xmss(parameters, new XmssHarnessTests.NullPrng());

            xmss3.ImportState(privateKey7, publicKey);

            byte[] signatureAgain = xmss3.Sign(message);
            Assert.IsTrue(Arrays.AreEqual(signatureAgain, signature7));
        }

        [Test]
        public void TestBdsImport()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            Xmss xmss = new Xmss(parameters, new SecureRandom());
            xmss.GenerateKeys();
            byte[] exportedPrivateKey = xmss.ExportPrivateKey().GetEncoded();
            byte[] exportedPublicKey = xmss.ExportPublicKey().GetEncoded();

            xmss.ImportState(exportedPrivateKey, exportedPublicKey);

            byte[] sig1 = xmss.Sign(new byte[1024]);

            xmss.ImportState(exportedPrivateKey, exportedPublicKey);

            byte[] sig2 = xmss.Sign(new byte[1024]);
            Assert.IsTrue(Arrays.AreEqual(sig1, sig2));
            try
            {
                xmss.ImportState(exportedPrivateKey, exportedPublicKey);
            }
            catch (Exception)
            {
            }
            xmss.Sign(new byte[1024]);
            byte[] sig3 = xmss.Sign(new byte[1024]);
            Assert.IsFalse(Arrays.AreEqual(sig1, sig3));
            Assert.Throws<ArgumentNullException>(() => xmss.ImportState(null, exportedPublicKey));
            Assert.Throws<ArgumentNullException>(() => xmss.ImportState(exportedPrivateKey, null));
        }

        [Test]
        public void TestSignVerifySP800208_Sha256_192()
        {
            CheckSignVerifySP800208(0x0000000d, 24);
        }

        [Test]
        [Explicit] // slow: ~20s
        public void TestSignVerifySP800208_Shake256_256()
        {
            CheckSignVerifySP800208(0x00000010, 32);
        }

        [Test]
        [Explicit] // slow: ~15s
        public void TestSignVerifySP800208_Shake256_192()
        {
            CheckSignVerifySP800208(0x00000013, 24);
        }

        private static void CheckSignVerifySP800208(int oid, int n)
        {
            XmssParameters parameters = XmssParameters.LookupByOid(oid);
            Assert.IsNotNull(parameters);
            Assert.AreEqual(n, parameters.TreeDigestSize);
            Assert.AreEqual(10, parameters.Height);

            Xmss xmss = new Xmss(parameters, new SecureRandom());
            xmss.GenerateKeys();

            byte[] msg = SecureRandom.GetNextBytes(new SecureRandom(), 1024);

            byte[] publicKey = xmss.ExportPublicKey().GetEncoded();
            byte[] signature = xmss.Sign(msg);

            Assert.IsTrue(xmss.VerifySignature(msg, signature, publicKey));

            msg[0] ^= 0xff;
            Assert.IsFalse(xmss.VerifySignature(msg, signature, publicKey));
        }

        [Test]
        [Explicit] // slow: ~19s
        public void TestKeyImportSP800208_Sha256_192()
        {
            CheckKeyImportSP800208(0x0000000d);
        }

        [Test]
        [Explicit] // slow: ~20s
        public void TestKeyImportSP800208_Shake256_256()
        {
            CheckKeyImportSP800208(0x00000010);
        }

        [Test]
        [Explicit] // slow: ~15s
        public void TestKeyImportSP800208_Shake256_192()
        {
            CheckKeyImportSP800208(0x00000013);
        }

        private static void CheckKeyImportSP800208(int oid)
        {
            XmssParameters parameters = XmssParameters.LookupByOid(oid);
            Xmss xmss = new Xmss(parameters, new SecureRandom());
            xmss.GenerateKeys();

            byte[] exportedPrivateKey = xmss.ExportPrivateKey().GetEncoded();
            byte[] exportedPublicKey = xmss.ExportPublicKey().GetEncoded();

            byte[] msg = new byte[1024];
            byte[] sig1 = xmss.Sign(msg);

            xmss.ImportState(exportedPrivateKey, exportedPublicKey);
            byte[] sig2 = xmss.Sign(msg);

            Assert.IsTrue(Arrays.AreEqual(sig1, sig2));
        }

        /// <summary>
        /// A signer re-initialised for signing no longer verifies against the public key of an earlier verification
        /// init; a verification init leaves the private key in place, so sign, verify, then collect the advanced
        /// state still works; and a signer that was never initialised says so for both directions.
        /// </summary>
        [Test]
        public void TestReInitClearsThePublicKey()
        {
            XmssKeyPairGenerator kpGen = new XmssKeyPairGenerator();

            kpGen.Init(new XmssKeyGenerationParameters(new SecureRandom(), new XmssParameters(4, new Sha256Digest())));

            AsymmetricCipherKeyPair kp = kpGen.GenerateKeyPair();

            byte[] msg = Hex.Decode("54686520706f77657273206e6f742064656c65676174656420746f2074686520");

            XmssSigner signer = new XmssSigner();

            signer.Init(false, kp.Public);
            signer.Init(true, kp.Private);

            byte[] sig = XmssHarnessTests.Sign(signer, msg);

            // the public key from the first init must not still be here
            InvalidOperationException e = Assert.Throws<InvalidOperationException>(
                () => XmssHarnessTests.Verify(signer, msg, sig));
            Assert.AreEqual("signer not initialized for verification", e.Message);

            // and the state contract still holds across a verification init
            signer.Init(false, kp.Public);

            Assert.IsTrue(XmssHarnessTests.Verify(signer, msg, sig));

            signer.Init(true, kp.Private);
            XmssHarnessTests.Sign(signer, msg);
            signer.Init(false, kp.Public);

            Assert.IsNotNull(signer.GetUpdatedPrivateKey());

            // the signing direction was already guarded; assert it stays that way
            signer.Init(false, kp.Public);

            e = Assert.Throws<InvalidOperationException>(() => XmssHarnessTests.Sign(signer, msg));
            Assert.AreEqual("signer not initialized for signature generation", e.Message);

            // a signer that was never initialised at all reports that rather than returning false
            XmssSigner fresh = new XmssSigner();

            e = Assert.Throws<InvalidOperationException>(() => XmssHarnessTests.Verify(fresh, msg, sig));
            Assert.AreEqual("signer not initialized for verification", e.Message);

            e = Assert.Throws<InvalidOperationException>(() => XmssHarnessTests.Sign(fresh, msg));
            Assert.AreEqual("signer not initialized for signature generation", e.Message);
        }
    }
}
