using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.Test;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>Test cases for XmssPrivateKeyParameters class.</summary>
    /// <remarks>
    /// The methods after <see cref="TestRootCorruptionRejected"/> cover what this key and the engine under it do
    /// without a signer: Java vectors for generation, encoding, signing, sharding and recovery, and the refusals that
    /// keep a one-time key from being used twice.
    /// </remarks>
    [TestFixture]
    public class XmssPrivateKeyTests
    {
        private static readonly byte[] Message = new byte[]{ 1, 2, 3, 4 };

        [Test]
        public void TestPrivateKeyParsing()
        {
            ParsingTest(new Sha256Digest());
            ParsingTest(new Sha512Digest());
            ParsingTest(new ShakeDigest(128));
            ParsingTest(new ShakeDigest(256));
        }

        private static void ParsingTest(IDigest digest)
        {
            //
            // A generated key rather than one assembled from placeholder fields: the private key carries the tree
            // root twice - its own field and the root of its BDS state - and decode requires the two to agree
            // (github #2414), which a placeholder root does not.
            //
            XmssParameters parameters = new XmssParameters(4, digest);
            XmssPrivateKeyParameters privateKey = GenerateKey(parameters);

            byte[] export = privateKey.GetEncoded();

            XmssPrivateKeyParameters privateKey2 = new XmssPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(export).Build();

            Assert.AreEqual(privateKey.Index, privateKey2.Index);
            Assert.IsTrue(Arrays.AreEqual(privateKey.GetSecretKeySeed(), privateKey2.GetSecretKeySeed()));
            Assert.IsTrue(Arrays.AreEqual(privateKey.GetSecretKeyPrf(), privateKey2.GetSecretKeyPrf()));
            Assert.IsTrue(Arrays.AreEqual(privateKey.GetPublicSeed(), privateKey2.GetPublicSeed()));
            Assert.IsTrue(Arrays.AreEqual(privateKey.GetRoot(), privateKey2.GetRoot()));
        }

        /// <summary>
        /// A stored private key carries the tree root twice - its own field and the root of the BDS state beside it -
        /// and decode requires them to agree. Without the check a corrupted root was accepted and then poisoned every
        /// signature the key made: the root is hashed into the message digest, so the signature did not verify, with
        /// nothing to say why (github #2414).
        /// </summary>
        [Test]
        public void TestRootCorruptionRejected()
        {
            int n = 32;
            XmssParameters parameters = new XmssParameters(10, new Sha256Digest());
            AsymmetricCipherKeyPair kp = Generate(parameters, new SecureRandom());

            XmssSigner signer = new XmssSigner();
            signer.Init(true, kp.Private);
            for (int i = 0; i != 3; i++)
            {
                XmssHarnessTests.Sign(signer, Strings.ToByteArray("message"));
            }
            XmssPrivateKeyParameters advanced = (XmssPrivateKeyParameters)signer.GetUpdatedPrivateKey();
            byte[] enc = advanced.GetEncoded();

            // index(4) | secretKeySeed(n) | secretKeyPRF(n) | publicSeed(n) | root(n) | BDS state
            int rootOff = 4 + 3 * n;
            Assert.IsTrue(Arrays.AreEqual(advanced.GetRoot(), Arrays.CopyOfRange(enc, rootOff, rootOff + n)));

            for (int b = 0; b != n; b++)
            {
                byte[] corrupt = Arrays.Clone(enc);
                corrupt[rootOff + b] ^= 0x01;
                ArgumentException e = Assert.Throws<ArgumentException>(
                    () => new XmssPrivateKeyParameters.Builder(parameters).WithPrivateKey(corrupt).Build(),
                    "no exception on corrupt root byte " + b);
                Assert.AreEqual("BDS state root does not match the private key root", e.Message);
                Assert.IsInstanceOf<InvalidOperationException>(e.InnerException);
            }

            // the untouched encoding still decodes and still signs verifiably
            XmssPrivateKeyParameters decoded = new XmssPrivateKeyParameters.Builder(parameters).WithPrivateKey(enc)
                .Build();
            XmssSigner s2 = new XmssSigner();
            s2.Init(true, decoded);
            byte[] sig = XmssHarnessTests.Sign(s2, Strings.ToByteArray("message"));
            XmssSigner v = new XmssSigner();
            v.Init(false, kp.Public);
            Assert.IsTrue(XmssHarnessTests.Verify(v, Strings.ToByteArray("message"), sig));
        }

        /*
         * Java vectors: bc-java e40316b, XMSSEngine.generateKeyPair over a SecureRandom handing out 0, 1, 2, ... in
         * turn, then generateSignature(key, {1, 2, 3, 4}), extractKeyShard(3), generateSignature again, and a key
         * recovered through the builder at index 5 from the same seeds. Every encoding is compared in full; the
         * SHA-256 signatures are longer than 4096 hex characters and are loaded from
         * crypto/test/data/xmss/XmssPrivateKeyTests.JavaVectors_Sha256_H4.*.hex.
         */

        [Test]
        public void JavaVectors_Sha256_H4()
        {
            CheckJavaVectors(new XmssParameters(4, NistObjectIdentifiers.IdSha256),
                "79f9d5e9bba4628aee015408559590ebdfb79a142980203cc0a30610054177de"
                    + "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
                Sha256H4Priv0, XmssTestData.LoadHex("XmssPrivateKeyTests.JavaVectors_Sha256_H4.Sig0.hex"),
                Sha256H4Priv1, Sha256H4Shard, Sha256H4Priv4,
                XmssTestData.LoadHex("XmssPrivateKeyTests.JavaVectors_Sha256_H4.Sig4.hex"), Sha256H4Rec5);
        }

        [Test]
        public void JavaVectors_Shake256_192_H4()
        {
            CheckJavaVectors(new XmssParameters(4, NistObjectIdentifiers.IdShake256Len, 24),
                "9520432a788830c7d61afac45b35ddad0d1c57e2a63b283f303132333435363738393a3b3c3d3e3f4041424344454647",
                Shake256_192H4Priv0, Hex.Decode(Shake256_192H4Sig0), Shake256_192H4Priv1, Shake256_192H4Shard,
                Shake256_192H4Priv4, Hex.Decode(Shake256_192H4Sig4), Shake256_192H4Rec5);
        }

        /// <summary>A registered parameter set carries its four byte identifier in front of the public key.</summary>
        [Test]
        public void JavaVectors_XmssSha2_10_256_PublicKey()
        {
            XmssParameters parameters = XmssParameters.LookupByOid(1);
            AsymmetricCipherKeyPair kp = Generate(parameters, CountingRandom(parameters));

            Assert.AreEqual("0000000185055d10d75c7d9f50d5d90dd43827a90fbcf397b76d3877ba85bfbde1ba9cc4"
                + "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
                Hex.ToHexString(((XmssPublicKeyParameters)kp.Public).GetEncoded()));
        }

        private static void CheckJavaVectors(XmssParameters parameters, string pub, string priv0, byte[] sig0,
            string priv1, string shard, string priv4, byte[] sig4, string rec5)
        {
            AsymmetricCipherKeyPair kp = Generate(parameters, CountingRandom(parameters));
            XmssPrivateKeyParameters priv = (XmssPrivateKeyParameters)kp.Private;
            XmssPublicKeyParameters pubKey = (XmssPublicKeyParameters)kp.Public;

            Assert.AreEqual(pub, Hex.ToHexString(pubKey.GetEncoded()), "pub");
            Assert.AreEqual(priv0, Hex.ToHexString(priv.GetEncoded()), "priv0");

            byte[] signature0 = XmssEngine.GenerateSignature(priv, Message);
            Assert.AreEqual(sig0, signature0, "sig0");
            Assert.AreEqual(priv1, Hex.ToHexString(priv.GetEncoded()), "priv1");
            Assert.IsTrue(XmssEngine.VerifySignature(pubKey, Message, signature0));

            XmssPrivateKeyParameters shardKey = priv.ExtractKeyShard(3);
            Assert.AreEqual(shard, Hex.ToHexString(shardKey.GetEncoded()), "shard");
            Assert.AreEqual(priv4, Hex.ToHexString(priv.GetEncoded()), "priv4");

            byte[] signature4 = XmssEngine.GenerateSignature(priv, Message);
            Assert.AreEqual(sig4, signature4, "sig4");
            Assert.IsTrue(XmssEngine.VerifySignature(pubKey, Message, signature4));

            XmssPrivateKeyParameters recovered = new XmssPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(priv.GetSecretKeySeed()).WithSecretKeyPrf(priv.GetSecretKeyPrf())
                .WithPublicSeed(priv.GetPublicSeed()).WithRoot(priv.GetRoot()).WithIndex(5).Build();
            Assert.AreEqual(rec5, Hex.ToHexString(recovered.GetEncoded()), "rec5");
            Assert.AreEqual(priv, recovered);

            // and the Java encodings read back to keys that encode the same
            foreach (string encoding in new string[]{ priv0, priv1, shard, priv4, rec5 })
            {
                XmssPrivateKeyParameters decoded = new XmssPrivateKeyParameters.Builder(parameters)
                    .WithPrivateKey(Hex.Decode(encoding)).Build();
                Assert.AreEqual(encoding, Hex.ToHexString(decoded.GetEncoded()));
            }
        }

        /// <summary>
        /// The state codec reports a bad encoding as an <see cref="IOException"/>; the key builder reports it as an
        /// <see cref="ArgumentException"/> with the same message, as Java wraps it in IllegalArgumentException.
        /// </summary>
        [Test]
        public void CorruptStateReportedAsArgumentException()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            int n = parameters.TreeDigestSize;
            byte[] enc = GenerateKey(parameters).GetEncoded();
            int stateOff = 4 + 4 * n;

            byte[] corrupt = Arrays.Clone(enc);
            corrupt[stateOff + 12] ^= 0x01;
            ArgumentException e = Assert.Throws<ArgumentException>(
                () => new XmssPrivateKeyParameters.Builder(parameters).WithPrivateKey(corrupt).Build());
            Assert.AreEqual("BDS state checksum does not match", e.Message);
            Assert.IsInstanceOf<IOException>(e.InnerException);

            // no state at all, and a head cut short
            e = Assert.Throws<ArgumentException>(() => new XmssPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(Arrays.CopyOfRange(enc, 0, stateOff)).Build());
            Assert.IsInstanceOf<IOException>(e.InnerException);
            for (int length = 0; length < stateOff; length += 7)
            {
                e = Assert.Throws<ArgumentException>(() => new XmssPrivateKeyParameters.Builder(parameters)
                    .WithPrivateKey(Arrays.CopyOfRange(enc, 0, length)).Build());
                Assert.AreEqual("private key has wrong size", e.Message);
            }

            // every truncation of the state is refused through the same exception type
            for (int length = stateOff; length < enc.Length; length++)
            {
                Assert.Throws<ArgumentException>(() => new XmssPrivateKeyParameters.Builder(parameters)
                    .WithPrivateKey(Arrays.CopyOfRange(enc, 0, length)).Build(), "length " + length);
            }
        }

        /// <summary>
        /// The stored index is bounded by 2^h before the state is read, and has to agree with the state after.
        /// </summary>
        [Test]
        public void StoredIndexChecked()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            byte[] enc = GenerateKey(parameters).GetEncoded();

            foreach (uint index in new uint[]{ 17, 0x7fffffff, 0x80000000, 0xffffffff })
            {
                byte[] corrupt = Arrays.Clone(enc);
                Org.BouncyCastle.Crypto.Utilities.Pack.UInt32_To_BE(index, corrupt, 0);
                ArgumentException e = Assert.Throws<ArgumentException>(
                    () => new XmssPrivateKeyParameters.Builder(parameters).WithPrivateKey(corrupt).Build());
                Assert.AreEqual("index out of bounds", e.Message, "index " + index);
            }

            foreach (uint index in new uint[]{ 1, 16 })
            {
                byte[] corrupt = Arrays.Clone(enc);
                Org.BouncyCastle.Crypto.Utilities.Pack.UInt32_To_BE(index, corrupt, 0);
                ArgumentException e = Assert.Throws<ArgumentException>(
                    () => new XmssPrivateKeyParameters.Builder(parameters).WithPrivateKey(corrupt).Build());
                Assert.AreEqual("BDS state has wrong index", e.Message, "index " + index);
            }
        }

        /// <summary>
        /// The used mark survives the encoding: a key rebuilt around a state that has already signed, written out and
        /// read back, is still refused at that index. (The builder path is OneTimeKeyReuseTests'
        /// testSigningIsRefusedOnAStateThatHasAlreadySigned.)
        /// </summary>
        [Test]
        public void SpentStateRefusedThroughTheEncoding()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            XmssPrivateKeyParameters priv = GenerateKey(parameters);
            Bds captured = priv.GetBdsState();

            XmssEngine.GenerateSignature(priv, Message);
            Assert.IsTrue(captured.IsUsed, "the state the signature spent is marked");

            XmssPrivateKeyParameters replay = new XmssPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(priv.GetSecretKeySeed()).WithSecretKeyPrf(priv.GetSecretKeyPrf())
                .WithPublicSeed(priv.GetPublicSeed()).WithRoot(priv.GetRoot()).WithBdsState(captured).Build();
            XmssPrivateKeyParameters restored = new XmssPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(replay.GetEncoded()).Build();
            Assert.AreEqual(0, restored.Index);

            XmssSigner signer = new XmssSigner();
            signer.Init(true, restored);
            InvalidOperationException e = Assert.Throws<InvalidOperationException>(
                () => XmssHarnessTests.Sign(signer, Message));
            Assert.AreEqual("one time key at index 0 has already signed", e.Message);
            Assert.AreEqual(0, restored.Index, "a refused signature advanced the index");
        }

        /// <summary>
        /// A key decoded from an encoding whose state carries no authentication path cannot sign, and says so
        /// rather than failing inside the traversal, before the index is advanced.
        /// </summary>
        [Test]
        public void KeyWithoutTraversalStateIsRefused()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            XmssPrivateKeyParameters priv = GenerateKey(parameters);

            // a state with no root and no authentication path, at index 0 of the full tree
            Bds empty = new Bds(parameters, 15, 0);
            Assert.IsTrue(empty.IsAuthenticationPathEmpty);
            XmssPrivateKeyParameters key = new XmssPrivateKeyParameters.Builder(parameters)
                .WithSecretKeySeed(priv.GetSecretKeySeed()).WithSecretKeyPrf(priv.GetSecretKeyPrf())
                .WithPublicSeed(priv.GetPublicSeed()).WithRoot(priv.GetRoot()).WithBdsState(empty).Build();

            Assert.IsFalse(XmssEngine.HasTraversalState(key));
            Assert.AreEqual(16, key.GetUsagesRemaining());

            XmssPrivateKeyParameters restored = new XmssPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(key.GetEncoded()).Build();
            Assert.IsFalse(XmssEngine.HasTraversalState(restored));

            foreach (XmssPrivateKeyParameters k in new XmssPrivateKeyParameters[]{ key, restored })
            {
                InvalidOperationException e = Assert.Throws<InvalidOperationException>(
                    () => XmssEngine.GenerateSignature(k, Message));
                Assert.AreEqual("not initialized", e.Message);
                Assert.AreEqual(0, k.Index);
            }
        }

        /// <summary>
        /// A shard covers [index, index + usageCount) and the key it came from goes on at index + usageCount, so
        /// the two never sign at one index; asking for none, or for more than is left, is refused.
        /// </summary>
        [Test]
        public void ShardsDoNotOverlap()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            AsymmetricCipherKeyPair kp = Generate(parameters, new SecureRandom());
            XmssPrivateKeyParameters priv = (XmssPrivateKeyParameters)kp.Private;
            XmssPublicKeyParameters pub = (XmssPublicKeyParameters)kp.Public;

            XmssPrivateKeyParameters shard = priv.ExtractKeyShard(3);
            Assert.AreEqual(0, shard.Index);
            Assert.AreEqual(3, shard.GetUsagesRemaining());
            Assert.AreEqual(3, priv.Index);
            Assert.AreEqual(13, priv.GetUsagesRemaining());

            for (int i = 0; i != 3; i++)
            {
                byte[] sig = XmssEngine.GenerateSignature(shard, Message);
                Assert.AreEqual(i, (int)Org.BouncyCastle.Crypto.Utilities.Pack.BE_To_UInt32(sig, 0));
                Assert.IsTrue(XmssEngine.VerifySignature(pub, Message, sig));
            }
            Assert.AreEqual(0, shard.GetUsagesRemaining());
            ExhaustedPrivateKeyException ex = Assert.Throws<ExhaustedPrivateKeyException>(
                () => XmssEngine.GenerateSignature(shard, Message));
            Assert.AreEqual("no usages of private key remaining", ex.Message);

            byte[] next = XmssEngine.GenerateSignature(priv, Message);
            Assert.AreEqual(3, (int)Org.BouncyCastle.Crypto.Utilities.Pack.BE_To_UInt32(next, 0));
            Assert.IsTrue(XmssEngine.VerifySignature(pub, Message, next));

            ArgumentException e = Assert.Throws<ArgumentException>(() => priv.ExtractKeyShard(0));
            Assert.AreEqual("cannot ask for a shard with 0 keys", e.Message);
            e = Assert.Throws<ArgumentException>(() => priv.ExtractKeyShard(13));
            Assert.AreEqual("usageCount exceeds usages remaining", e.Message);
            Assert.AreEqual(4, priv.Index, "a refused shard moved the key");

            // the whole of what is left: the key is spent and the shard carries it all
            XmssPrivateKeyParameters rest = priv.ExtractKeyShard(12);
            Assert.AreEqual(4, rest.Index);
            Assert.AreEqual(12, rest.GetUsagesRemaining());
            Assert.AreEqual(0, priv.GetUsagesRemaining());
            Assert.AreEqual(16, priv.Index);
            Assert.Throws<ExhaustedPrivateKeyException>(() => XmssEngine.GenerateSignature(priv, Message));

            // and the spent key survives being stored
            XmssPrivateKeyParameters stored = new XmssPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(priv.GetEncoded()).Build();
            Assert.AreEqual(16, stored.Index);
            Assert.AreEqual(0, stored.GetUsagesRemaining());
        }

        /// <summary>A shard's limit survives the encoding: a stored shard does not widen to the whole tree.</summary>
        [Test]
        public void ShardLimitSurvivesEncoding()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            XmssPrivateKeyParameters priv = GenerateKey(parameters);
            XmssPrivateKeyParameters shard = priv.GetNextKey();

            XmssPrivateKeyParameters stored = new XmssPrivateKeyParameters.Builder(parameters)
                .WithPrivateKey(shard.GetEncoded()).Build();
            Assert.AreEqual(0, stored.Index);
            Assert.AreEqual(1, stored.GetUsagesRemaining());
            Assert.AreEqual(0, stored.GetBdsState().MaxIndex);
        }

        /// <summary>
        /// A signature whose index is outside the tree - read as a signed int, a negative one - does not decode, and
        /// verification answers false for it rather than raising.
        /// </summary>
        [Test]
        public void VerifyRejectsAnIndexOutsideTheTree()
        {
            XmssParameters parameters = new XmssParameters(4, new Sha256Digest());
            AsymmetricCipherKeyPair kp = Generate(parameters, new SecureRandom());
            XmssPublicKeyParameters pub = (XmssPublicKeyParameters)kp.Public;
            byte[] sig = XmssEngine.GenerateSignature((XmssPrivateKeyParameters)kp.Private, Message);

            Assert.IsTrue(XmssEngine.VerifySignature(pub, Message, sig));

            byte[] badIndex = Arrays.Clone(sig);
            badIndex[0] = 0x80;
            Assert.IsFalse(XmssEngine.VerifySignature(pub, Message, badIndex));

            badIndex = Arrays.Clone(sig);
            badIndex[3] = 16;
            Assert.IsFalse(XmssEngine.VerifySignature(pub, Message, badIndex));
        }

        // Sha256H4
        private const string Sha256H4Priv0 =
            "00000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
                + "2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b"
                + "5c5d5e5f79f9d5e9bba4628aee015408559590ebdfb79a142980203cc0a30610054177de424453000000000100000004"
                + "000000020000000f000000000001000000040000002079f9d5e9bba4628aee015408559590ebdfb79a142980203cc0a3"
                + "0610054177de0000000400000000000000202caf15d3d48449094727d18cabe762d012b82643b52ddbeed788b06e37bb"
                + "91630000000100000020e27018bee1e998af861210b1037bfd8ac9b74df3f14a76d40721e9059be195f5000000020000"
                + "0020d1f3876cc98c46c49285a77fc111c928b340d7d2d1c82df125dd902c902669e8000000030000002068538e5a1e95"
                + "8ac7475ad526a9a311260e805687429be218579e94bbe7c0bfcf00000001000000020000000100000002000000209798"
                + "8034c44f4964156ce4fc7ddb604978835d40bf019ee0097f961323d5254d000000000000000200000000000000000000"
                + "000000010100000000000000201c004781827c563cab8ad5b6ac41dcd569d3c0a6115417692b8fd580680ab218000000"
                + "01000000010000000000010100000001000000206cb8aa9165f5205de7535ddd09a1b84e8d57d78c837e3d3589956d87"
                + "c8efa4e400000000a52d0b6dfb3ecacce11e73071f956671699da844e9c9aa2ebd2cdd88aa1d608e";

        private const string Sha256H4Priv1 =
            "00000001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
                + "2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b"
                + "5c5d5e5f79f9d5e9bba4628aee015408559590ebdfb79a142980203cc0a30610054177de424453000000000100000004"
                + "000000020000000f000000010001000000040000002079f9d5e9bba4628aee015408559590ebdfb79a142980203cc0a3"
                + "0610054177de0000000400000000000000200c9f44bad769c5866af8d63b5f84adaa6a404aacddef42ebc96f7e9f7460"
                + "b07f0000000100000020e27018bee1e998af861210b1037bfd8ac9b74df3f14a76d40721e9059be195f5000000020000"
                + "0020d1f3876cc98c46c49285a77fc111c928b340d7d2d1c82df125dd902c902669e8000000030000002068538e5a1e95"
                + "8ac7475ad526a9a311260e805687429be218579e94bbe7c0bfcf00000001000000020000000100000002000000209798"
                + "8034c44f4964156ce4fc7ddb604978835d40bf019ee0097f961323d5254d000000000000000200000000000000000000"
                + "000000010100000000000000201c004781827c563cab8ad5b6ac41dcd569d3c0a6115417692b8fd580680ab218000000"
                + "01000000010000000000010100000001000000206cb8aa9165f5205de7535ddd09a1b84e8d57d78c837e3d3589956d87"
                + "c8efa4e4000000010000000000000000000000202caf15d3d48449094727d18cabe762d012b82643b52ddbeed788b06e"
                + "37bb916392a066e6e83f80a4daf4359edbd794722d5b93d02ac5e304e4577e0476ed3d9e";

        private const string Sha256H4Shard =
            "00000001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
                + "2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b"
                + "5c5d5e5f79f9d5e9bba4628aee015408559590ebdfb79a142980203cc0a30610054177de424453000000000100000004"
                + "0000000200000003000000010001000000040000002079f9d5e9bba4628aee015408559590ebdfb79a142980203cc0a3"
                + "0610054177de0000000400000000000000200c9f44bad769c5866af8d63b5f84adaa6a404aacddef42ebc96f7e9f7460"
                + "b07f0000000100000020e27018bee1e998af861210b1037bfd8ac9b74df3f14a76d40721e9059be195f5000000020000"
                + "0020d1f3876cc98c46c49285a77fc111c928b340d7d2d1c82df125dd902c902669e8000000030000002068538e5a1e95"
                + "8ac7475ad526a9a311260e805687429be218579e94bbe7c0bfcf00000001000000020000000100000002000000209798"
                + "8034c44f4964156ce4fc7ddb604978835d40bf019ee0097f961323d5254d000000000000000200000000000000000000"
                + "000000010100000000000000201c004781827c563cab8ad5b6ac41dcd569d3c0a6115417692b8fd580680ab218000000"
                + "01000000010000000000010100000001000000206cb8aa9165f5205de7535ddd09a1b84e8d57d78c837e3d3589956d87"
                + "c8efa4e4000000010000000000000000000000202caf15d3d48449094727d18cabe762d012b82643b52ddbeed788b06e"
                + "37bb91639af2b6bd12be572d39bbc6497692d4da98edde9760448038ab735e97f9e1264a";

        private const string Sha256H4Priv4 =
            "00000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
                + "2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b"
                + "5c5d5e5f79f9d5e9bba4628aee015408559590ebdfb79a142980203cc0a30610054177de424453000000000100000004"
                + "000000020000000f000000040001000000040000002079f9d5e9bba4628aee015408559590ebdfb79a142980203cc0a3"
                + "0610054177de000000040000000000000020918e2cc1ff7b84ad19cdfb9a0c64598f54705c24e34d837410c0d078c28d"
                + "b5ba00000001000000206cb8aa9165f5205de7535ddd09a1b84e8d57d78c837e3d3589956d87c8efa4e4000000020000"
                + "0020459a423afd247679ab8102df23c4e781f3a8df70a3d54403bffbed62bce8d373000000030000002068538e5a1e95"
                + "8ac7475ad526a9a311260e805687429be218579e94bbe7c0bfcf00000001000000020000000100000002000000209798"
                + "8034c44f4964156ce4fc7ddb604978835d40bf019ee0097f961323d5254d000000000000000200000000000000000000"
                + "0007010101000000000000002037bb88e11581df5ff649ee5d7491f9769782800ea3f2f983c7d73bad0ee2d2d4000000"
                + "01000000010000000a01000000000001000000020000000200000020d1f3876cc98c46c49285a77fc111c928b340d7d2"
                + "d1c82df125dd902c902669e8b091005d5579250cde707ec3e84a2f830fd2e7e2238ad1f0e0c92c5a4c59f47c";

        private const string Sha256H4Rec5 =
            "00000005000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
                + "2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b"
                + "5c5d5e5f79f9d5e9bba4628aee015408559590ebdfb79a142980203cc0a30610054177de424453000000000100000004"
                + "000000020000000f000000050001000000040000002079f9d5e9bba4628aee015408559590ebdfb79a142980203cc0a3"
                + "0610054177de000000040000000000000020b3495c6e53ac466f4176d51d4ba4c5a8102d6138a24272af23c7a2bba83d"
                + "c95700000001000000206cb8aa9165f5205de7535ddd09a1b84e8d57d78c837e3d3589956d87c8efa4e4000000020000"
                + "0020459a423afd247679ab8102df23c4e781f3a8df70a3d54403bffbed62bce8d373000000030000002068538e5a1e95"
                + "8ac7475ad526a9a311260e805687429be218579e94bbe7c0bfcf00000001000000020000000100000002000000209798"
                + "8034c44f4964156ce4fc7ddb604978835d40bf019ee0097f961323d5254d000000000000000200000000000000000000"
                + "0007010101000000000000002037bb88e11581df5ff649ee5d7491f9769782800ea3f2f983c7d73bad0ee2d2d4000000"
                + "01000000000000000b0100010000000000000020aa66295ea5e17ff7aadede4df773596638caa2177a8705e4855a5096"
                + "d54a369d00000002000000000000000000000020918e2cc1ff7b84ad19cdfb9a0c64598f54705c24e34d837410c0d078"
                + "c28db5ba000000020000000200000020d1f3876cc98c46c49285a77fc111c928b340d7d2d1c82df125dd902c902669e8"
                + "b264d50fa991d34b31a2b09c657f6dda27fcba9f2c3444ecaecbcb19971d26ae";

        // Shake256_192H4
        private const string Shake256_192H4Priv0 =
            "00000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
                + "2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546479520432a788830c7d61afac45b35ddad0d1c57e2"
                + "a63b283f424453000000000100000004000000020000000f00000000000100000004000000189520432a788830c7d61a"
                + "fac45b35ddad0d1c57e2a63b283f0000000400000000000000183918c77f115da5d9233c0de77324ad7d6898f7f5f71f"
                + "ba560000000100000018f9ddbfd73505b8e36377addb60c3da5ab885e5a164d8431800000002000000188c821eb39580"
                + "ab4bbc40e46d158270f430b26aa7f413926700000003000000185c7e07409037eb844d33cd4bfd62f9d4976f21118d5a"
                + "ef840000000100000002000000010000000200000018fef30c56847d3a074467504719758057763e133c6d8067b10000"
                + "0000000000020000000000000000000000000001010000000000000018ad4442f7ad8b679ddafe50bd985ec06d3531dc"
                + "dbe5eb38bb0000000100000001000000000001010000000100000018cff6571208bbe93d1c924b801f3386871ca2a718"
                + "855a172b00000000224a4ba1c2d8f790b0270c2307435cedbd5f06f9b4ba7f8c0192bb4c3e338c57";

        private const string Shake256_192H4Priv1 =
            "00000001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
                + "2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546479520432a788830c7d61afac45b35ddad0d1c57e2"
                + "a63b283f424453000000000100000004000000020000000f00000001000100000004000000189520432a788830c7d61a"
                + "fac45b35ddad0d1c57e2a63b283f0000000400000000000000181ef069c12d0b56f113af21b90c40fdd6bab1b7cf89a8"
                + "eef00000000100000018f9ddbfd73505b8e36377addb60c3da5ab885e5a164d8431800000002000000188c821eb39580"
                + "ab4bbc40e46d158270f430b26aa7f413926700000003000000185c7e07409037eb844d33cd4bfd62f9d4976f21118d5a"
                + "ef840000000100000002000000010000000200000018fef30c56847d3a074467504719758057763e133c6d8067b10000"
                + "0000000000020000000000000000000000000001010000000000000018ad4442f7ad8b679ddafe50bd985ec06d3531dc"
                + "dbe5eb38bb0000000100000001000000000001010000000100000018cff6571208bbe93d1c924b801f3386871ca2a718"
                + "855a172b000000010000000000000000000000183918c77f115da5d9233c0de77324ad7d6898f7f5f71fba56d2a170f7"
                + "d2c4505811b76687ee9add9bbde80d1fa203b38dd147c4a1932d2c2a";

        private const string Shake256_192H4Shard =
            "00000001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
                + "2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546479520432a788830c7d61afac45b35ddad0d1c57e2"
                + "a63b283f424453000000000100000004000000020000000300000001000100000004000000189520432a788830c7d61a"
                + "fac45b35ddad0d1c57e2a63b283f0000000400000000000000181ef069c12d0b56f113af21b90c40fdd6bab1b7cf89a8"
                + "eef00000000100000018f9ddbfd73505b8e36377addb60c3da5ab885e5a164d8431800000002000000188c821eb39580"
                + "ab4bbc40e46d158270f430b26aa7f413926700000003000000185c7e07409037eb844d33cd4bfd62f9d4976f21118d5a"
                + "ef840000000100000002000000010000000200000018fef30c56847d3a074467504719758057763e133c6d8067b10000"
                + "0000000000020000000000000000000000000001010000000000000018ad4442f7ad8b679ddafe50bd985ec06d3531dc"
                + "dbe5eb38bb0000000100000001000000000001010000000100000018cff6571208bbe93d1c924b801f3386871ca2a718"
                + "855a172b000000010000000000000000000000183918c77f115da5d9233c0de77324ad7d6898f7f5f71fba56cc6f3f47"
                + "8e27ea5cd5ad131bc9375ffd74f838f524c43a21b28f2b65f67c1645";

        private const string Shake256_192H4Priv4 =
            "00000004000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
                + "2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546479520432a788830c7d61afac45b35ddad0d1c57e2"
                + "a63b283f424453000000000100000004000000020000000f00000004000100000004000000189520432a788830c7d61a"
                + "fac45b35ddad0d1c57e2a63b283f0000000400000000000000185689b488eec5f1eeff90c115d186ad9334069873ba2f"
                + "8d130000000100000018cff6571208bbe93d1c924b801f3386871ca2a718855a172b00000002000000186a11c6b653e0"
                + "68d6198a7d3d164ddd848e2f4bcf9105654e00000003000000185c7e07409037eb844d33cd4bfd62f9d4976f21118d5a"
                + "ef840000000100000002000000010000000200000018fef30c56847d3a074467504719758057763e133c6d8067b10000"
                + "0000000000020000000000000000000000070101010000000000000018b56ca7a58980220868640cae7cbae1170c6942"
                + "235966d3a200000001000000010000000a010000000000010000000200000002000000188c821eb39580ab4bbc40e46d"
                + "158270f430b26aa7f4139267c0149f4deaad15269fbbfdd3717d30173629920af786f9b20336a01a91ae2303";

        private const string Shake256_192H4Rec5 =
            "00000005000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
                + "2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546479520432a788830c7d61afac45b35ddad0d1c57e2"
                + "a63b283f424453000000000100000004000000020000000f00000005000100000004000000189520432a788830c7d61a"
                + "fac45b35ddad0d1c57e2a63b283f0000000400000000000000187fa037edb4177b26b0abdfdfd11e30aea1686077087d"
                + "30240000000100000018cff6571208bbe93d1c924b801f3386871ca2a718855a172b00000002000000186a11c6b653e0"
                + "68d6198a7d3d164ddd848e2f4bcf9105654e00000003000000185c7e07409037eb844d33cd4bfd62f9d4976f21118d5a"
                + "ef840000000100000002000000010000000200000018fef30c56847d3a074467504719758057763e133c6d8067b10000"
                + "0000000000020000000000000000000000070101010000000000000018b56ca7a58980220868640cae7cbae1170c6942"
                + "235966d3a200000001000000000000000b01000100000000000000189203ff4786a60e2b02d9eb70689d4ee5fa70ee12"
                + "a8fcb7c2000000020000000000000000000000185689b488eec5f1eeff90c115d186ad9334069873ba2f8d1300000002"
                + "00000002000000188c821eb39580ab4bbc40e46d158270f430b26aa7f4139267e1ebe587c178497f4678db554e3fff2d"
                + "08c3b1cd019694c4e862d6c82f9b67ef";

        private const string Shake256_192H4Sig0 =
            "00000000a735b8162977f73307ba2084089750469c25ad20d9ee387e96b5defe9f9f942e9a7656c3e38c587fefa1105b"
                + "5a4c99059c8c9511974ae084a8d15b129b759ce947628c75fef902b3256bdf4083546f289a89cc8d101a3480142a3ea9"
                + "9322d24c6973d5eeed18bbb65980f409f9baf03950714c346a471e2129085354804c52aee29ed040b8eef7d897cb1637"
                + "992cb96c5984655500640b42a33d60bf06324b33154d5189d45370fcb22896822cbeee18096b4a3af1adb0ba76032c9a"
                + "a7fc6fb7786928d5c7493b59406827655997da7f3e21a9f55a86c7c77789c4c629c191ce90ce82c7a0b3bb7de02e6a9c"
                + "6e58c2d94c81d8c027928333da823a2584222cb9fe57ea6efdbb3b7c2bea3b0a36f0e474499ef6c64860a3d4c1523a8d"
                + "5255170c67d9a870cdc5ca48b419d0112bc45d778c94d01b572fd388e81cd469fb57cd798b87a9e9e14b4e0d98794c1e"
                + "6db694467fd0967dcf9af620c13b99178f4aed598937204d991f89af95d8e7a0ade98a4fc0c34d0cf7b94fae4cd73489"
                + "92b8ed47ab4001aeea15139c358d5d138339d1d7263db99aa08770a943bece90cb222755a1bbc0400da9cd2551eb91c7"
                + "d70aaabcde3f6ded0e01bb3c690afc787cfbc41d09e08fe4f64e3c945e352d31f166807c5a374127bc0d596740e0fcf9"
                + "98e48b39755056ac4a7e2be6cb0a8d7e79df8b2ed46c2f48832865a0e573810d84a5eade88ace5313ef295ce2dda2b28"
                + "89b8d972623c8c1cf9d6b5e38f0b32e52806ed7a239d20c9ba97578cc08c396db1d11bbab2e68c7455950fb9123d1a7b"
                + "ed25ed9cd46ad1bbf5cdbebfc348d8c01fc3dd58dda8cb6694daa7f8fa1a11ab2ef0351348e68f5b000002085917b447"
                + "82e250af5b0cc342363efc9461138b165cec45507915462bc7da703b16a77d76f97f400dea9d4996b13f0d1bae4edcb5"
                + "24a2cca2f809c3d3a9bd8bb56fd629fb0ee87ff9631eed0350472e393cfb1f4b79296452db4763f72d351e2738b56e4a"
                + "17098785e041a24a2a03ff777a59825abc4f9c45b4481d59473e5ea46c4fb3c26a796d1cdeff0573dcf65cf0d7dad574"
                + "58446a523d887c5e62d58666a5ea03004ccd49df763d5429566eb6dbe4cf39b354bfbdc61b0f07e208ee3dcf8936be24"
                + "6a58972f7fd67b9eadb096db42e475c5a15f7d2528d209e128e12ed4b0d5ec036a4cc0417faa4e7d0f04c8be4a1dab8d"
                + "2256fe87ecf26d83a71c546b65094473efa8997f428acaf074f00f05c8660e293ca6e4da177eb8d649ce2f8b00527def"
                + "d8ba947f301ba016dc1e9c0c3f3d52cdf4c9ad7e31d576fa0bce2fac32d2cda0e9ad1d28913caa26be2fabf507a76582"
                + "20b2b73c6364d1734c91fbc6ac30113a2a8e96187fcfb2d14617ff784997a676fa6356478546cc422e1a26e9b1f4d762"
                + "a419f5233cbe665201f7b0fb434b685836621d183f7fc862bef6b4dd1165abd40b8265a52d810f878c1f5314df1e4064"
                + "e02004e27ae5f9523ceb1fc558dab0af80dc67c38ec314b362e10275610ec23324090abd014cc0294bddae142c509fc9"
                + "f2336d97d2d6d2fc4845e1d6110be4de71250855a2e8169579dbc799931e1c2686b0c245e05a2fa5b0c34d224bd91a76"
                + "25bb9d6cca62262610e5736f62a4711755367e83695ff18727f6d5d30585bbdea7963510fb75f4203e425584abfad19b"
                + "ebad8fdefb87c5342dcbf483615234aa6f6d56cf523bbbe1249750829ac947d90032c4ca866556c5b611ccf5c94247ad"
                + "feef70833918c77f115da5d9233c0de77324ad7d6898f7f5f71fba56f9ddbfd73505b8e36377addb60c3da5ab885e5a1"
                + "64d843188c821eb39580ab4bbc40e46d158270f430b26aa7f41392675c7e07409037eb844d33cd4bfd62f9d4976f2111"
                + "8d5aef84";

        private const string Shake256_192H4Sig4 =
            "00000004def84fa358355e613c1d94946253948b83d2154af3b5f8c601bf8f737ac0a8463bc3e391d9eb0197c156d26d"
                + "51d2e5d4e1acda876c04c426d586687eafa40b03ab32907690bef048052bcade43607198636eb36186d895af9471d024"
                + "98cba5223befba5ab13740cbdfa9ecda2ccc8077a51db37dee41740376e3fc52aef2223b5d578fa1bde1c3d3f4f2c8ff"
                + "9725831d80ec6a6db6633abf6155feb931e4627e792c6b59a948e2a0f1623a84dc004d2f6e93643fa07ab2acbf844541"
                + "9d84014c0611e8edd0fd14c67c87701e65feda0838a3d81ba45e10ba6a89013e1db94d9a2853ee15489805bd328b32e4"
                + "75192c7b48b1f1015098785d6f479b169e0e1bb9afb13e83188f426f109c67f85c32d2033efb10253f527ff282a5ec6c"
                + "8cce5224bfd5ef21dc7d626dce131186c0a57f286f8d8ea551e93fb99d6ef6dcb5e6d81e5dc104fd05d083cbafb66f36"
                + "75f5e1ef589841e9ad407825443955b812b078ecf1950c97e892b6f31401a3f281dd5e0cadb4b3de8d54dd2f2b747780"
                + "142803fa70078b2cb304ca6a11f5c36a75b008c7aba498f8c121b3b343a6cd7898e699b57cc8862f9b90be49f408c54f"
                + "02d96b06ad562439f348fb323f5c2d7faedd630d6145f2130ec5b09bcea192c5b9911ddd1408257ac1aeea5ee466b6b6"
                + "66f2fcb13e38b5f2c18a4d01094090ea2dea83cb1d756909b04c59bced5dbffa3dd741b5c5e490e36464cc2cc2d07275"
                + "1dbd391bf5db45b362f6fdc3d29a598a0964ad64a0e727a42ceac9db4291f85f579c5e3048b9c4ca955325886874011a"
                + "7f27edd7bdb4feabf8e8c1cf444b0728dd942f37b655ec77b8e6ed75493e25fcb43f31c49e634d6cb8b889863e6381a9"
                + "2b2b1b2a004e6799c819e3a5a6ea64e28663351ffc11c938712a5f4e7ea4d58a7fae00a7705ebfd8d6e9011870421202"
                + "ced20f8883d0e246c2a1402341add70ff7d0218b262f66d6c2218bf5fe1614e8c45dfe1410450ea5abbefaf5ec4364bd"
                + "4341fa4cd59014b9ede581c4084fb446448c7b79e38b38af4daa5c87822b1a37b7c8fad40f1018adbb9e6e668b1f80ef"
                + "5e022a974edca5b8e63a878a975fd5592343535ccb94bcc9aafaaa2115133e846e80ebb07d714329edf369bbbf258a61"
                + "6cb30644e1f4fd85dfc54a5e76d2b7cc3dff4aeb7e1f26bdf7d07272b993b392cb0251a9418892818c5285d6f2c5d19a"
                + "5b3fba57e60976dd46fb117f754644129467f7d17f6bd2ff8144cb8e42360988831309bd47b9600b1e5fd3cd645f7d35"
                + "dec12b8f7e99b9b2aee03caaa2f89f98b2a4fab28ed843d725952740e1ff759767a77a92896c922d1de3c6993028ee21"
                + "a18835f611898d10f8ce132d74061a726407b932690cb27a4d65bafd56ae0ccd56f758db44a843bea54f20e718bf33f1"
                + "4a9557990a85d4a3152917bf9a0729d054045869e2b88198343b0650c5df94b6a343e469328cf99825d90b39e54f7be8"
                + "051ccad4cc9afe7223030da60efe91703f22f8f54faf1bbcb7430b7e8ebf53e750346b47389dec181380a56633c34fc9"
                + "f9514a419b8a34ada14d3e2d35595e9c80632eb3a743eac4d3b4056dff90db2f0e0526e5fb4596febfa536e8db3e2ea2"
                + "a59379f64f39ffb1603b7afa8ce7e4a465121f40c685e1c2bbc6d51fc73069fdb6121d89211054ce03b5a41b58607558"
                + "94100aecda8419b8c52f98d6fc06dd682650cb76fa4b4578bee59895c8b2e560652aa0264680e2986c3fd06b9785d670"
                + "90a05f085689b488eec5f1eeff90c115d186ad9334069873ba2f8d13cff6571208bbe93d1c924b801f3386871ca2a718"
                + "855a172b6a11c6b653e068d6198a7d3d164ddd848e2f4bcf9105654e5c7e07409037eb844d33cd4bfd62f9d4976f2111"
                + "8d5aef84";

        private static SecureRandom CountingRandom(XmssParameters parameters)
        {
            byte[] data = new byte[3 * parameters.TreeDigestSize];
            for (int i = 0; i != data.Length; i++)
            {
                data[i] = (byte)i;
            }
            return FixedSecureRandom.From(data);
        }

        private static AsymmetricCipherKeyPair Generate(XmssParameters parameters, SecureRandom random)
        {
            XmssKeyPairGenerator kpGen = new XmssKeyPairGenerator();
            kpGen.Init(new XmssKeyGenerationParameters(random, parameters));
            return kpGen.GenerateKeyPair();
        }

        private static XmssPrivateKeyParameters GenerateKey(XmssParameters parameters) =>
            (XmssPrivateKeyParameters)Generate(parameters, new SecureRandom()).Private;
    }
}
