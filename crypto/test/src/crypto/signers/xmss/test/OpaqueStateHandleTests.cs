using System;
using System.Reflection;

using NUnit.Framework;

namespace Org.BouncyCastle.Crypto.Signers.Xmss.Tests
{
    /// <summary>
    /// A traversal state is the second record a stateful key keeps of its signing position, so a public mutator on
    /// one is a way to advance that position behind the key's back. In bc-java the state types are public because a
    /// private key carries one as a field, and their public surface is pinned to a list of read-only methods. Here
    /// they are internal and the key's accessor for its state is internal too, so the assertion is the stronger
    /// one: there is no public surface at all.
    /// </summary>
    /// <remarks>testBDSStateMapExposesNoMutator arrives with the XMSS^MT state map.</remarks>
    [TestFixture]
    public class OpaqueStateHandleTests
    {
        [Test]
        public void TestBdsExposesNoMutator()
        {
            AssertNoPublicSurface(typeof(Bds));

            MethodInfo getBdsState = typeof(Org.BouncyCastle.Crypto.Parameters.XmssPrivateKeyParameters).GetMethod(
                "GetBdsState", BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
            Assert.IsNotNull(getBdsState);
            Assert.IsFalse(getBdsState.IsPublic, "a private key hands out its traversal state publicly");
        }

        private static void AssertNoPublicSurface(Type type)
        {
            Assert.IsFalse(type.IsPublic || type.IsNestedPublic, type.Name + " is public");

            MethodInfo[] methods = type.GetMethods(BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public
                | BindingFlags.DeclaredOnly);
            Assert.AreEqual(0, methods.Length, type.Name + " declares a public method");
        }
    }
}
