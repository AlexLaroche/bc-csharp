namespace Org.BouncyCastle.Crypto.Parameters
{
    /// <summary>Common base for XMSS public and private key parameters (RFC 8391).</summary>
    public class XmssKeyParameters
        : AsymmetricKeyParameter
    {
        public const string Sha256 = "SHA-256";
        public const string Sha512 = "SHA-512";
        public const string Shake128 = "SHAKE128";
        public const string Shake256 = "SHAKE256";
        public const string Shake256Len = "SHAKE256-LEN";

        private readonly string m_treeDigest;

        public XmssKeyParameters(bool isPrivateKey, string treeDigest)
            : base(isPrivateKey)
        {
            m_treeDigest = treeDigest;
        }

        /// <summary>The name of the digest the key's tree is built with.</summary>
        public string TreeDigest => m_treeDigest;
    }
}
