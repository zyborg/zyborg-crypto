using System;
using System.Collections.Generic;

namespace Zyborg.Security.Cryptography
{
    public abstract class SecretSharingAlgorithm : IDisposable
    {
        // Case-insensitive, name to algor class mapping
        private static readonly IReadOnlyDictionary<string, Type> ALG_MAP =
                new Dictionary<string, Type>(StringComparer.CurrentCultureIgnoreCase)
                {
                    ["layered-symmetric"] =
                        typeof(LayeredSymmetricSecretSharing),
                    [nameof(LayeredSymmetricSecretSharing)] =
                        typeof(LayeredSymmetricSecretSharing),
                    [typeof(LayeredSymmetricSecretSharing).FullName] =
                        typeof(LayeredSymmetricSecretSharing),

                    ["layered-asymmetric"] =
                        typeof(LayeredAsymmetricSecretSharing),
                    [nameof(LayeredAsymmetricSecretSharing)] =
                        typeof(LayeredAsymmetricSecretSharing),
                    [typeof(LayeredAsymmetricSecretSharing).FullName] =
                        typeof(LayeredAsymmetricSecretSharing),

                    ["BigIntShamirs"] =
                        Type.GetType("Zyborg.Security.Cryptography.BigIntShamirsSecretSharing,"
                                + " Zyborg.Security.Cryptography.TrivialShamir", false),
                    ["BigIntShamirsSecretSharing"] =
                        Type.GetType("Zyborg.Security.Cryptography.BigIntShamirsSecretSharing,"
                                + " Zyborg.Security.Cryptography.TrivialShamir", false),
                    ["Zyborg.Security.Cryptography.BigIntShamirsSecretSharing"] =
                        Type.GetType("Zyborg.Security.Cryptography.BigIntShamirsSecretSharing,"
                                + " Zyborg.Security.Cryptography.TrivialShamir", false),

                    ["HashiCorpShamirs"] =
                        Type.GetType("Zyborg.Security.Cryptography.HashiCorpShamirsSecretSharing,"
                                + " Zyborg.Security.Cryptography.HashiCorpShamir", false),
                    ["HashiCorpShamirsSecretSharing"] =
                        Type.GetType("Zyborg.Security.Cryptography.HashiCorpShamirsSecretSharing,"
                                + " Zyborg.Security.Cryptography.HashiCorpShamir", false),
                    ["Zyborg.Security.Cryptography.HashiCorpShamirsSecretSharing"] =
                        Type.GetType("Zyborg.Security.Cryptography.HashiCorpShamirsSecretSharing,"
                                + " Zyborg.Security.Cryptography.HashiCorpShamir", false),
                };

        public static SecretSharingAlgorithm Create()
        {
            return Create(typeof(SecretSharingAlgorithm).FullName);
        }

        public static SecretSharingAlgorithm Create(string algName)
        {
            // TODO: turn this into a provider-extension point (via MEF?)

            if (ALG_MAP.ContainsKey(algName))
                return (SecretSharingAlgorithm)Activator.CreateInstance(ALG_MAP[algName]);
            else
                return null;
        }

        public virtual IEnumerable<byte[]> Shares
        { get; set; }

        public abstract byte[] Split(byte[] secretClear, int shareCount);

        public abstract byte[] Combine(byte[] secretCrypt);

        #region -- IDisposable Support --
        
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects).
                }

                // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.
                // TODO: set large fields to null.

                disposedValue = true;
            }
        }

        // TODO: override a finalizer only if Dispose(bool disposing) above has code to free unmanaged resources.
        // ~SecretSharingAlgorithm() {
        //   // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
        //   Dispose(false);
        // }

        // This code added to correctly implement the disposable pattern.
        void IDisposable.Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
            // TODO: uncomment the following line if the finalizer is overridden above.
            // GC.SuppressFinalize(this);
        }

        #endregion  -- IDisposable Support --
    }
}