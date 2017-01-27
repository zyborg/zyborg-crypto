namespace Zyborg.Security.Cryptography
{
    public abstract class ThresholdSecretSharingAlgorithm : SecretSharingAlgorithm
    {
        public abstract byte[] Split(byte[] secretClear, int shareCount, int threshold);

        public static new ThresholdSecretSharingAlgorithm Create()
        {
            return (ThresholdSecretSharingAlgorithm)SecretSharingAlgorithm.Create();
        }
        
        public static new ThresholdSecretSharingAlgorithm Create(string algName)
        {
            return (ThresholdSecretSharingAlgorithm)SecretSharingAlgorithm.Create(algName);
        }
    }
}