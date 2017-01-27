namespace Zyborg.Security.Cryptography
{
    public interface IThresholdSecretSharingAlgorithm
    {
        byte[] Split(byte[] secretClear, int shareCount, int threshold);
    }
}