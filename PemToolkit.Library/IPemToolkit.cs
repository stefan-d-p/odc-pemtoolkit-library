using OutSystems.ExternalLibraries.SDK;

namespace Without.Systems.PemToolkit
{
    [OSInterface(
        Name = "PemToolkit",
        Description = "Toolkit for working with PEM certificates and keys",
        IconResourceName = "Without.Systems.PemToolkit.Resources.PEM.png")]
    public interface IPemToolkit
    {
        [OSAction(
            Description = "Convert an X.509 certificate PEM (leaf) to a serialized JWK JSON string (includes x5c).",
            ReturnName = "jwk",
            ReturnType = OSDataType.Text,
            IconResourceName = "Without.Systems.PemToolkit.Resources.PEM.png")]
        string PemCertificateToJwk(
            [OSParameter(
                DataType = OSDataType.Text,
                Description = "PEM source")]
            string pem,
            [OSParameter(
                DataType = OSDataType.Boolean,
                Description = "Return serialized Jwk indented. Defaults to true")]
            bool indented = true);

        [OSAction(
            Description = "Convert an RSA private or public key PEM to a serialized JWK JSON string.",
            ReturnName = "jwk",
            ReturnType = OSDataType.Text,
            IconResourceName = "Without.Systems.PemToolkit.Resources.PEM.png")]
        string PemRsaToJwk(
            [OSParameter(
                DataType = OSDataType.Text,
                Description = "PEM source")]
            string pem,
            [OSParameter(
                DataType = OSDataType.Boolean,
                Description = "Return serialized Jwk indented. Defaults to true")]
            bool indented = true,
            [OSParameter(
                DataType = OSDataType.Boolean,
                Description = "Include only public parameters in the JWK. Defaults to false")]
            bool publicOnly = false);
    }
}