using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace Without.Systems.PemToolkit;

public class PemToolkit : IPemToolkit
{
    public string Echo(string message)
    {
        return message;
    }

    /// <summary>
    /// Convert an X.509 certificate PEM (leaf) to a serialized JWK JSON string (includes x5c).
    /// </summary>
    /// <param name="pem">PEM source</param>
    /// <param name="indented">Return serialized Jwk indented. Defaults to true</param>
    /// <param name="kid">Optional kid value. if not provided one will be generated</param>
    /// <returns>Serialized Jwk</returns>
    /// <exception cref="ArgumentException"></exception>
    /// <exception cref="NotSupportedException"></exception>
    /// <exception cref="InvalidOperationException"></exception>
    public string PemCertificateToJwk(string pem, bool indented = true, string kid = "")
    {
        const string begin = "-----BEGIN CERTIFICATE-----";
        const string end = "-----END CERTIFICATE-----";
        
        if(string.IsNullOrWhiteSpace(pem) || !pem.Contains(begin, StringComparison.Ordinal))
        {
            throw new ArgumentException("Invalid PEM certificate format.", nameof(pem));
        }

        try
        {
            var inner = pem.Split(begin, StringSplitOptions.RemoveEmptyEntries)
                .Skip(1).First()
                .Split(end, StringSplitOptions.RemoveEmptyEntries)
                .First();

            var raw = Convert.FromBase64String(inner.Replace("\r", "").Replace("\n", "").Trim());

            using var cert = new X509Certificate2(raw);
            SecurityKey? key = null;

            using (var rsa = cert.GetRSAPublicKey())
                if (rsa != null)
                    key = new RsaSecurityKey(rsa);
            if (key == null)
            {
                using var ecdsa = cert.GetECDsaPublicKey();
                if (ecdsa != null) key = new ECDsaSecurityKey(ecdsa);
            }

            if (key == null)
            {
                throw new NotSupportedException(
                    "The certificate does not contain a supported public key type (RSA or ECDsa).");
            }

            JsonWebKey jwk = key is RsaSecurityKey r
                ? JsonWebKeyConverter.ConvertFromRSASecurityKey(r)
                : JsonWebKeyConverter.ConvertFromECDsaSecurityKey((ECDsaSecurityKey)key);

            jwk.X5c.Add(Convert.ToBase64String(cert.RawData));

            if(!string.IsNullOrWhiteSpace(kid))
                jwk.Kid = kid;
            else
                jwk.Kid ??= GenerateKid(jwk);

            return SerializeJwk(jwk, indented);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("Invalid PEM certificate format.", nameof(pem), ex);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Invalid PEM certificate format.", ex);
        }
    }

    /// <summary>
    /// Convert RSA PEM (public or private, PKCS#1 or PKCS#8) to a serialized JWK JSON string.
    /// </summary>
    /// <param name="pem">PEM Source</param>
    /// <param name="indented">Return serialized Jwk indented. Defaults to true</param>
    /// <param name="publicOnly">Include only public parameters in the JWK. Defaults to false</param>
    /// <param name="kid">Optional kid value. if not provided one will be generated</param>
    /// <returns>Serialized Jwk</returns>
    /// <exception cref="ArgumentException"></exception>
    /// <exception cref="InvalidOperationException"></exception>
    public string PemRsaToJwk(string pem, bool indented = true, bool publicOnly = false, string kid = "")
    {
        if (string.IsNullOrWhiteSpace(pem))
            throw new ArgumentException("Input PEM is empty.", nameof(pem));

        // Must look like an RSA/public/private key PEM
        bool looksRsa =
            pem.Contains("BEGIN RSA PUBLIC KEY", StringComparison.OrdinalIgnoreCase) ||
            pem.Contains("BEGIN PUBLIC KEY", StringComparison.OrdinalIgnoreCase) ||
            pem.Contains("BEGIN RSA PRIVATE KEY", StringComparison.OrdinalIgnoreCase) ||
            pem.Contains("BEGIN PRIVATE KEY", StringComparison.OrdinalIgnoreCase);

        if (!looksRsa)
            throw new ArgumentException("Input does not appear to be an RSA PEM.", nameof(pem));

        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(pem.AsSpan()); // handles PKCS#1 and PKCS#8

            var rsaKey = new RsaSecurityKey(rsa);
            var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(rsaKey);
            
            if(!string.IsNullOrWhiteSpace(kid))
                jwk.Kid = kid;
            else
                jwk.Kid ??= GenerateKid(jwk);

            if (publicOnly)
                StripPrivateRsa(jwk);

            return SerializeJwk(jwk, indented);
        }
        catch (CryptographicException ex)
        {
            throw new ArgumentException("Malformed or unsupported RSA PEM content.", nameof(pem), ex);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Failed to convert RSA PEM to JWK.", ex);
        }
    }


    private string GenerateKid(JsonWebKey jwk)
    {
        
        byte[] material;

        if (string.Equals(jwk.Kty, "RSA", StringComparison.OrdinalIgnoreCase) &&
            jwk.N is not null && jwk.E is not null)
        {
            material = Concat(Base64UrlEncoder.DecodeBytes(jwk.N), Base64UrlEncoder.DecodeBytes(jwk.E));
        }
        else if (string.Equals(jwk.Kty, "EC", StringComparison.OrdinalIgnoreCase) &&
                 jwk.X is not null && jwk.Y is not null)
        {
            material = Concat(Base64UrlEncoder.DecodeBytes(jwk.X), Base64UrlEncoder.DecodeBytes(jwk.Y));
        }
        else
        {
            var json = JsonSerializer.Serialize(jwk);
            material = Encoding.UTF8.GetBytes(json);
        }

        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(material);
        return Base64UrlEncoder.Encode(hash);

    }
    
    private string SerializeJwk(JsonWebKey jwk, bool indented)
        => JsonSerializer.Serialize(jwk, new JsonSerializerOptions { WriteIndented = indented });
    
    private byte[] Concat(byte[] a, byte[] b)
    {
        var r = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, r, 0, a.Length);
        Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
        return r;
    }
    
    private void StripPrivateRsa(JsonWebKey jwk)
    {
        jwk.D = null;
        jwk.DP = null;
        jwk.DQ = null;
        jwk.P = null;
        jwk.Q = null;
        jwk.QI = null;
    }

}