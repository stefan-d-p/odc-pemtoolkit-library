namespace Without.Systems.PemToolkit.Test;

public class Tests
{
    private static readonly IPemToolkit Actions = new PemToolkit();

    [SetUp]
    public void Setup()
    {
    }

    [Test]
    public void Convert_Rsa_Pem_To_Jwk()
    {
        const string pem =
            "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0XbeegnxK0D5Q6yu7a+N\nBXlfT665v9hnXYMBv3hNVWrObOqtLFs2UTklUsU49q9FmxP4WkUIoM9aKZcTj3nV\nWdLOWYqbPeaZNJepmh2q1ICm55Y8HmV7RNLQDfeIhCERZvt/Jwvid/QzZb0Y0JAD\ntBEFvuwTgIqfGL4uS2LBd3DhRj17VY/vgqOEkE0Ophhp7oQOhPqI399yXk4JUqF1\ndvqM6q8ckCeLdv2sE6wm/3QhN/5kMV0mMGf3xGAJquRDggaQodbguHKh3gUDXZWm\npdVxkBNUu77GHzXVvLKBT+AjkWyJmBV/k02/N8VWrljiwy5uJ3vVW16eeH5RBDpz\nEHmdcv/uZokwgocWdF+LYEH6kghT3PCIzALe4xuS39vk6+svuAm+fT6qPa/Mms6W\nkAczPQpyFv4VYd1xXKlvGkgK2UYH40I4jzvi46ncuebv0dmu5Nr1GNB19NSL3cjG\nd099lhuiooXB6FqDjhvspeFn3I4uMdJe7RhbKXVa4cd3SJjqh7VYCmbakX6atNTE\nCbiTZWuVyVeoay9W63JZ4K9WSQe3LSqwsUr/FvX9d3yA01TwxDqecqjne6A/E26I\nhytdD1Mb1cUWZHVXeK4K2ikVBB/kk8Z+wfOsyzTOqBPW2DO77eGXikjKRGcnXc2R\n7ak/g7k80hHJriW7vEfJtTECAwEAAQ==\n-----END PUBLIC KEY-----\n";
        var jwkJson = Actions.PemRsaToJwk(pem, indented: true, publicOnly: true);
    }
    
    
    
}