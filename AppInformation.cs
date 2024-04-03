using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DNE.CS.Inventory.Library;

public static class AppInformation
{
    private static IConfiguration? _configuration;

    public static string Url { get; } = "https://localhost:5266";

    public static string RedirectUrl { get; } = "/Account/Login";
    public static string LogoutUrl { get; } = "/Logout";

    public static DateTime AccessTokenValideMinute
    {
        get
        {
            if (_configuration == null) return DateTime.Now.AddMinutes(1);
            return DateTime.Now.AddMinutes(
                Convert.ToInt32(_configuration["AccessTokenValideMinute"]));
        }
    }

    public static DateTime RefreshTokenValideTime {
        get
        {
            if (_configuration == null) return DateTime.Now.AddDays(1);
            return DateTime.Now.AddDays(
                Convert.ToInt32(_configuration["RefreshTokenValideDay"]));
        } 
    }

    public static string? AccessTokenName
    {
        get
        {
            return "DNE_CS_Inventory_AccessToken";
        }
    }

    public static string? RefreshTokenName
    {
        get
        {
            return "DNE_CS_Inventory_RefreshToken";
        }
    }

    //calculation in sec
    public static int TokenValidationTime
    {
        get
        {
            return 60;
        }
    }

    public static string? AsyJwtCertification
    {
        get
        {
            if (_configuration == null) return string.Empty;
            return _configuration["JwtTokenCertification"];
        }
    }

    public static string? DataProtectKey
    {
        get
        {
            if (_configuration == null) return string.Empty;
            return _configuration["DataProtectKey"];
        }
    }

    public static RsaSecurityKey? AsyJwtECDsaPublicKey
    {
        get
        {
            try
            {
                // Load the X509Certificate2 from a file or store
                if (AsyJwtCertification == null) return null;
                using (X509Certificate2 certificate = new X509Certificate2(AsyJwtCertification, AsyJwtPrivateKeyDecryptPassword))
                {
                    // Get the RSA public key from the certificate
                    RSA? publicKey = certificate.GetRSAPublicKey();

                    if (publicKey == null)
                    {
                        return null;
                    }

                    // Create an instance of RsaSecurityKey
                    return new RsaSecurityKey(publicKey);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

            return null;
        }
    }

    public static string? AsyJwtPrivateKeyDecryptPassword
    {
        get
        {
            try
            {
                if (_configuration == null) throw new Exception("AsyJwtPrivateKeyDecryptPassword key is empty.");
                return _configuration["AsyJwtPrivateKeyDecryptPassword"];
            }
            catch(Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

            return null;
        }
    }

    public static void Initialize(IConfiguration configuration)
    {
        _configuration = configuration;
    }
}
