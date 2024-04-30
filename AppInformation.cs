using DNE.CS.Inventory.Library.Interface;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DNE.CS.Inventory.Library;

public static class AppInformation
{
    private static IConfiguration? _configuration;

    public static string Url { get; } = "https://localhost:7125/";

    public static string RedirectUrl { get; } = "/Account/Login";
    public static string LogoutUrl { get; } = "/Logout";
    public static string CookieName { get; } = "Test";
    public static bool IsNlog { get; } = false;


    public static DateTime AccessTokenValideMinute
    {
        get
        {
            try
            {
                if (_configuration == null) return DateTime.Now.AddMinutes(1);
                return DateTime.Now.AddMinutes(
                    Convert.ToInt32(_configuration["AccessTokenValideMinute"]));
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }
    }

    public static DateTime RefreshTokenValideTime
    {
        get
        {
            try
            {
                if (_configuration == null) return DateTime.Now.AddDays(1);
                return DateTime.Now.AddDays(
                    Convert.ToInt32(_configuration["RefreshTokenValideDay"]));
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }

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

    public static string PrivateKey
    {
        get
        {
            if (_configuration == null) throw new Exception("configuration is null in appinformation");
            return _configuration["PrivateKey"] ?? throw new Exception("Private key is null");
        }
    }

    public static string DataProtectionKey
    {
        get
        {
            if(_configuration == null) throw new Exception("configuration is null in appinformation");
            return _configuration["DataProtectionKey"] ?? throw new Exception("Data protection key is null");
        }
    }

    public static RsaSecurityKey PublicKey
    {
        get
        {
            try
            {
                if (_configuration == null) throw new Exception("configuration is null in appinformation");
                string publicKey = _configuration["PublicKey"] ?? throw new Exception("Public key is null");

                ICryptography<string> c = new Cryptography<string>();
                return c.PublicKey(publicKey);
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }
    }

    public static void Initialize(IConfiguration configuration)
    {
        _configuration = configuration;
    }
}
