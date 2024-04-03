using DNE.CS.Inventory.Library.Interface;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

namespace DNE.CS.Inventory.Library;

public class Cryptography<Tuser> : ICryptography<Tuser> where Tuser : class
{
    private readonly int _tokenEntity = 4;
    private readonly char _stringSeparator = ';';
    private UserManager<Tuser> _userManager;

    public Cryptography(UserManager<Tuser> userManager)
    {
        _userManager = userManager;
    }


    private string GenerateJWTAsymmetricToken(Claim[] claims,
           DateTime tokenValidationTime, string issuer, string audience)
    {
        try
        {
            if (!File.Exists(AppInformation.AsyJwtCertification))
            {
                throw new Exception("Certificate is not found.");
            }

            // Create signing credentials using the key
            var certificate = new X509Certificate2(AppInformation.AsyJwtCertification,
                AppInformation.AsyJwtPrivateKeyDecryptPassword);

            var signingCredentials = new SigningCredentials(new X509SecurityKey(certificate),
                SecurityAlgorithms.RsaSha256);

            // Define the token's options
            var tokenOptions = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: tokenValidationTime,
                signingCredentials: signingCredentials
            );

            // Generate the token as a string
            return new JwtSecurityTokenHandler().WriteToken(tokenOptions);
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }
    }

    public Claim[] GetClaims(Guid userId, string firstName, string lastName,
        string userName, Guid clientId, string userEmail)
    {
        try
        {
            return new[]
            {
                    new Claim("Id", userId.ToString()),
                    new Claim("ClientId", clientId.ToString()),
                    new Claim("firstName", firstName),
                    new Claim("lastName", lastName),
                    new Claim("userName", userName),
                    new Claim("email", userEmail),
                    new Claim("iat", new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds().ToString()),
            };
        }
        catch(Exception ex)
        {
            throw new Exception(ex.Message);
        }
    }

    public Claim[] GetClaims(Guid userId, string userName, string firstName, string lastName, Guid clientId,
            string userEmail, IList<string> roleList)
    {
        try
        {
            var clims = GetClaims(userId, firstName, lastName, userName, clientId,
            userEmail);

            clims = clims.Concat(roleList.Select(role => new Claim(ClaimTypes.Role, role))).ToArray();

            return clims;
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }
    }

    public string OpenIdJwtToken(Guid userId, string userName, string firstName, string lastName, 
        Guid clientId, string userEmail, IList<string> roleList, DateTime tokenValidationDate)

    {
        try
        {
            var clims = GetClaims(userId, firstName, lastName, userName, clientId, userEmail, roleList);

            return GenerateJWTAsymmetricToken(clims, tokenValidationDate,
                AppInformation.Url,
                AppInformation.Url);
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }
    }

    public string ProtectData(string data)
    {
        try
        {
            if (string.IsNullOrEmpty(AppInformation.DataProtectKey))
                throw new Exception("Data protect key isn't found.");

            // Instantiate the data protection system at this folder
            var dataProtectionProvider = DataProtectionProvider.Create(
                new DirectoryInfo(AppInformation.DataProtectKey!));

            var protector = dataProtectionProvider.CreateProtector("Cryptography protection");
            return protector.Protect(data);
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }
    }

    public string UnProtectData(string data)
    {
        try
        {
            if (string.IsNullOrEmpty(AppInformation.DataProtectKey))
                throw new Exception("Data protect key isn't found.");

            // Instantiate the data protection system at this folder
            var dataProtectionProvider = DataProtectionProvider.Create(
                new DirectoryInfo(AppInformation.DataProtectKey!));

            var protector = dataProtectionProvider.CreateProtector("Cryptography protection");
            return protector.Unprotect(data);
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }
    }

    public string GenerateRefreshToken(Guid userId, string purpose, string securityStamp, DateTime validityTime)
    {
        try
        {
            if (string.IsNullOrEmpty(purpose) || string.IsNullOrEmpty(securityStamp))
                throw new Exception("Purpose or security stamp isn't found.");

            string[] listInfo = new string[_tokenEntity];
            listInfo[0] = userId.ToString();
            listInfo[1] = purpose;
            listInfo[2] = securityStamp;
            listInfo[3] = validityTime.ToString();
            string info = string.Join(_stringSeparator, listInfo);

            return ProtectData(info);
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }
    }

    public async Task<string?> ValidateRefreshTokenAsync(string token, string purpose)
    {
        try
        {
            var unprotectedData = UnProtectData(token);

            string[] listInfo = unprotectedData.Split(_stringSeparator);

            if (!listInfo.Any() || listInfo.Count() < _tokenEntity)
                throw new Exception("User information is empty in refresh token");

            DateTime validityDate = DateTime.Parse(listInfo[3]);
            if (validityDate < DateTime.Now)
            {
                throw new Exception("InvalidExpirationTime");
            }

            string userId = listInfo[0];
            Tuser? user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                throw new Exception("UserIdsNotEquals");
            }

            string userPrpose = listInfo[1];
            if (!string.Equals(userPrpose, purpose))
            {
                throw new Exception("PurposeNotEquals");
            }

            string userSecurityStamp = listInfo[2];
            if (_userManager.SupportsUserSecurityStamp)
            {
                string securityStamp = await _userManager.GetSecurityStampAsync(user);
                if (!string.Equals(userSecurityStamp, securityStamp))
                {
                    throw new Exception("PurposeNotEquals");
                }
            }

            return userId;
        }
        catch (Exception ex)
        {
            throw new Exception(ex.Message);
        }
    }
}
