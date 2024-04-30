using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace DNE.CS.Inventory.Library.Interface;

public interface ICryptography<Tuser> where Tuser : class
{
    RsaSecurityKey PublicKey(string publicKey);
    RsaSecurityKey PrivateKey(string privateKey);
    Claim[] GetClaims(Guid userId, string firstName, string lastName, string userName, Guid clientId,
            string userEmail);
    Claim[] GetClaims(Guid userId, string firstName, string lastName, string userName, Guid clientId,
            string userEmail, IList<string> roleList);
    string OpenIdJwtToken(Guid userId, string firstName, string lastName, string userName, Guid clientId,
            string userEmail, IList<string> roleList,
            DateTime tokenValidationDate);
    string GenerateRefreshToken(Guid userId, string purpose,
        string securityStamp, DateTime validityTime);
    Task<string?> ValidateRefreshTokenAsync(string token, string purpose);
}
