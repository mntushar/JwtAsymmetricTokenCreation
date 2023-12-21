namespace DNE.CS.Inventory.Library.Interface;

public interface ICryptography<Tuser> where Tuser : class
{
    string OpenIdJwtToken(Guid userId, string userName, Guid customerId,
            string userEmail, IList<string> roleList,
            IList<System.Security.Claims.Claim> ClaimTypes,
            DateTime tokenValidationDate);
    string GenerateRefreshToken(Guid userId, string purpose,
        string securityStamp, DateTime validityTime);
    Task<string?> ValidateRefreshTokenAsync(string token, string purpose);
}
