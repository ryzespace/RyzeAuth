using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public interface IOpaqueTokenService
{
    string CreateToken();
    string Digest(string rawToken);
    bool Verify(string rawToken, string expectedDigest);
}
