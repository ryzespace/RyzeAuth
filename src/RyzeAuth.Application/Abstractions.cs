using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public interface IApiKeyRepository
{
    Task AddAsync(ApiKey apiKey, CancellationToken cancellationToken);
    Task<ApiKey?> FindByPrefixAsync(string prefix, CancellationToken cancellationToken);
    Task<ApiKey?> GetAsync(Guid id, CancellationToken cancellationToken);
    Task SaveChangesAsync(CancellationToken cancellationToken);
}

public interface IOrganizationRepository
{
    Task AddAsync(Organization organization, CancellationToken cancellationToken);
    Task AddMembershipAsync(Membership membership, CancellationToken cancellationToken);
    Task<Organization?> GetAsync(Guid id, CancellationToken cancellationToken);
    Task<Membership?> GetMembershipAsync(Guid organizationId, string subjectId, CancellationToken cancellationToken);
    Task SaveChangesAsync(CancellationToken cancellationToken);
}

public interface IPasswordResetTicketStore
{
    Task AddAsync(PasswordResetTicket ticket, CancellationToken cancellationToken);
    Task<PasswordResetTicket?> FindByDigestAsync(string digest, CancellationToken cancellationToken);
    Task InvalidateActiveForSubjectAsync(string subjectId, DateTimeOffset now, CancellationToken cancellationToken);
    Task SaveChangesAsync(CancellationToken cancellationToken);
}

public interface IAuditTrail
{
    Task RecordAsync(SecurityAuditEvent auditEvent, CancellationToken cancellationToken);
}

public interface IKeycloakAdminClient
{
    Task<KeycloakUser?> FindUserByEmailAsync(string email, CancellationToken cancellationToken);
    Task<KeycloakUser?> GetUserAsync(string subjectId, CancellationToken cancellationToken);
    Task<KeycloakUser> CreateUserAsync(KeycloakUserCreateRequest request, CancellationToken cancellationToken);
    Task UpdateUserAsync(string subjectId, KeycloakUserUpdateRequest request, CancellationToken cancellationToken);
    Task DisableUserAsync(string subjectId, CancellationToken cancellationToken);
    Task<TokenIntrospectionResult> IntrospectAsync(string token, CancellationToken cancellationToken);
    Task ResetPasswordAsync(string subjectId, string newPassword, CancellationToken cancellationToken);
    Task LogoutSessionAsync(string keycloakSessionId, CancellationToken cancellationToken);
    Task LogoutAllSessionsAsync(string subjectId, CancellationToken cancellationToken);
}

public sealed record KeycloakUser(string SubjectId, string Email, bool EmailVerified, bool Enabled);
public sealed record TokenIntrospectionResult(bool Active, string? SubjectId, string? ClientId, IReadOnlyList<string> Scopes, DateTimeOffset? ExpiresAt);

public interface IPasswordPolicy
{
    Task<PasswordPolicyResult> ValidateAsync(string password, string? userName, CancellationToken cancellationToken);
}

public sealed record PasswordPolicyResult(bool IsValid, IReadOnlyList<string> Errors)
{
    public static PasswordPolicyResult Success { get; } = new(true, []);
}

public interface IOpaqueTokenService
{
    string CreateToken();
    string Digest(string rawToken);
    bool Verify(string rawToken, string expectedDigest);
}

public interface IResetNotificationSender
{
    Task SendAsync(string recipientEmail, Uri resetUrl, DateTimeOffset expiresAt, CancellationToken cancellationToken);
}

public interface IRequestSecurityContext
{
    string? SubjectId { get; }
    string? CorrelationId { get; }
    string? IpAddress { get; }
}

public interface IOrganizationAuthorizer
{
    Task DemandAsync(string subjectId, Guid organizationId, OrganizationAccess permission, CancellationToken cancellationToken);
}

public enum OrganizationAccess
{
    View,
    ManageMembers,
    ManageApiKeys,
    ManageSessions,
    ViewAudit
}

public interface IRiskEngine
{
    Task<RiskAssessment> AssessAsync(RiskContext context, CancellationToken cancellationToken);
    Task RegisterFailureAsync(string kind, string principal, string? ipAddress, CancellationToken cancellationToken);
}

public sealed record RiskContext(string SubjectOrEmail, string? IpAddress, string? UserAgent, string? CountryCode);
public sealed record RiskAssessment(int Score, bool RequireStepUpMfa, bool Block, IReadOnlyList<string> Signals);

public sealed class AuthorizationDeniedException(string message) : Exception(message);
public sealed class NotFoundException(string message) : Exception(message);
public sealed class SecurityValidationException(string message) : Exception(message);

public interface IDeviceSessionRepository
{
    Task<DeviceSession?> GetAsync(Guid id, CancellationToken cancellationToken);
    Task<DeviceSession?> FindByKeycloakSessionIdAsync(string keycloakSessionId, CancellationToken cancellationToken);
    Task<IReadOnlyList<DeviceSession>> ListActiveForSubjectAsync(string subjectId, CancellationToken cancellationToken);
    Task AddAsync(DeviceSession session, CancellationToken cancellationToken);
    Task SaveChangesAsync(CancellationToken cancellationToken);
}

public interface ILoginObservationRepository
{
    Task<LoginObservation?> GetLatestForSubjectAsync(string subjectId, CancellationToken cancellationToken);
    Task AddAsync(LoginObservation observation, CancellationToken cancellationToken);
    Task SaveChangesAsync(CancellationToken cancellationToken);
}

public interface ITokenBlacklistService
{
    Task RevokeTokenAsync(string tokenId, DateTimeOffset expiresAt, CancellationToken cancellationToken);
    Task RevokeSubjectAsync(string subjectId, DateTimeOffset revokeAfter, CancellationToken cancellationToken);
    Task<bool> IsTokenRevokedAsync(string tokenId, CancellationToken cancellationToken);
    Task<bool> IsSubjectRevokedAsync(string subjectId, DateTimeOffset issuedAt, CancellationToken cancellationToken);
}

public interface IGeoIpRiskProvider
{
    Task<GeoIpRiskInfo> LookupAsync(string? ipAddress, CancellationToken cancellationToken);
}

public sealed record GeoIpRiskInfo(
    string? CountryCode,
    decimal? Latitude,
    decimal? Longitude,
    string? AutonomousSystem,
    bool IsVpn,
    bool IsProxy,
    bool IsTor);

public interface IAdaptiveRiskService
{
    Task<AdaptiveRiskDecision> AssessAsync(LoginRiskInput input, CancellationToken cancellationToken);
    Task RecordSuccessfulLoginAsync(LoginRiskInput input, AdaptiveRiskDecision decision, CancellationToken cancellationToken);
}

public sealed record LoginRiskInput(string SubjectId, string? IpAddress, string? UserAgent, string? DeviceId, DateTimeOffset OccurredAt);
public sealed record AdaptiveRiskDecision(int Score, bool RequireMfa, bool Block, IReadOnlyList<string> Signals, GeoIpRiskInfo Geo);

public sealed record KeycloakUserCreateRequest(
    string Email,
    string? FirstName,
    string? LastName,
    bool Enabled,
    string? ExternalId);

public sealed record KeycloakUserUpdateRequest(
    string Email,
    string? FirstName,
    string? LastName,
    bool Enabled,
    string? ExternalId);

public interface ISessionLimitPolicy
{
    int MaximumActiveDevices { get; }
}

public interface IEventSignatureValidator
{
    bool IsValid(string payload, string? signature);
}

public interface ISecurityNotificationSender
{
    Task SendAsync(SecurityNotification notification, CancellationToken cancellationToken);
}

public sealed record SecurityNotification(string RecipientEmail, string EventType, DateTimeOffset OccurredAt, string? UserAgent, string? CountryCode);

public interface IAuditReadRepository
{
    Task<IReadOnlyList<SecurityAuditEvent>> ListForSubjectAsync(string subjectId, int take, CancellationToken cancellationToken);
    Task<IReadOnlyList<SecurityAuditEvent>> ListForOrganizationAsync(Guid organizationId, int take, CancellationToken cancellationToken);
}

public interface IRequestRateLimiter
{
    Task<bool> TryAcquireAsync(string category, string partition, int permitLimit, TimeSpan window, CancellationToken cancellationToken);
}
