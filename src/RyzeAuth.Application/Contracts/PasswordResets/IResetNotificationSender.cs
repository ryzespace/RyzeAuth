using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public interface IResetNotificationSender
{
    Task SendAsync(string recipientEmail, Uri resetUrl, DateTimeOffset expiresAt, CancellationToken cancellationToken);
}
