using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public interface ISecurityNotificationSender
{
    Task SendAsync(SecurityNotification notification, CancellationToken cancellationToken);
}
