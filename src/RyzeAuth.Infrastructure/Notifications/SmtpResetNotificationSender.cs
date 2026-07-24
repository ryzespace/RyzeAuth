using System.Net;
using System.Net.Mail;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RyzeAuth.Application;

namespace RyzeAuth.Infrastructure.Notifications;

public sealed class SmtpResetNotificationSender(IOptions<SmtpOptions> options, ILogger<SmtpResetNotificationSender> logger) : IResetNotificationSender, ISecurityNotificationSender
{
    private static readonly Action<ILogger, string, Exception?> LogSuppressedReset = LoggerMessage.Define<string>(
        LogLevel.Warning, new EventId(1003, "PasswordResetMailSuppressed"),
        "SMTP is disabled; a password-reset mail to {Recipient} was suppressed.");

    private static readonly Action<ILogger, string, Exception?> LogSuppressedSecurityNotification = LoggerMessage.Define<string>(
        LogLevel.Warning, new EventId(1004, "SecurityNotificationSuppressed"),
        "SMTP is disabled; a security notification to {Recipient} was suppressed.");

    public async Task SendAsync(string recipientEmail, Uri resetUrl, DateTimeOffset expiresAt, CancellationToken cancellationToken)
    {
        var smtp = options.Value;
        if (!smtp.Enabled)
        {
            LogSuppressedReset(logger, recipientEmail, null);
            return;
        }

        using var message = new MailMessage(smtp.From, recipientEmail)
        {
            Subject = "RyzeSpace: reset your password",
            Body = $"A password reset was requested. Use this one-time link before {expiresAt:O}:\n\n{resetUrl}\n\nIf this was not you, ignore this message.",
            IsBodyHtml = false
        };
        await SendAsync(message, smtp, cancellationToken);
    }

    public async Task SendAsync(SecurityNotification notification, CancellationToken cancellationToken)
    {
        var smtp = options.Value;
        if (!smtp.Enabled)
        {
            LogSuppressedSecurityNotification(logger, notification.RecipientEmail, null);
            return;
        }

        var details = new List<string> { $"Time: {notification.OccurredAt:O}" };
        if (!string.IsNullOrWhiteSpace(notification.UserAgent))
        {
            details.Add($"Browser or device: {notification.UserAgent}");
        }

        if (!string.IsNullOrWhiteSpace(notification.CountryCode))
        {
            details.Add($"Country: {notification.CountryCode}");
        }

        using var message = new MailMessage(smtp.From, notification.RecipientEmail)
        {
            Subject = "RyzeSpace security notification",
            Body = $"A security event occurred: {notification.EventType}.\n\n{string.Join("\n", details)}\n\nIf this was not you, revoke your sessions and contact support.",
            IsBodyHtml = false
        };
        await SendAsync(message, smtp, cancellationToken);
    }

    private static async Task SendAsync(MailMessage message, SmtpOptions smtp, CancellationToken cancellationToken)
    {
        using var client = new SmtpClient(smtp.Host, smtp.Port)
        {
            EnableSsl = true,
            Credentials = new NetworkCredential(smtp.UserName, smtp.Password)
        };
        await client.SendMailAsync(message, cancellationToken);
    }
}
