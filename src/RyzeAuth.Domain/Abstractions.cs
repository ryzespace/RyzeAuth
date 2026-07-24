namespace RyzeAuth.Domain;

public interface IClock
{
    DateTimeOffset UtcNow { get; }
}
