using Grpc.Core;
using MediatR;
using RyzeAuth.Application;
using RyzeAuth.Contracts.Grpc;

namespace RyzeAuth.Api.Grpc;

public sealed class ApiKeyIntrospectionGrpcService(ISender sender) : ApiKeyIntrospection.ApiKeyIntrospectionBase
{
    public override async Task<IntrospectApiKeyReply> Introspect(IntrospectApiKeyRequest request, ServerCallContext context)
    {
        if (string.IsNullOrWhiteSpace(request.ApiKey))
        {
            throw new RpcException(new Status(StatusCode.InvalidArgument, "api_key is required"));
        }

        var result = await sender.Send(new IntrospectApiKeyQuery(request.ApiKey, request.RequiredScope), context.CancellationToken);
        return new IntrospectApiKeyReply
        {
            Active = result.Active,
            OrganizationId = result.OrganizationId?.ToString() ?? string.Empty,
            KeyId = result.KeyId?.ToString() ?? string.Empty,
            Reason = result.Reason ?? string.Empty,
            Scopes = { result.Scopes }
        };
    }
}
