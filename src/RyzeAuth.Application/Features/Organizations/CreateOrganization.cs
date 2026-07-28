using FluentValidation;
using MediatR;
using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public sealed record CreateOrganizationCommand(string Slug, string DisplayName, string OwnerSubjectId) : IRequest<OrganizationResult>;
public sealed record OrganizationResult(Guid Id, string Slug, string DisplayName);

public sealed class CreateOrganizationCommandValidator : AbstractValidator<CreateOrganizationCommand>
{
    public CreateOrganizationCommandValidator()
    {
        RuleFor(x => x.Slug).Matches("^[a-z0-9][a-z0-9-]{2,62}$");
        RuleFor(x => x.DisplayName).NotEmpty().MaximumLength(120);
        RuleFor(x => x.OwnerSubjectId).NotEmpty().MaximumLength(100);
    }
}

public sealed class CreateOrganizationCommandHandler(
    IOrganizationRepository organizations,
    IClock clock) : IRequestHandler<CreateOrganizationCommand, OrganizationResult>
{
    public async Task<OrganizationResult> Handle(CreateOrganizationCommand request, CancellationToken cancellationToken)
    {
        var org = Organization.Create(request.Slug, request.DisplayName, clock.UtcNow);
        await organizations.AddAsync(org, cancellationToken);
        await organizations.AddMembershipAsync(
            Membership.Create(org.Id, request.OwnerSubjectId, "Owner", "{}", clock.UtcNow), cancellationToken);
        await organizations.SaveChangesAsync(cancellationToken);
        return new OrganizationResult(org.Id, org.Slug, org.DisplayName);
    }
}
