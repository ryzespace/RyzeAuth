using FluentValidation;
using MediatR;
using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public sealed record AddMemberCommand(Guid OrganizationId, string ActorSubjectId, string SubjectId, string Role, string AttributesJson) : IRequest;

public sealed class AddMemberCommandValidator : AbstractValidator<AddMemberCommand>
{
    public AddMemberCommandValidator()
    {
        RuleFor(x => x.OrganizationId).NotEmpty();
        RuleFor(x => x.ActorSubjectId).NotEmpty();
        RuleFor(x => x.SubjectId).NotEmpty().MaximumLength(100);
        RuleFor(x => x.Role).Must(x => x is "Owner" or "OrgAdmin" or "SecurityAdmin" or "Member")
            .WithMessage("Role must be Owner, OrgAdmin, SecurityAdmin or Member.");
        RuleFor(x => x.AttributesJson).NotEmpty().MaximumLength(8_000);
    }
}

public sealed class AddMemberCommandHandler(
    IOrganizationRepository organizations,
    IOrganizationAuthorizer authorizer,
    IClock clock) : IRequestHandler<AddMemberCommand>
{
    public async Task Handle(AddMemberCommand request, CancellationToken cancellationToken)
    {
        await authorizer.DemandAsync(request.ActorSubjectId, request.OrganizationId, OrganizationAccess.ManageMembers, cancellationToken);
        if (await organizations.GetAsync(request.OrganizationId, cancellationToken) is null)
        {
            throw new NotFoundException("Organization does not exist.");
        }

        if (await organizations.GetMembershipAsync(request.OrganizationId, request.SubjectId, cancellationToken) is not null)
        {
            throw new SecurityValidationException("User already belongs to this organization.");
        }

        await organizations.AddMembershipAsync(
            Membership.Create(request.OrganizationId, request.SubjectId, request.Role, request.AttributesJson, clock.UtcNow), cancellationToken);
        await organizations.SaveChangesAsync(cancellationToken);
    }
}
