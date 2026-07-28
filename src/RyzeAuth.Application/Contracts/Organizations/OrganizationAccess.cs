using RyzeAuth.Domain;

namespace RyzeAuth.Application;

public enum OrganizationAccess
{
    View,
    ManageMembers,
    ManageApiKeys,
    ManageSessions,
    ViewAudit
}
