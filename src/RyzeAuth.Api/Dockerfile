FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY Directory.Build.props Directory.Packages.props global.json RyzeAuth.sln ./
COPY src/RyzeAuth.Domain/RyzeAuth.Domain.csproj src/RyzeAuth.Domain/
COPY src/RyzeAuth.Application/RyzeAuth.Application.csproj src/RyzeAuth.Application/
COPY src/RyzeAuth.Contracts/RyzeAuth.Contracts.csproj src/RyzeAuth.Contracts/
COPY src/RyzeAuth.Infrastructure/RyzeAuth.Infrastructure.csproj src/RyzeAuth.Infrastructure/
COPY src/RyzeAuth.Api/RyzeAuth.Api.csproj src/RyzeAuth.Api/
RUN dotnet restore src/RyzeAuth.Api/RyzeAuth.Api.csproj
COPY src ./src
RUN dotnet publish src/RyzeAuth.Api/RyzeAuth.Api.csproj -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app
RUN addgroup --system ryzeauth && adduser --system --ingroup ryzeauth ryzeauth
COPY --from=build /app/publish ./
USER ryzeauth
ENV ASPNETCORE_URLS=http://+:8080 \
    ASPNETCORE_FORWARDEDHEADERS_ENABLED=true \
    DOTNET_EnableDiagnostics=0
EXPOSE 8080
ENTRYPOINT ["dotnet", "RyzeAuth.Api.dll"]
