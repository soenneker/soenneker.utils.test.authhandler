using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Soenneker.Extensions.List.Claims;
using Soenneker.Utils.Jwt.Abstract;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace Soenneker.Utils.Test.AuthHandler;

public sealed class TestAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly IJwtUtil _jwtUtil;

    private const string _objectIdentifierClaim = "http://schemas.microsoft.com/identity/claims/objectidentifier";

    private const string _authorizationHeader = "Authorization";
    private const string _authorizationUserIdHeader = "AuthorizationUserId";
    private const string _authorizationEmailHeader = "AuthorizationEmail";
    private const string _authorizationRolesHeader = "AuthorizationRoles";

    private const string _defaultRole = "Admin";

    // Avoid allocating this failure string path repeatedly.
    private static readonly Task<AuthenticateResult> _sMissingAuthFail =
        Task.FromResult(AuthenticateResult.Fail("User id/Email was not found in headers, and no JWT set on request"));

    public TestAuthHandler(IJwtUtil jwtUtil, IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder) : base(options,
        logger, encoder)
    {
        _jwtUtil = jwtUtil;
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        // Use Handler's Request/Context - no IHttpContextAccessor needed.
        IHeaderDictionary headers = Request.Headers;

        if (headers.TryGetValue(_authorizationUserIdHeader, out StringValues userIdValues))
            return BuildAuthResultFromHeaders(headers, userIdValues);

        if (headers.TryGetValue(_authorizationHeader, out StringValues authorizationValues))
            return BuildAuthResultFromJwt(authorizationValues);

        return _sMissingAuthFail;
    }

    private static Task<AuthenticateResult> BuildAuthResultFromHeaders(IHeaderDictionary headers, StringValues userIdValues)
    {
        // StringValues is a struct, Count is cheap, indexer returns string?
        string userId = userIdValues.Count > 0 ? (userIdValues[0] ?? string.Empty) : string.Empty;

        // Common case: oid + email(optional) + role(s)
        // Capacity guess: 2 base + up to a few roles.
        var claims = new List<Claim>(6)
        {
            new(_objectIdentifierClaim, userId)
        };

        if (headers.TryGetValue(_authorizationEmailHeader, out StringValues emailValues) && emailValues.Count > 0)
        {
            claims.Add(new Claim(ClaimTypes.Email, emailValues[0] ?? string.Empty));
        }

        // Prefer multi-value header: AuthorizationRoles: Admin
        // AuthorizationRoles: Manager
        // AuthorizationRoles: Billing
        //
        // Still support comma-separated in each value for convenience.
        if (headers.TryGetValue(_authorizationRolesHeader, out StringValues roleValues) && roleValues.Count > 0)
        {
            AddRoles(claims, roleValues);
        }
        else
        {
            claims.Add(new Claim(ClaimTypes.Role, _defaultRole));
        }

        var principal = claims.ToClaimsPrincipal("Test");
        var ticket = new AuthenticationTicket(principal, JwtBearerDefaults.AuthenticationScheme);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }

    private static void AddRoles(List<Claim> claims, StringValues roleValues)
    {
        for (var v = 0; v < roleValues.Count; v++)
        {
            string? rolesString = roleValues[v];
            if (string.IsNullOrWhiteSpace(rolesString))
                continue;

            ReadOnlySpan<char> span = rolesString.AsSpan();

            var start = 0;
            for (var i = 0; i <= span.Length; i++)
            {
                if (i == span.Length || span[i] == ',')
                {
                    ReadOnlySpan<char> role = span.Slice(start, i - start)
                                                  .Trim();
                    if (!role.IsEmpty)
                    {
                        // Claim requires string; unavoidable allocation per distinct role.
                        claims.Add(new Claim(ClaimTypes.Role, role.ToString()));
                    }

                    start = i + 1;
                }
            }
        }
    }

    private Task<AuthenticateResult> BuildAuthResultFromJwt(StringValues authorizationValues)
    {
        string authHeader = authorizationValues.Count > 0 ? (authorizationValues[0] ?? string.Empty) : string.Empty;

        ReadOnlySpan<char> span = authHeader.AsSpan();
        int spaceIndex = span.IndexOf(' ');

        // If you want to be stricter, verify "Bearer" prefix, but keeping your behavior.
        string token = spaceIndex >= 0
            ? span.Slice(spaceIndex + 1)
                  .ToString()
            : string.Empty;

        // Avoid an async state machine by returning a continuation task.
        // (Assumes _jwtUtil.GetPrincipal returns Task/ValueTask-like; if it's ValueTask, this still works via AsTask in your util.)
        return BuildTicketFromPrincipalAsync(token);

        async Task<AuthenticateResult> BuildTicketFromPrincipalAsync(string t)
        {
            ClaimsPrincipal? principal = (await _jwtUtil.GetPrincipal(t))!;
            var ticket = new AuthenticationTicket(principal, JwtBearerDefaults.AuthenticationScheme);
            return AuthenticateResult.Success(ticket);
        }
    }
}