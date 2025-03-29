using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Soenneker.Utils.Jwt.Abstract;
using Soenneker.Extensions.List.Claims;

namespace Soenneker.Utils.Test.AuthHandler;

/// <summary>
/// A test authentication handler used for integration testing scenarios.
/// Allows authentication via custom HTTP headers or JWT tokens, simulating authenticated users
/// without requiring real authentication infrastructure.
/// </summary>
public class TestAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly IHttpContextAccessor _context;
    private readonly IJwtUtil _jwtUtil;

    private const string ObjectIdentifierClaim = "http://schemas.microsoft.com/identity/claims/objectidentifier";
    private const string AuthorizationHeader = "Authorization";
    private const string AuthorizationUserIdHeader = "AuthorizationUserId";
    private const string AuthorizationEmailHeader = "AuthorizationEmail";
    private const string AuthorizationRolesHeader = "AuthorizationRoles";

    public TestAuthHandler(IHttpContextAccessor context, IJwtUtil jwtUtil, IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger, UrlEncoder encoder)
        : base(options, logger, encoder)
    {
        _context = context;
        _jwtUtil = jwtUtil;
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        IHeaderDictionary headers = _context.HttpContext!.Request.Headers;

        if (headers.TryGetValue(AuthorizationUserIdHeader, out StringValues userIdValue))
            return BuildAuthResultFromHeaders(headers, userIdValue);

        if (headers.TryGetValue(AuthorizationHeader, out StringValues authorizationValue))
            return BuildAuthResultFromJwt(authorizationValue);

        return Task.FromResult(AuthenticateResult.Fail("User id/Email was not found in headers, and no JWT set on request"));
    }

    private static Task<AuthenticateResult> BuildAuthResultFromHeaders(IHeaderDictionary headers, StringValues userIdValue)
    {
        string userId = userIdValue.Count > 0 ? userIdValue[0] ?? "" : "";

        var claims = new List<Claim>(4)
        {
            new(ObjectIdentifierClaim, userId)
        };

        if (headers.TryGetValue(AuthorizationEmailHeader, out StringValues emailValue) && emailValue.Count > 0)
        {
            claims.Add(new Claim(ClaimTypes.Email, emailValue[0] ?? ""));
        }

        if (headers.TryGetValue(AuthorizationRolesHeader, out StringValues roles) && roles.Count > 0)
        {
            ReadOnlySpan<char> span = roles[0].AsSpan();
            var start = 0;

            for (var i = 0; i <= span.Length; i++)
            {
                if (i == span.Length || span[i] == ',')
                {
                    ReadOnlySpan<char> role = span.Slice(start, i - start).Trim();
                    if (!role.IsEmpty)
                        claims.Add(new Claim(ClaimTypes.Role, role.ToString()));
                    start = i + 1;
                }
            }
        }
        else
        {
            claims.Add(new Claim(ClaimTypes.Role, "Admin"));
        }

        var principal = claims.ToClaimsPrincipal();
        var ticket = new AuthenticationTicket(principal, JwtBearerDefaults.AuthenticationScheme);

        return Task.FromResult(AuthenticateResult.Success(ticket));
    }

    private Task<AuthenticateResult> BuildAuthResultFromJwt(StringValues authorizationValue)
    {
        string authHeader = authorizationValue.Count > 0 ? authorizationValue[0] ?? "" : "";

        ReadOnlySpan<char> span = authHeader.AsSpan();
        int spaceIndex = span.IndexOf(' ');

        string token = spaceIndex >= 0 ? span.Slice(spaceIndex + 1).ToString() : "";

        ClaimsPrincipal claimsPrincipal = _jwtUtil.GetPrincipal(token)!;

        var ticket = new AuthenticationTicket(claimsPrincipal, JwtBearerDefaults.AuthenticationScheme);
        return Task.FromResult(AuthenticateResult.Success(ticket));
    }
}
