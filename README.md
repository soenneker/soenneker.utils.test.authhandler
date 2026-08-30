[![](https://img.shields.io/nuget/v/soenneker.utils.test.authhandler.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.utils.test.authhandler/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.utils.test.authhandler/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.utils.test.authhandler/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.utils.test.authhandler.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.utils.test.authhandler/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.utils.test.authhandler/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.utils.test.authhandler/actions/workflows/codeql.yml)

# ![](https://user-images.githubusercontent.com/4441470/224455560-91ed3ee7-f510-4041-a8d2-3fc093025112.png) Soenneker.Utils.Test.AuthHandler
A test authentication handler for integration tests. It creates an authenticated user from simple request headers or an existing bearer token.

## Installation

```bash
dotnet add package Soenneker.Utils.Test.AuthHandler
```

## Setup

```csharp
using Microsoft.AspNetCore.Authentication;
using Soenneker.Utils.Test.AuthHandler;

services
    .AddAuthentication("Test")
    .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>("Test", _ => { });
```

`TestAuthHandler` depends on `IJwtUtil`, so register that in the test host as well. Set `"Test"` as the default authentication scheme when requests should use this handler automatically.

## Authenticate a test request

The simplest option is to send a user ID. Email and roles are optional:

```csharp
client.DefaultRequestHeaders.Add("AuthorizationUserId", "test-user-123");
client.DefaultRequestHeaders.Add("AuthorizationEmail", "test@example.com");
client.DefaultRequestHeaders.Add("AuthorizationRoles", "Admin,Manager");
```

The resulting principal contains the Microsoft identity-platform object identifier claim, an optional `ClaimTypes.Email` claim, and one `ClaimTypes.Role` claim per role. Role values may be sent as repeated headers, comma-separated values, or both; whitespace around comma-separated roles is trimmed. If `AuthorizationRoles` is omitted, the handler assigns the `Admin` role.

`AuthorizationUserId` takes precedence over `Authorization`. Header-created identities use the configured authentication scheme name.

## Authenticate with a token

Alternatively, send an authorization value containing a scheme followed by a token:

```csharp
using System.Net.Http.Headers;

client.DefaultRequestHeaders.Authorization =
    new AuthenticationHeaderValue("Bearer", token);
```

The handler passes the text after the first space to `IJwtUtil.GetPrincipal`. For test compatibility it does not require the scheme text itself to be `Bearer`. If the token does not produce a principal, authentication fails instead of creating a ticket.

## Failure behavior

Authentication fails when neither `AuthorizationUserId` nor `Authorization` is present. JWT parsing exceptions from `IJwtUtil` propagate through the authentication pipeline; a null principal becomes a normal failed authentication result.

This package is intended only for controlled integration-test hosts. The identity headers are trusted input and must never be enabled as an authentication mechanism in a deployed application.
