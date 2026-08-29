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

`TestAuthHandler` depends on `IJwtUtil`, so register that in the test host as well.

## Authenticate a test request

The simplest option is to send a user ID. Email and roles are optional:

```csharp
client.DefaultRequestHeaders.Add("AuthorizationUserId", "test-user-123");
client.DefaultRequestHeaders.Add("AuthorizationEmail", "test@example.com");
client.DefaultRequestHeaders.Add("AuthorizationRoles", "Admin,Manager");
```

If `AuthorizationRoles` is omitted, the handler assigns the `Admin` role. Alternatively, send a normal `Authorization: Bearer <token>` header to build the principal from a JWT.
