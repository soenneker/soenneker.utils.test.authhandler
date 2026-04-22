using Soenneker.Tests.HostedUnit;

namespace Soenneker.Utils.Test.AuthHandler.Tests;

[ClassDataSource<Host>(Shared = SharedType.PerTestSession)]
public class TestAuthHandlerTests : HostedUnitTest
{
    public TestAuthHandlerTests(Host host) : base(host)
    {
    }

    [Test]
    public void Default()
    {

    }
}
