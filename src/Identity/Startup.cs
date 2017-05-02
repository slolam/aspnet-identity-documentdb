using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(Identity.Startup))]
namespace Identity
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
