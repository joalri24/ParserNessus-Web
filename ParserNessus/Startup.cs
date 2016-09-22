using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(ParserNessus.Startup))]
namespace ParserNessus
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
