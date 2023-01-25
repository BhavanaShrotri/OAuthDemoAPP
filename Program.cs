using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;

var builder = WebApplication.CreateBuilder(args);

// REF OAuth mock API : https://www.mocklab.io/docs/oauth2-mock/

builder.Services.AddAuthentication()
    .AddScheme<CookieAuthenticationOptions, VisiterAutHandler>("visitor", o => { })
    .AddCookie("local")
    .AddCookie("patreon-cookie")
    .AddOAuth("external-patreon", o =>
    {
        o.SignInScheme = "patreon-cookie";

        o.ClientId = "id";
        o.ClientSecret= "secret";
        o.AuthorizationEndpoint = "https://oauth.mocklab.io/oauth/authorize";
        o.TokenEndpoint= "https://oauth.mocklab.io/oauth/token";
        o.UserInformationEndpoint= "https://oauth.mocklab.io/userinfo";
        o.CallbackPath = "/cb-patreon";

        o.Scope.Add("profile");
        o.SaveTokens = true;
    });

builder.Services.AddAuthorization(b =>
{
    b.AddPolicy("customer", p =>
    {
        p.AddAuthenticationSchemes("local", "visitor")
        .RequireAuthenticatedUser();
    });

    b.AddPolicy("user", p =>
    {
        p.AddAuthenticationSchemes("local")
        .RequireAuthenticatedUser();
    });

});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", (HttpContext ctx) =>
{
    return Task.FromResult("Hello World");
}).RequireAuthorization("customer");

app.MapGet("/login-local", async (HttpContext ctx) =>
{
    var claims = new List<Claim>();
    claims.Add(new Claim("usr", "Bhavana"));
    var identity = new ClaimsIdentity(claims, "local");
    var user = new ClaimsPrincipal(identity);
    await ctx.SignInAsync("local", user);
}).AllowAnonymous();


app.MapGet("/login-patreon", async (HttpContext ctx) =>
{
    await ctx.ChallengeAsync("external-patreon", new AuthenticationProperties()
    {
        RedirectUri ="/"
    });

}).RequireAuthorization("user");

app.Run();


public class VisiterAutHandler : CookieAuthenticationHandler
{
    public VisiterAutHandler(
        IOptionsMonitor<CookieAuthenticationOptions> options, 
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock) : base(options, logger, encoder, clock)
    {
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var result = await base.HandleAuthenticateAsync();

        if (result.Succeeded)
        {
            return result;
        }

        var claims = new List<Claim>();
        claims.Add(new Claim("usr", "Bhavana"));
        var identity = new ClaimsIdentity(claims, "cookie");
        var user = new ClaimsPrincipal(identity);
        await Context.SignInAsync("visitor", user);

        return AuthenticateResult.Success(new AuthenticationTicket(user, "visitor"));
    }
}