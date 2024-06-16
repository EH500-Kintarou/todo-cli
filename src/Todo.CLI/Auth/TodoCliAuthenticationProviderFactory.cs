using System;

namespace Todo.CLI.Auth;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Identity.Client;
using Microsoft.Kiota.Abstractions.Authentication;
using System.Linq;

static class TodoCliAuthenticationProviderFactory
{
    public static IAuthenticationProvider GetAuthenticationProvider(IServiceProvider factory)
    {
        var config = factory.GetRequiredService<TodoCliConfiguration>();

        IPublicClientApplication app = PublicClientApplicationBuilder
            .Create(config.ClientId)
            .WithRedirectUri("http://localhost") // Only loopback redirect uri is supported, see https://aka.ms/msal-net-os-browser for details
            .Build();

        TokenCacheHelper.EnableSerialization(app.UserTokenCache);

		var accounts = app.GetAccountsAsync().GetAwaiter().GetResult();
		AuthenticationResult login;
		try {
			login = app.AcquireTokenSilent(config.Scopes, accounts.FirstOrDefault()).ExecuteAsync()
				.GetAwaiter().GetResult();
		}
		catch(MsalUiRequiredException) {
			login = app.AcquireTokenInteractive(config.Scopes).WithPrompt(Prompt.NoPrompt).ExecuteAsync()
				.GetAwaiter().GetResult();
		}
		var token = login.AccessToken;

        return new ApiKeyAuthenticationProvider("Bearer " + token, "Authorization",
            ApiKeyAuthenticationProvider.KeyLocation.Header);
    }
}