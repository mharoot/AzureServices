using System;
using System.Threading;

namespace WEBNAME.Auth
{
    /// <summary>
    /// Minimal composition root (the project has no DI container). Singletons are created
    /// lazily and, with PublicationOnly, a configuration error is NOT cached: fix the
    /// setting and the next request works without an app-pool recycle.
    /// </summary>
    public static class AuthServices
    {
        private static readonly Lazy<AuthSettings> SettingsLazy =
            new Lazy<AuthSettings>(AuthSettings.FromConfiguration, LazyThreadSafetyMode.PublicationOnly);

        private static readonly Lazy<IOidcClient> OidcLazy =
            new Lazy<IOidcClient>(() => new MsalOidcClient(Settings), LazyThreadSafetyMode.PublicationOnly);

        private static readonly Lazy<IIdTokenValidator> ValidatorLazy =
            new Lazy<IIdTokenValidator>(() => IdTokenValidator.Create(Settings), LazyThreadSafetyMode.PublicationOnly);

        public static AuthSettings Settings => SettingsLazy.Value;
        public static IOidcClient OidcClient => OidcLazy.Value;
        public static IIdTokenValidator TokenValidator => ValidatorLazy.Value;
        public static IUserSessionStore SessionStore { get; } = new HttpSessionUserStore();
        public static IAuthLogger Logger { get; } = new TraceAuthLogger();
    }
}
