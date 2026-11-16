using System;
using Microsoft.Extensions.Configuration;

namespace WEBNAME.E2E
{
    /// <summary>
    /// Test configuration. Values come from (later wins):
    ///   1. dotnet user-secrets   (developer machines; stored outside the repo)
    ///   2. environment variables (CI; fed from the pipeline's secret store)
    /// Nothing sensitive is ever read from a file in the repository.
    /// </summary>
    public sealed class E2ESettings
    {
        private E2ESettings() { }

        /// <summary>Deployed dev/test site, e.g. https://webname-dev.com/ (always ends with '/').</summary>
        public Uri BaseUrl { get; private set; }

        /// <summary>Dedicated Entra test account (UPN). Never a real person's account.</summary>
        public string Username { get; private set; }
        public string Password { get; private set; }

        /// <summary>Optional: if set, the home page must contain this text after login.</summary>
        public string ExpectedDisplayName { get; private set; }

        /// <summary>Set E2E_HEADED=true to watch the browser locally.</summary>
        public bool Headed { get; private set; }

        public static E2ESettings Load()
        {
            var config = new ConfigurationBuilder()
                .AddUserSecrets<E2ESettings>(optional: true)
                .AddEnvironmentVariables()
                .Build();

            var rawUrl = Require(config, "E2E_BASE_URL");
            if (!rawUrl.EndsWith("/")) rawUrl += "/";

            Uri baseUrl;
            var ok = Uri.TryCreate(rawUrl, UriKind.Absolute, out baseUrl)
                     && (baseUrl.Scheme == Uri.UriSchemeHttps || baseUrl.IsLoopback);
            if (!ok)
            {
                throw new InvalidOperationException("E2E_BASE_URL must be an absolute https URL.");
            }

            return new E2ESettings
            {
                BaseUrl = baseUrl,
                Username = Require(config, "E2E_USERNAME"),
                Password = Require(config, "E2E_PASSWORD"),
                ExpectedDisplayName = config["E2E_EXPECTED_NAME"],
                Headed = string.Equals(config["E2E_HEADED"], "true", StringComparison.OrdinalIgnoreCase)
            };
        }

        private static string Require(IConfiguration config, string key)
        {
            var value = config[key];
            if (string.IsNullOrWhiteSpace(value))
            {
                // Names the missing key only. Never print values.
                throw new InvalidOperationException(
                    "Missing setting '" + key + "'. Set it with `dotnet user-secrets set " + key + " <value>` " +
                    "or as an environment variable (see README-E2E.md).");
            }
            return value.Trim();
        }
    }
}
