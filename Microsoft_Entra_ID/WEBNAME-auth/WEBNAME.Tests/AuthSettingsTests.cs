using System.Collections.Specialized;
using System.Configuration;
using WEBNAME.Auth;
using Xunit;

namespace WEBNAME.Tests
{
    public class AuthSettingsTests
    {
        private static NameValueCollection Valid() => new NameValueCollection
        {
            { AuthSettings.ClientIdKey, TestData.ClientId },
            { AuthSettings.TenantIdKey, TestData.TenantId },
            { AuthSettings.ClientSecretKey, "secret" },
            { AuthSettings.RedirectUriKey, "https://app.example.com/api/SigninRedirectCallback" },
            { AuthSettings.PostLoginUriKey, "https://app.example.com/index.aspx" }
        };

        [Fact]
        public void Loads_valid_settings()
        {
            var s = AuthSettings.FromAppSettings(Valid());

            Assert.Equal(TestData.ClientId, s.ClientId);
            Assert.Equal("https://login.microsoftonline.com/" + TestData.TenantId, s.Authority);
            Assert.EndsWith("/v2.0/.well-known/openid-configuration", s.MetadataAddress);
            Assert.Equal("https://app.example.com/index.aspx", s.PostLoginRedirectUri.AbsoluteUri);
        }

        [Theory]
        [InlineData(AuthSettings.ClientIdKey)]
        [InlineData(AuthSettings.TenantIdKey)]
        [InlineData(AuthSettings.ClientSecretKey)]
        [InlineData(AuthSettings.RedirectUriKey)]
        [InlineData(AuthSettings.PostLoginUriKey)]
        public void Missing_setting_throws_and_names_the_key(string key)
        {
            var settings = Valid();
            settings.Remove(key);

            var ex = Assert.Throws<ConfigurationErrorsException>(() => AuthSettings.FromAppSettings(settings));
            Assert.Contains(key, ex.Message);
        }

        [Fact]
        public void Error_messages_never_contain_the_secret()
        {
            var settings = Valid();
            settings[AuthSettings.ClientSecretKey] = "TOP-SECRET-VALUE";
            settings[AuthSettings.RedirectUriKey] = "not a uri";

            var ex = Assert.Throws<ConfigurationErrorsException>(() => AuthSettings.FromAppSettings(settings));
            Assert.DoesNotContain("TOP-SECRET-VALUE", ex.Message);
        }

        [Theory]
        [InlineData("common")]
        [InlineData("Organizations")]
        [InlineData("consumers")]
        [InlineData("evil.com/path")]
        [InlineData("tenant?x=y")]
        public void Rejects_multi_tenant_or_malformed_tenant(string tenant)
        {
            var settings = Valid();
            settings[AuthSettings.TenantIdKey] = tenant;
            Assert.Throws<ConfigurationErrorsException>(() => AuthSettings.FromAppSettings(settings));
        }

        [Fact]
        public void Rejects_plain_http_for_non_loopback_hosts()
        {
            var settings = Valid();
            settings[AuthSettings.RedirectUriKey] = "http://app.example.com/api/SigninRedirectCallback";
            settings[AuthSettings.PostLoginUriKey] = "http://app.example.com/index.aspx";
            Assert.Throws<ConfigurationErrorsException>(() => AuthSettings.FromAppSettings(settings));
        }

        [Fact]
        public void Allows_http_for_localhost()
        {
            var settings = Valid();
            settings[AuthSettings.RedirectUriKey] = "http://localhost:44300/api/SigninRedirectCallback";
            settings[AuthSettings.PostLoginUriKey] = "http://localhost:44300/index.aspx";
            Assert.NotNull(AuthSettings.FromAppSettings(settings));
        }

        [Fact]
        public void Rejects_post_login_uri_on_a_different_host()
        {
            var settings = Valid();
            settings[AuthSettings.PostLoginUriKey] = "https://evil.example.net/index.aspx";
            Assert.Throws<ConfigurationErrorsException>(() => AuthSettings.FromAppSettings(settings));
        }

        [Fact]
        public void Rejects_relative_uris()
        {
            var settings = Valid();
            settings[AuthSettings.PostLoginUriKey] = "/index.aspx";
            Assert.Throws<ConfigurationErrorsException>(() => AuthSettings.FromAppSettings(settings));
        }
    }
}
