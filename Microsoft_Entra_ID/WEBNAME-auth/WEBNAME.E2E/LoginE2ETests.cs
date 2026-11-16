using System;
using System.IO;
using OpenQA.Selenium;
using OpenQA.Selenium.Chrome;
using Xunit;

namespace WEBNAME.E2E
{
    /// <summary>
    /// Proves the REAL Entra ID setup works end to end: client id / tenant / client secret /
    /// redirect URI registration / token validation / session creation.
    /// Run against a deployed dev or test site, not in the per-commit unit-test stage.
    /// </summary>
    public sealed class LoginE2ETests : IDisposable
    {
        private readonly E2ESettings _settings = E2ESettings.Load();
        private readonly IWebDriver _driver;

        public LoginE2ETests()
        {
            var options = new ChromeOptions();
            if (!_settings.Headed) options.AddArgument("--headless=new");
            options.AddArgument("--window-size=1280,900");
            options.AddArgument("--incognito"); // always start with no Microsoft SSO session

            // Selenium Manager (built into Selenium 4.6+) downloads the matching chromedriver automatically.
            _driver = new ChromeDriver(options);
        }

        public void Dispose() => _driver.Quit();

        [Fact]
        public void Test_user_can_sign_in_and_reach_the_home_page()
        {
            RunWithScreenshotOnFailure(nameof(Test_user_can_sign_in_and_reach_the_home_page), () =>
            {
                // Start where a user's "Sign in" link goes. If your login button has a stable id, you can
                // instead open the home page and click it: _driver.FindElement(By.Id("signin")).Click();
                _driver.Navigate().GoToUrl(new Uri(_settings.BaseUrl, "api/Signin"));

                new EntraLoginPage(_driver, _settings.BaseUrl)
                    .SignInAndReturnToSite(_settings.Username, _settings.Password);

                // Landed on the configured post-login page.
                Assert.EndsWith("/index.aspx", new Uri(_driver.Url).AbsolutePath, StringComparison.OrdinalIgnoreCase);

                // Session cookie issued and the one-time flow cookie consumed.
                Assert.NotNull(_driver.Manage().Cookies.GetCookieNamed("ASP.NET_SessionId"));
                Assert.Null(_driver.Manage().Cookies.GetCookieNamed("__Host-oidc-flow"));

                // The session carries the right identity (only checked if you provide the expected name).
                if (!string.IsNullOrWhiteSpace(_settings.ExpectedDisplayName))
                {
                    Assert.Contains(_settings.ExpectedDisplayName, _driver.PageSource);
                }
            });
        }

        [Fact]
        public void Callback_without_a_login_attempt_is_rejected_safely()
        {
            RunWithScreenshotOnFailure(nameof(Callback_without_a_login_attempt_is_rejected_safely), () =>
            {
                // A forged callback: no flow cookie, made-up code/state. Must be refused before any token exchange.
                _driver.Navigate().GoToUrl(new Uri(_settings.BaseUrl, "api/SigninRedirectCallback?code=forged&state=forged"));

                var page = _driver.PageSource;
                Assert.Contains("expired or is invalid", page);
                Assert.DoesNotContain("Exception", page);   // no stack traces
                Assert.DoesNotContain("   at ", page);
            });
        }

        // On failure, save a screenshot so you can see what the browser saw (CI can upload ./artifacts).
        private void RunWithScreenshotOnFailure(string testName, Action body)
        {
            try
            {
                body();
            }
            catch
            {
                try
                {
                    Directory.CreateDirectory("artifacts");
                    ((ITakesScreenshot)_driver).GetScreenshot()
                        .SaveAsFile(Path.Combine("artifacts", testName + ".png"));
                }
                catch (Exception) { /* never mask the real failure */ }
                throw;
            }
        }
    }
}
