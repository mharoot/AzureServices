using System;
using System.Linq;
using OpenQA.Selenium;
using OpenQA.Selenium.Support.UI;

namespace WEBNAME.E2E
{
    /// <summary>
    /// Page object for the Microsoft sign-in pages plus the return trip to our site.
    /// Microsoft owns these pages and changes them occasionally; if the E2E test starts failing
    /// at the login form, the selectors below are the first thing to check.
    /// </summary>
    public sealed class EntraLoginPage
    {
        private static readonly TimeSpan StepTimeout = TimeSpan.FromSeconds(30);

        private readonly IWebDriver _driver;
        private readonly Uri _baseUrl;
        private readonly WebDriverWait _wait;

        public EntraLoginPage(IWebDriver driver, Uri baseUrl)
        {
            _driver = driver;
            _baseUrl = baseUrl;
            _wait = new WebDriverWait(driver, StepTimeout) { PollingInterval = TimeSpan.FromMilliseconds(250) };
        }

        /// <summary>Completes the Microsoft login and returns once the browser is back on our site.</summary>
        public void SignInAndReturnToSite(string username, string password)
        {
            // Step 1: username
            var user = WaitForVisible(By.Name("loginfmt"));
            user.Clear();
            user.SendKeys(username);
            ClickPrimaryButton();

            // Step 2: password (waiting for the field first avoids double-clicking the shared "Next" button)
            var pass = WaitForVisible(By.Name("passwd"));
            pass.SendKeys(password);
            ClickPrimaryButton();

            // Step 3: "Stay signed in?" may or may not appear, then Microsoft redirects to our callback.
            WaitForReturnToSite();
        }

        private IWebElement WaitForVisible(By by) =>
            _wait.Until(d =>
            {
                ThrowIfMicrosoftRejectedUs();
                var found = d.FindElements(by).FirstOrDefault(e => e.Displayed && e.Enabled);
                return found;
            });

        private void ClickPrimaryButton()
        {
            // idSIButton9 is the blue Next / Sign in / Yes button on every step.
            var button = _wait.Until(d =>
                d.FindElements(By.Id("idSIButton9")).FirstOrDefault(e => e.Displayed && e.Enabled));
            button.Click();
        }

        private void WaitForReturnToSite()
        {
            var deadline = DateTime.UtcNow + StepTimeout + StepTimeout;
            while (DateTime.UtcNow < deadline)
            {
                if (string.Equals(new Uri(_driver.Url).Host, _baseUrl.Host, StringComparison.OrdinalIgnoreCase))
                {
                    // Back on our host. Normally the callback has already redirected to the home page.
                    // If we are still sitting on the callback URL, it rendered an error page.
                    if (!IsOnCallback()) return;

                    System.Threading.Thread.Sleep(1500); // let a pending redirect finish
                    if (!IsOnCallback()) return;

                    throw new Exception(
                        "Microsoft login succeeded, but OUR callback returned an error. " +
                        "Likely causes: wrong AZURE_CLIENT_SECRET, redirect URI mismatch, or invalid token. " +
                        "Page said: " + BodyText() + " (use the 'ref' id to find the server log entry)");
                }

                ThrowIfMicrosoftRejectedUs();
                DismissStaySignedInPrompt();
                System.Threading.Thread.Sleep(250);
            }

            throw new TimeoutException(
                "Did not return to the site. Stuck at: " + _driver.Url + " | title: '" + _driver.Title + "'. " +
                "If this is an MFA / 'verify your identity' page, exclude the test account from MFA " +
                "(Conditional Access) or add TOTP support.");
        }

        private bool IsOnCallback() =>
            _driver.Url.IndexOf("SigninRedirectCallback", StringComparison.OrdinalIgnoreCase) >= 0;

        private void DismissStaySignedInPrompt()
        {
            // "No" button on the "Stay signed in?" screen. Absent on most other screens.
            var no = _driver.FindElements(By.Id("idBtn_Back")).FirstOrDefault(e => e.Displayed && e.Enabled);
            no?.Click();
        }

        private void ThrowIfMicrosoftRejectedUs()
        {
            foreach (var id in new[] { "usernameError", "passwordError" })
            {
                var error = _driver.FindElements(By.Id(id)).FirstOrDefault(e => e.Displayed);
                if (error != null)
                {
                    // Do not retry: repeated bad passwords trigger smart lockout on the test account.
                    throw new Exception("Microsoft rejected the test account credentials: " + error.Text);
                }
            }
        }

        private string BodyText()
        {
            try { return _driver.FindElement(By.TagName("body")).Text; }
            catch (WebDriverException) { return "(unreadable)"; }
        }
    }
}
