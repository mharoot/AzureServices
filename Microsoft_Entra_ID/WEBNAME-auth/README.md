# Entra ID sign-in: hardened version

## What changed vs. the original

| Original issue | Fix |
|---|---|
| No `state` validation (CSRF / login-CSRF) | `/api/Signin` issues `state`, `nonce` and a PKCE verifier into a `__Host-` HttpOnly, Secure, SameSite=Lax cookie. The callback verifies state (constant-time) before redeeming the code. Cookie is single-use. |
| ID token only *parsed* (`ReadJwtToken`), never validated | `IdTokenValidator` checks signature (tenant JWKS, auto-refreshed), issuer, audience, lifetime, RS256 only, and `nonce`. |
| `HttpContext.Current.Session` is null in Web API, so a `NullReferenceException` was returned to the user | Wrapped in `IUserSessionStore`; fails with a clear message if session isn't enabled. Enable it with the Global.asax step below. |
| App-pool-name if/else ladders; unknown pool silently fell through to **production** URLs | Redirect URIs come from app settings (`AZURE_REDIRECT_URI`, `AZURE_POST_LOGIN_URI`), validated at startup: absolute, https (http only on localhost), same host. Per-environment values via Web.config transforms. |
| `ex.Message` returned to the browser | Generic message + support reference id; full exception goes to the log. Proper 400/401/403/500/503 codes. |
| MSAL app rebuilt on every request | Singleton `MsalOidcClient`; token cache entry removed after use so memory doesn't grow per user. |
| Missing `given_name`/`family_name` gave `" "` or `"null null"`-style names | Falls back to `name`, then email. |
| Unvalidated `error=` / `error_description` from query string | Handled (user cancel/consent denied → 401); values sanitized before logging (no log forging). |
| Responses cacheable | `Cache-Control: no-store` on every response. |
| Hard to test | Everything behind interfaces; 40+ unit tests. |

## Files

```
WEBNAME/Auth/            settings, flow state, MSAL client, token validator, session store, logger
WEBNAME/Controllers/     SigninController (start), SigninRedirectCallbackController (finish)
WEBNAME.Tests/           xUnit tests
```

## Required setup

**1. NuGet packages (web project):** `Microsoft.Identity.Client` 4.66+, `System.IdentityModel.Tokens.Jwt` 6.35,
`Microsoft.IdentityModel.Protocols.OpenIdConnect` 6.35, `Microsoft.AspNet.WebApi.Core` 5.2.9.
Target .NET Framework 4.7.2+ (4.8 recommended).

**2. Web.config**

```xml
<appSettings>
  <add key="AZURE_CLIENT_ID" value="..." />
  <add key="AZURE_TENANT_ID" value="..." />            <!-- a specific tenant GUID/domain, not "common" -->
  <add key="AZURE_CLIENT_SECRET" value="..." />        <!-- see "Secrets" below -->
  <add key="AZURE_REDIRECT_URI" value="https://webname.com/api/SigninRedirectCallback" />
  <add key="AZURE_POST_LOGIN_URI" value="https://webname.com/index.aspx" />
</appSettings>
<system.web>
  <httpRuntime targetFramework="4.8" />   <!-- required so HttpContext survives `await` -->
  <httpCookies httpOnlyCookies="true" requireSSL="true" />
</system.web>
```
Use `Web.Debug.config` / `Web.Test.config` / `Web.Release.config` `xdt:Transform="SetAttributes"` to override the two URIs per environment. Local: `https://localhost:44300/...`.

**3. Global.asax.cs** (session isn't available to Web API unless you opt in; this is what fixes the original `Session` NRE):

```csharp
protected void Application_PostAuthorizeRequest()
{
    var path = HttpContext.Current.Request.AppRelativeCurrentExecutionFilePath;
    if (path.StartsWith("~/api/SigninRedirectCallback", StringComparison.OrdinalIgnoreCase))
    {
        HttpContext.Current.SetSessionStateBehavior(System.Web.SessionState.SessionStateBehavior.Required);
    }
}
```

**4. Point your "Sign in" link at `/api/Signin`.** Whatever previously sent users straight to
`login.microsoftonline.com` must now go through this endpoint, otherwise there is no state cookie
and the callback will (correctly) reject the login.

**5. Entra app registration:** redirect URIs must match `AZURE_REDIRECT_URI` exactly (scheme, host, path, no trailing slash difference).
To get `given_name` / `family_name` / `email`, add them under *Token configuration → Add optional claim → ID*.

## Follow-ups worth scheduling (not changed here)

- **Secrets:** don't keep `AZURE_CLIENT_SECRET` in plain Web.config. Use Azure Key Vault / App Service settings / encrypted config section, or switch to a certificate credential (`WithCertificate`) and rotate regularly.
- **Authorize on `ObjectId` (`oid`) + `TenantId`, not email.** Email/preferred_username can change or be reassigned. Both are now stored in session.
- **Session fixation:** classic ASP.NET doesn't rotate the session id on login. If your threat model needs it, regenerate via `SessionIDManager` or move to OWIN cookie auth / Forms auth ticket.
- Consider replacing the hand-rolled flow with `Microsoft.Identity.Web`/OWIN OpenID Connect middleware if you can touch the pipeline.
- The code was written without a .NET SDK available, so it has **not been compiled or run**; first step is `dotnet test` / Test Explorer in Visual Studio.
