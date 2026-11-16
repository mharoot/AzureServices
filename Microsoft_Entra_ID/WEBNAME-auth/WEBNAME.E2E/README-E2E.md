# E2E login test (Selenium + C#)

Drives real Chrome against the **deployed dev/test site** and signs in through the real Microsoft
login page. It fails if the client id, tenant, client secret, redirect URI registration or token
validation is wrong. Run it after each deployment, not on every commit.

## One-time setup

1. **Create a dedicated test user** in the dev tenant (e.g. `e2e-test@yourtenant.onmicrosoft.com`).
   Least privilege, not a real person, strong generated password, owned by the team.
2. **MFA:** the browser can't answer an MFA prompt. Ask your Entra admin to exclude this one account
   from MFA via a Conditional Access policy (restrict it to your CI/office IPs if possible), or extend
   the page object with TOTP.
3. Install Chrome on the machine that runs the tests.

## Where the credentials go (never in the repo)

Local machine, stored in your user profile outside the repo:

```
cd WEBNAME.E2E
dotnet user-secrets set E2E_BASE_URL  "https://webname-dev.com/"
dotnet user-secrets set E2E_USERNAME  "e2e-test@yourtenant.onmicrosoft.com"
dotnet user-secrets set E2E_PASSWORD  "<password>"
dotnet user-secrets set E2E_EXPECTED_NAME "Test User"     # optional: name shown on the home page
```

(user-secrets is plain text on your disk: fine for a low-privilege test account, not for real credentials.)

Or as environment variables (what CI uses): `E2E_BASE_URL`, `E2E_USERNAME`, `E2E_PASSWORD`,
`E2E_EXPECTED_NAME`. Set `E2E_HEADED=true` to watch the browser.

## Run

```
dotnet test WEBNAME.E2E
```

On failure a screenshot is written to `WEBNAME.E2E/bin/.../artifacts/`.

## CI example (GitHub Actions)

Store the three values under *Settings -> Secrets and variables -> Actions*. Secrets are masked in logs.

```yaml
name: e2e-dev
on:
  workflow_dispatch:
  workflow_run: { workflows: ["deploy-dev"], types: [completed] }
jobs:
  e2e:
    runs-on: ubuntu-latest        # Chrome is preinstalled; use a self-hosted runner if dev is behind a VPN/IP allowlist
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-dotnet@v4
        with: { dotnet-version: 8.0.x }
      - run: dotnet test WEBNAME.E2E
        env:
          E2E_BASE_URL: ${{ vars.E2E_BASE_URL }}
          E2E_USERNAME: ${{ secrets.E2E_USERNAME }}
          E2E_PASSWORD: ${{ secrets.E2E_PASSWORD }}
      - uses: actions/upload-artifact@v4
        if: failure()
        with: { name: e2e-screenshots, path: "**/artifacts/*.png" }
```

## Notes

- **Reading a failure:** "OUR callback returned an error" with a `ref` id means Microsoft accepted the
  login but the server failed afterwards, usually a wrong `AZURE_CLIENT_SECRET` (`invalid_client`) or a
  redirect URI mismatch. Search the server log for that `ref`.
- **Deliberately no "wrong password" test:** repeated bad logins trigger Entra smart lockout and would
  lock the test account, breaking every later run.
- **Maintenance:** Microsoft owns the login page. If it changes, only `EntraLoginPage.cs` needs updating.
- Add to `.gitignore`: `artifacts/` and `secrets.json`.
- The test assumes the `/api/Signin` endpoint and the `ASP.NET_SessionId` cookie from the earlier code.
- This project has not been compiled or run (no .NET SDK or NuGet access in my environment), so expect to
  tweak selectors or package versions on first run.
