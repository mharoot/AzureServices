using System;
using System.Threading;
using System.Threading.Tasks;

namespace WEBNAME.Auth
{
    /// <summary>Talks to Entra ID. Abstracted so controllers can be unit-tested without the network.</summary>
    public interface IOidcClient
    {
        /// <summary>Builds the /authorize URL for a new sign-in attempt.</summary>
        Uri BuildAuthorizationUri(AuthFlowState flow);

        /// <summary>Exchanges the authorization code for a raw ID token (JWT).</summary>
        Task<string> RedeemAuthorizationCodeAsync(string code, string codeVerifier, CancellationToken cancellationToken);
    }
}
