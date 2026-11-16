using System;
using System.Diagnostics;
using System.Web;

namespace WEBNAME.Auth
{
    public interface IUserSessionStore
    {
        void SignIn(AuthenticatedUser user);
    }

    /// <summary>
    /// Writes the user into ASP.NET session using the same keys the rest of the site already
    /// reads (Email, Name, DisplayName). Session is NOT available to Web API by default; see
    /// README.md (Global.asax step) for enabling it on the callback route.
    /// </summary>
    public sealed class HttpSessionUserStore : IUserSessionStore
    {
        public void SignIn(AuthenticatedUser user)
        {
            if (user == null) throw new ArgumentNullException(nameof(user));

            var session = HttpContext.Current?.Session;
            if (session == null)
            {
                throw new InvalidOperationException(
                    "ASP.NET session state is not available for this request. " +
                    "Enable it for the sign-in callback route (see README: Global.asax).");
            }

            // Drop anything left over from a previous user of this session.
            session.Clear();
            session["Email"] = user.Email;
            session["Name"] = user.Name;
            session["DisplayName"] = user.DisplayName;
            session["ObjectId"] = user.ObjectId;
            session["TenantId"] = user.TenantId;
        }
    }

    public interface IAuthLogger
    {
        void Info(string message);
        void Warn(string message);
        void Error(string message, Exception exception);
    }

    /// <summary>Routes to System.Diagnostics.Trace so any configured listener (file, App Insights, ETW) receives it.</summary>
    public sealed class TraceAuthLogger : IAuthLogger
    {
        public void Info(string message) => Trace.TraceInformation("[Auth] " + message);
        public void Warn(string message) => Trace.TraceWarning("[Auth] " + message);
        public void Error(string message, Exception exception) =>
            Trace.TraceError("[Auth] " + message + (exception == null ? "" : Environment.NewLine + exception));
    }
}
