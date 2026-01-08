using Microsoft.AspNetCore.Http;

namespace Innovt.AspNetCore.Utility
{
    public static class SecureCookieHelper
    {
        public static void SetSecureCookie(
            HttpResponse response,
            string cookieName,
            string value,
            string domain,
            int expirationInSeconds = 3600,
            bool httpOnly = true
            )
        {
            ArgumentNullException.ThrowIfNull(response);
            if (string.IsNullOrWhiteSpace(domain)) throw new ArgumentNullException(nameof(domain));
            if (string.IsNullOrWhiteSpace(cookieName)) throw new ArgumentNullException(nameof(cookieName));

            var cookieOptions = new CookieOptions
            {
                HttpOnly = httpOnly,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = "/",
                Domain = domain,
                Expires = DateTime.UtcNow.AddSeconds(expirationInSeconds),
                IsEssential = true
            };

            response.Cookies.Append($"{cookieName}", value, cookieOptions);
        }

        public static void RemoveSecureCookie(
            HttpResponse response,
            string cookieName,
            string domain)
        {
            ArgumentNullException.ThrowIfNull(response);
            if (string.IsNullOrWhiteSpace(domain)) throw new ArgumentNullException(nameof(domain));
            if (string.IsNullOrWhiteSpace(cookieName)) throw new ArgumentNullException(nameof(cookieName));

            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = "/",
                Domain = domain,
                Expires = DateTime.UtcNow.AddDays(-1)
            };

            response.Cookies.Delete($"{cookieName}", cookieOptions);
        }

        public static string GetCookie(HttpRequest request, string name)
        {
            ArgumentNullException.ThrowIfNull(request);

            if (request.Cookies.TryGetValue($"{name}", out var value))
                return value;
            return null;
        }
    }
}