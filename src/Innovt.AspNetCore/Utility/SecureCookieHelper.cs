using Microsoft.AspNetCore.Http;

namespace Innovt.AspNetCore.Utility
{
    public static class SecureCookieHelper
    {
        public static void SetSecureCookie(
            HttpResponse response,
            string name,
            string value,
            int expirationInSeconds = 3600,
            bool httpOnly = true,
            string domain = ".antecipa.com")
        {
            ArgumentNullException.ThrowIfNull(response);

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

            response.Cookies.Append($"{name}", value, cookieOptions);
        }

        public static void RemoveSecureCookie(
            HttpResponse response,
            string name,
            string domain = ".antecipa.com")
        {
            ArgumentNullException.ThrowIfNull(response);

            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = "/",
                Domain = domain,
                Expires = DateTime.UtcNow.AddDays(-1)
            };

            response.Cookies.Delete($"{name}", cookieOptions);
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