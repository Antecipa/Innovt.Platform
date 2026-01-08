// Innovt Company
// Author: Michel Borges
// Project: Innovt.AspNetCore

using Innovt.AspNetCore.Utility.Pagination;
using Innovt.Core.Exceptions;
using Innovt.Core.Utilities;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Localization;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Globalization;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

namespace Innovt.AspNetCore.Extensions;

/// <summary>
///     Extension methods for configuring MVC-related functionality.
/// </summary>
public static class MvcExtensions
{
    /// <summary>
    ///     Default Cultures are en, en-US, pt-BR
    /// </summary>
    /// <param name="app"></param>
    /// <param name="supportedCultures"></param>
    public static void UseRequestLocalization(this IApplicationBuilder app,
        IList<CultureInfo> supportedCultures = null!)
    {
        supportedCultures ??= new List<CultureInfo>
        {
            new("en"), new("en-US"), new("pt"), new("pt-BR")
        };

        app.UseRequestLocalization(new RequestLocalizationOptions
        {
            DefaultRequestCulture = new RequestCulture("pt-BR"),
            SupportedCultures = supportedCultures
        });
    }

    /// <summary>
    ///     Adds the application scope to the request headers.
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <param name="scope">The application scope.</param>
    /// <returns>The updated application builder.</returns>
    public static IApplicationBuilder UseApplicationScope(this IApplicationBuilder app, string scope)
    {
        if (scope.IsNullOrEmpty())
            return app;

        return app.Use(async (context, next) =>
        {
            context.Request.Headers.Add(Constants.HeaderApplicationScope, scope);
            await next().ConfigureAwait(false);
        });
    }

    /// <summary>
    ///     Sets the application context header in the request headers.
    /// </summary>
    /// <param name="app">The application builder.</param>
    /// <param name="headerContext">The header context value.</param>
    /// <returns>The updated application builder.</returns>
    public static IApplicationBuilder SetHeaderApplicationContext(this IApplicationBuilder app, string headerContext)
    {
        if (headerContext.IsNullOrEmpty())
            return app;

        return app.Use(async (context, next) =>
        {
            context.Request.Headers.Add(Constants.HeaderApplicationContext, headerContext);
            await next().ConfigureAwait(false);
        });
    }

    /// <summary>
    ///     Adds Bearer token authentication based on the provided configuration.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The configuration.</param>
    /// <param name="configSection">The configuration section name.</param>
    /// <param name="validateAudience">Whether to validate audience.</param>
    /// <param name="validateIssuer">Whether to validate issuer.</param>
    /// <param name="validateLifetime">Whether to validate lifetime.</param>
    /// <param name="validateIssuerSigningKey">Whether to validate issuer signing key.</param>
    public static void AddBearerAuthorization(
        this IServiceCollection services,
        IConfiguration configuration,
        string configSection = "BearerAuthentication",
        bool validateAudience = true,
        bool validateIssuer = true,
        bool validateLifetime = true,
        bool validateIssuerSigningKey = true,
        JwtBearerEvents jwtBearerEvents = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var audienceSection = configuration.GetSection($"{configSection}:Audience");
        var authoritySection = configuration.GetSection($"{configSection}:Authority");
        var audiences = configuration.GetSection($"{configSection}:ValidAudiences").Get<string[]>();

        if (audienceSection.Value == null)
            throw new CriticalException($"The Config Section '{configSection}:Audience' not defined.");
        if (authoritySection.Value == null)
            throw new CriticalException($"The Config Section '{configSection}:Authority' not defined.");

        services.AddBearerAuthorization(
            audienceSection.Value,
            authoritySection.Value,
            validateAudience: validateAudience,
            validateIssuer: validateIssuer,
            validateLifetime: validateLifetime,
            validateIssuerSigningKey: validateIssuerSigningKey,
            validAudiences: audiences,
            jwtBearerEvents: jwtBearerEvents);
    }

    /// <summary>
    ///     Adds Bearer token authentication with HttpOnly cookie support based on the provided configuration.
    ///     Tokens can be provided either via HttpOnly cookies or Authorization header (for backward compatibility).
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The configuration.</param>
    /// <param name="configSection">The configuration section name.</param>
    /// <param name="cookieName">The name of the cookie containing the access token (default: "access_token").</param>
    /// <param name="validateAudience">Whether to validate audience.</param>
    /// <param name="validateIssuer">Whether to validate issuer.</param>
    /// <param name="validateLifetime">Whether to validate lifetime.</param>
    /// <param name="validateIssuerSigningKey">Whether to validate issuer signing key.</param>
    /// <param name="jwtBearerEvents">Optional additional JWT Bearer events to merge with cookie authentication.</param>
    public static void AddCookieOrBearerAuthorization(
        this IServiceCollection services,
        IConfiguration configuration,
        string configSection = "BearerAuthentication",
        string cookieName = "access_token",
        bool validateAudience = true,
        bool validateIssuer = true,
        bool validateLifetime = true,
        bool validateIssuerSigningKey = true,
        JwtBearerEvents jwtBearerEvents = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var audienceSection = configuration.GetSection($"{configSection}:Audience");
        var authoritySection = configuration.GetSection($"{configSection}:Authority");
        var audiences = configuration.GetSection($"{configSection}:ValidAudiences").Get<string[]>();

        if (audienceSection.Value == null)
            throw new CriticalException($"The Config Section '{configSection}:Audience' not defined.");
        if (authoritySection.Value == null)
            throw new CriticalException($"The Config Section '{configSection}:Authority' not defined.");

        var jwtEvents = CreateCookieAwareJwtBearerEvents(cookieName, jwtBearerEvents, allowHeaderFallback: true);

        services.AddBearerAuthorization(
            audienceSection.Value,
            authoritySection.Value,
            validateAudience: validateAudience,
            validateIssuer: validateIssuer,
            validateLifetime: validateLifetime,
            validateIssuerSigningKey: validateIssuerSigningKey,
            validAudiences: audiences,
            jwtBearerEvents: jwtEvents);
    }

    /// <summary>
    ///     Adds Bearer token authentication with HttpOnly cookie support.
    ///     Tokens can be provided either via HttpOnly cookies or Authorization header (for backward compatibility).
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="audienceId">The audience ID.</param>
    /// <param name="authority">The authority.</param>
    /// <param name="cookieName">The name of the cookie containing the access token (default: "access_token").</param>
    /// <param name="validateAudience">Whether to validate audience.</param>
    /// <param name="validateIssuer">Whether to validate issuer.</param>
    /// <param name="validateLifetime">Whether to validate lifetime.</param>
    /// <param name="validateIssuerSigningKey">Whether to validate issuer signing key.</param>
    /// <param name="validAudiences">The valid token audiences if you want to validate it.</param>
    /// <param name="jwtBearerEvents">Optional additional JWT Bearer events to merge with cookie authentication.</param>
    public static void AddCookieOrBearerAuthorization(
        this IServiceCollection services,
        string audienceId,
        string authority,
        string cookieName = "access_token",
        bool validateAudience = true,
        bool validateIssuer = true,
        bool validateLifetime = true,
        bool validateIssuerSigningKey = true,
        string[]? validAudiences = null,
        JwtBearerEvents jwtBearerEvents = null)
    {
        var jwtEvents = CreateCookieAwareJwtBearerEvents(cookieName, jwtBearerEvents, allowHeaderFallback: true);

        services.AddBearerAuthorization(
            audienceId,
            authority,
            validateAudience,
            validateIssuer,
            validateLifetime,
            validateIssuerSigningKey,
            validAudiences,
            jwtEvents);
    }

    /// <summary>
    ///     Adds Bearer token authentication with ONLY HttpOnly cookie support based on the provided configuration.
    ///     Tokens MUST be provided via HttpOnly cookies. Authorization header is NOT supported.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The configuration.</param>
    /// <param name="configSection">The configuration section name.</param>
    /// <param name="cookieName">The name of the cookie containing the access token (default: "access_token").</param>
    /// <param name="validateAudience">Whether to validate audience.</param>
    /// <param name="validateIssuer">Whether to validate issuer.</param>
    /// <param name="validateLifetime">Whether to validate lifetime.</param>
    /// <param name="validateIssuerSigningKey">Whether to validate issuer signing key.</param>
    /// <param name="jwtBearerEvents">Optional additional JWT Bearer events to merge with cookie authentication.</param>
    public static void AddCookieAuthorization(
        this IServiceCollection services,
        IConfiguration configuration,
        string configSection = "BearerAuthentication",
        string cookieName = "access_token",
        bool validateAudience = true,
        bool validateIssuer = true,
        bool validateLifetime = true,
        bool validateIssuerSigningKey = true,
        JwtBearerEvents jwtBearerEvents = null)
    {
        ArgumentNullException.ThrowIfNull(configuration);

        var audienceSection = configuration.GetSection($"{configSection}:Audience");
        var authoritySection = configuration.GetSection($"{configSection}:Authority");
        var audiences = configuration.GetSection($"{configSection}:ValidAudiences").Get<string[]>();

        if (audienceSection.Value == null)
            throw new CriticalException($"The Config Section '{configSection}:Audience' not defined.");
        if (authoritySection.Value == null)
            throw new CriticalException($"The Config Section '{configSection}:Authority' not defined.");

        var jwtEvents = CreateCookieAwareJwtBearerEvents(cookieName, jwtBearerEvents, allowHeaderFallback: false);

        services.AddBearerAuthorization(
            audienceSection.Value,
            authoritySection.Value,
            validateAudience: validateAudience,
            validateIssuer: validateIssuer,
            validateLifetime: validateLifetime,
            validateIssuerSigningKey: validateIssuerSigningKey,
            validAudiences: audiences,
            jwtBearerEvents: jwtEvents);
    }

    /// <summary>
    ///     Adds Bearer token authentication with ONLY HttpOnly cookie support.
    ///     Tokens MUST be provided via HttpOnly cookies. Authorization header is NOT supported.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="audienceId">The audience ID.</param>
    /// <param name="authority">The authority.</param>
    /// <param name="cookieName">The name of the cookie containing the access token (default: "access_token").</param>
    /// <param name="validateAudience">Whether to validate audience.</param>
    /// <param name="validateIssuer">Whether to validate issuer.</param>
    /// <param name="validateLifetime">Whether to validate lifetime.</param>
    /// <param name="validateIssuerSigningKey">Whether to validate issuer signing key.</param>
    /// <param name="validAudiences">The valid token audiences if you want to validate it.</param>
    /// <param name="jwtBearerEvents">Optional additional JWT Bearer events to merge with cookie authentication.</param>
    public static void AddCookieAuthorization(
        this IServiceCollection services,
        string audienceId,
        string authority,
        string cookieName = "access_token",
        bool validateAudience = true,
        bool validateIssuer = true,
        bool validateLifetime = true,
        bool validateIssuerSigningKey = true,
        string[]? validAudiences = null,
        JwtBearerEvents jwtBearerEvents = null)
    {
        // Create JwtBearerEvents with ONLY cookie support (no header fallback)
        var jwtEvents = CreateCookieAwareJwtBearerEvents(cookieName, jwtBearerEvents, allowHeaderFallback: false);

        services.AddBearerAuthorization(
            audienceId,
            authority,
            validateAudience,
            validateIssuer,
            validateLifetime,
            validateIssuerSigningKey,
            validAudiences,
            jwtEvents);
    }

    /// <summary>
    ///     Creates a JwtBearerEvents instance that supports reading tokens from HttpOnly cookies.
    /// </summary>
    /// <param name="cookieName">The name of the cookie containing the access token.</param>
    /// <param name="baseEvents">Optional base events to extend. If provided, the OnMessageReceived will be merged.</param>
    /// <param name="allowHeaderFallback">If true, falls back to Authorization header when cookie is not present.</param>
    /// <returns>A configured JwtBearerEvents instance.</returns>
    private static JwtBearerEvents CreateCookieAwareJwtBearerEvents(
        string cookieName,
        JwtBearerEvents baseEvents = null,
        bool allowHeaderFallback = true)
    {
        var events = baseEvents ?? new JwtBearerEvents();

        // Store original OnMessageReceived if it exists
        var originalOnMessageReceived = events.OnMessageReceived;

        events.OnMessageReceived = async context =>
        {
            if (context.Request.Cookies.TryGetValue(cookieName, out var cookieToken) &&
                !string.IsNullOrWhiteSpace(cookieToken))
            {
                context.Token = cookieToken;
            }
            else if (allowHeaderFallback &&
                     context.Request.Headers.TryGetValue("Authorization", out var authHeader))
            {
                var auth = authHeader.ToString();
                if (auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    context.Token = auth.Substring("Bearer ".Length).Trim();
                }
            }

            if (originalOnMessageReceived != null)
            {
                await originalOnMessageReceived(context).ConfigureAwait(false);
            }
        };

        return events;
    }

    // ReSharper disable once MemberCanBePrivate.Global
    /// <summary>
    ///     Adds Bearer token authentication.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="audienceId">The audience ID.</param>
    /// <param name="authority">The authority.</param>
    /// <param name="validateAudience">Whether to validate audience.</param>
    /// <param name="validateIssuer">Whether to validate issuer.</param>
    /// <param name="validateLifetime">Whether to validate lifetime.</param>
    /// <param name="validateIssuerSigningKey">Whether to validate issuer signing key.</param>
    /// <param name="validAudiences">The valid token audiences if you want to validate it.</param>
    public static void AddBearerAuthorization(
        this IServiceCollection services,
        string audienceId,
        string authority,
        bool validateAudience = true,
        bool validateIssuer = true,
        bool validateLifetime = true,
        bool validateIssuerSigningKey = true,
        string[]? validAudiences = null,
        JwtBearerEvents jwtBearerEvents = null)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrEmpty(audienceId);
        ArgumentException.ThrowIfNullOrEmpty(authority);
        services.AddAuthorization(options =>
        {
            options.DefaultPolicy = new AuthorizationPolicyBuilder()
                .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
                .RequireAuthenticatedUser().Build();
        });

        if (validateAudience && (validAudiences == null || validAudiences.Length == 0) && !string.IsNullOrWhiteSpace(audienceId))
        {
            validAudiences ??= [];
            validAudiences = [.. validAudiences, audienceId];
        }

        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            options.Audience = audienceId;
            options.Authority = authority;
            options.RequireHttpsMetadata = false;
            options.IncludeErrorDetails = true;
            options.SaveToken = true;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = validateIssuerSigningKey,
                ValidateAudience = validateAudience,
                ValidAudiences = validAudiences,
                ValidateIssuer = validateIssuer,
                ValidIssuer = validateIssuer ? authority : null,
                ValidateLifetime = validateLifetime,
                AudienceValidator = validateAudience ? (audiences, securityToken, validationParameters) =>
                {
                    if (securityToken is JsonWebToken jwtToken)
                    {
                        try
                        {
                            if (jwtToken.TryGetClaim("aud", out var audClaim) && !string.IsNullOrEmpty(audClaim.Value))
                            {
                                return audClaim.Value == audienceId ||
                                        (validAudiences?.Contains(audClaim.Value) == true);
                            }

                            // Cognito AccessToken uses 'client_id' instead of 'aud'
                            if (jwtToken.TryGetClaim("client_id", out var clientIdClaim) && !string.IsNullOrEmpty(clientIdClaim.Value))
                            {
                                return clientIdClaim.Value == audienceId ||
                                        (validAudiences?.Contains(clientIdClaim.Value) == true);
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"Error validating audience: {ex.Message}");
                            return false;
                        }
                    }
                    return false;
                }
                : null
            };
            options.Events = jwtBearerEvents;
        });
    }

    /// <summary>
    ///     Generates an HTML pager for pagination.
    /// </summary>
    /// <typeparam name="T">The type of items being paginated.</typeparam>
    /// <param name="helper">The HTML helper.</param>
    /// <param name="builder">The pagination builder.</param>
    /// <returns>The HTML pager content.</returns>
    public static IHtmlContent Pager<T>(this IHtmlHelper helper, PaginationBuilder<T> builder) where T : class
    {
        ArgumentNullException.ThrowIfNull(helper);
        ArgumentNullException.ThrowIfNull(builder);

        if (builder.Collection.TotalRecords < builder.Collection.PageSize &&
            builder.Collection.IsNumberPagination && builder.Collection.Page != null && int.Parse(
                builder.Collection.Page,
                CultureInfo.InvariantCulture) <= 1)
            return new HtmlString(string.Empty);

        var html = new StringBuilder();

        html.Append(builder.BuildHeader());

        if (builder.Collection.HasPrevious()) html.Append(builder.BuildPrevious());

        if (builder.Collection.PageCount > 1)
            for (var i = 0; i <= builder.Collection.PageCount - 1; i++)
            {
                var isCurrent = builder.Collection.Page == i.ToString(CultureInfo.InvariantCulture);

                html.Append(builder.BuildItem(i, isCurrent));
            }

        if (builder.Collection.HasNext()) html.Append(builder.BuildNext());

        html.Append(builder.BuildFooter());

        html.Append(builder.BuildPagerScript());

        return new HtmlString(html.ToString());
    }

    /// <summary>
    ///     Creates a select list containing "Ativo" and "Inativo" items.
    /// </summary>
    /// <returns>The select list.</returns>
    public static SelectList ActiveAndInactiveList()
    {
        var statusList = new List<SelectListItem>
        {
            new() { Value = "1", Text = "Ativo" },
            new() { Value = "0", Text = "Inativo" }
        };

        return new SelectList(statusList, "Value", "Text");
    }

    /// <summary>
    ///     Creates a select list containing "Sim" and "Não" items.
    /// </summary>
    /// <returns>The select list.</returns>
    public static SelectList YesAndNoList()
    {
        var statusList = new List<SelectListItem>
        {
            new() { Value = "1", Text = "Sim" },
            new() { Value = "0", Text = "Não" }
        };

        return new SelectList(statusList, "Value", "Text");
    }

    /// <summary>
    ///     Gets the value of a claim from the user's claims principal.
    /// </summary>
    /// <param name="user">The claims principal.</param>
    /// <param name="type">The claim type (default is ClaimTypes.Email).</param>
    /// <returns>The claim value or an empty string if not found.</returns>
    public static string GetClaim(this ClaimsPrincipal user, string type = ClaimTypes.Email)
    {
        if (user is null)
            return string.Empty;

        var value = (from c in user.Claims
                     where c.Type == type
                     select c.Value).FirstOrDefault();

        return value ?? string.Empty;
    }

    /// <summary>
    ///     Checks if the specified action descriptor has a filter of the given type.
    /// </summary>
    /// <param name="action">The action descriptor.</param>
    /// <param name="filter">The type of filter to check for.</param>
    /// <returns>True if the action has the filter, otherwise false.</returns>
    public static bool HasFilter(this ActionDescriptor action, Type filter)
    {
        if (action == null || filter == null)
            return false;

        var exist = action.FilterDescriptors.Any(f => f.Filter.GetType() == filter);

        return exist;
    }

    /// <summary>
    ///     Check if the request is local (Code from Web)
    /// </summary>
    /// <param name="context">The current context</param>
    /// <returns></returns>
    public static bool IsLocal(this HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var remoteIp = context.Connection?.RemoteIpAddress;
        var localIp = context.Connection?.LocalIpAddress;

        if (remoteIp == null && localIp == null) return true;

        if (remoteIp != null)
        {
            if (localIp != null)
                return remoteIp.Equals(localIp);
            return IPAddress.IsLoopback(remoteIp);
        }

        return false;
    }

    /// <summary>
    ///     Sets an object in the session after serializing it to JSON.
    /// </summary>
    /// <typeparam name="T">The type of the object to be stored.</typeparam>
    /// <param name="session">The session object.</param>
    /// <param name="key">The key to store the object under.</param>
    /// <param name="value">The object to be stored.</param>
    public static void Set<T>(this ISession session, string key, T value)
    {
        session?.SetString(key, JsonSerializer.Serialize(value));
    }

    /// <summary>
    ///     Gets an object from the session and deserializes it from JSON.
    /// </summary>
    /// <typeparam name="T">The type of the object to be retrieved.</typeparam>
    /// <param name="session">The session object.</param>
    /// <param name="key">The key the object was stored under.</param>
    /// <returns>The deserialized object.</returns>
    public static T Get<T>(this ISession session, string key)
    {
        var value = session?.GetString(key);

        return value == null ? default : JsonSerializer.Deserialize<T>(value);
    }
}