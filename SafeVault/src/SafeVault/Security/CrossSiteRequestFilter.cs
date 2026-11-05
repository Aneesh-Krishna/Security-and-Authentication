namespace SafeVault.Security;

/// <summary>
/// Blocks state-changing requests (POST, PUT, PATCH, DELETE) that the browser reports as coming
/// from another site. This protects every form against CSRF, including login and registration,
/// which are static pages and so can't carry an anti-forgery token.
/// </summary>
public static class CrossSiteRequestFilter
{
    public static IApplicationBuilder UseCrossSiteRequestFilter(this IApplicationBuilder app) =>
        app.Use(async (context, next) =>
        {
            if (IsStateChanging(context.Request.Method) && IsCrossSite(context.Request))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsync("Cross-site request blocked.");
                return;
            }

            await next();
        });

    private static bool IsStateChanging(string method) =>
        !(HttpMethods.IsGet(method) || HttpMethods.IsHead(method) || HttpMethods.IsOptions(method));

    private static bool IsCrossSite(HttpRequest request)
    {
        // Modern browsers say exactly where a request came from (Fetch Metadata).
        // "none" means the user started it themselves (address bar, bookmark).
        var fetchSite = request.Headers["Sec-Fetch-Site"].ToString();
        if (fetchSite.Length > 0)
            return fetchSite is not ("same-origin" or "none");

        // Older browsers: compare the Origin header with this site's own origin.
        var origin = request.Headers.Origin.ToString();
        if (origin.Length > 0)
            return !string.Equals(origin, $"{request.Scheme}://{request.Host}", StringComparison.OrdinalIgnoreCase);

        // Browsers always send at least one of these headers on a cross-site POST, so a request with
        // neither comes from a non-browser client (curl, scripts, tests), where CSRF doesn't apply.
        return false;
    }
}
