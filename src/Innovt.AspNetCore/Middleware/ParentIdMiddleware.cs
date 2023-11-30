using Microsoft.AspNetCore.Http;
using System.Diagnostics;

namespace Innovt.AspNetCore.Middleware
{
    public class ParentIdMiddleware
    {
        private readonly RequestDelegate _next;

        public ParentIdMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (context?.Request?.Headers != null && context.Request.Headers.TryGetValue("X-ParentId", out var parentId))
            {
                Activity activity = null;
                var currentActivity = Activity.Current;
                if (currentActivity != null)
                {
                    activity = new Activity(currentActivity.DisplayName);
                }

                activity ??= new Activity("Innovt.AspNetCore");
                activity.SetParentId(parentId);
                activity.SetIdFormat(ActivityIdFormat.W3C);
                activity.Start();
            }

            await _next(context).ConfigureAwait(false);
        }
    }
}