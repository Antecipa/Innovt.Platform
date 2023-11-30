using System.Diagnostics;

namespace Innovt.AspNetCore.Handlers
{
    public class ParentIdPropagationHandler : DelegatingHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var activity = Activity.Current;
            if (activity != null && request?.Headers != null)
            {
                string parentId = Activity.Current.ParentId;

                request.Headers.Add("X-ParentId", parentId);
            }
            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
    }
}