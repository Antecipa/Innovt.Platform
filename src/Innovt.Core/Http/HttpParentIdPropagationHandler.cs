using System.Diagnostics;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Innovt.Core.Http
{
    public class HttpParentIdPropagationHandler : DelegatingHandler
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