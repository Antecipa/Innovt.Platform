// Innovt Company
// Author: Michel Borges
// Project: Innovt.Cloud.AWS.Kinesis

using Amazon.Kinesis;
using Amazon.Kinesis.Model;
using Innovt.Cloud.AWS.Configuration;
using Innovt.Core.CrossCutting.Log;
using Innovt.Core.Utilities;
using Innovt.Domain.Core.Streams;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace Innovt.Cloud.AWS.Kinesis;

public class DataProducer<T> : AwsBaseService where T : class, IDataStream
{
    protected static readonly ActivitySource ActivityDataProducer = new("Innovt.Cloud.AWS.KinesisDataProducer");
    private AmazonKinesisClient kinesisClient;

    protected DataProducer(string busName, ILogger logger, IAwsConfiguration configuration) : base(logger,
        configuration)
    {
        BusName = busName ?? throw new ArgumentNullException(nameof(busName));
    }

    protected DataProducer(string busName, ILogger logger, IAwsConfiguration configuration,
        string region) : base(logger, configuration, region)
    {
        BusName = busName ?? throw new ArgumentNullException(nameof(busName));
    }

    private string BusName { get; }

    private AmazonKinesisClient KinesisClient
    {
        get { return kinesisClient ??= CreateService<AmazonKinesisClient>(); }
    }

    public async Task Publish(T data, CancellationToken cancellationToken = default)
    {
        await InternalPublish(data, cancellationToken).ConfigureAwait(false);
    }

    public async Task Publish(IEnumerable<T> events, CancellationToken cancellationToken = default)
    {
        await InternalPublish(events, cancellationToken).ConfigureAwait(false);
    }

    private static List<PutRecordsRequestEntry> CreatePutRecords(IList<T> dataStreams, Activity activity)
    {
        if (dataStreams == null)
            return null;

        var request = new List<PutRecordsRequestEntry>();

        foreach (var data in dataStreams)
        {
            if (data.TraceId.IsNullOrEmpty() && activity != null)
            {
                data.TraceId = activity.Id.ToString();
                data.ParentId = activity.ParentId;
            }

            data.PublishedAt = DateTimeOffset.UtcNow;

            var dataAsBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize<object>(data));

            using (var ms = new MemoryStream(dataAsBytes))
            {
                request.Add(new PutRecordsRequestEntry
                {
                    Data = ms,
                    PartitionKey = data.Partition
                });
            }
        }

        return request;
    }

    private static PutRecordRequest CreatePutRecordRequest(T data, Activity activity)
    {
        if (data == null)
            return null;

        if (data.TraceId.IsNullOrEmpty() && activity != null)
        {
            data.TraceId = activity.Id.ToString();
            data.ParentId = activity.ParentId;
        }

        data.PublishedAt = DateTimeOffset.UtcNow;

        PutRecordRequest request;

        var dataAsBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize<object>(data));

        using (var ms = new MemoryStream(dataAsBytes))
        {
            request = new PutRecordRequest
            {
                PartitionKey = data.Partition,
                Data = ms,
            };
        }

        return request;
    }

    private async Task InternalPublish(IEnumerable<T> dataList, CancellationToken cancellationToken = default)
    {
        if (dataList is null)
        {
            Logger.Info("The event list is empty or null.");
            return;
        }

        var dataStreams = dataList.ToList();

        if (dataStreams.Count > 500) throw new InvalidEventLimitException();

        using var activity = Activity.Current;
        activity?.SetTag("BusName", BusName);

        var request = new PutRecordsRequest
        {
            StreamName = BusName,
            Records = CreatePutRecords(dataStreams, activity)
        };

        var policy = base.CreateDefaultRetryAsyncPolicy();

        var results = await policy.ExecuteAsync(async () =>
                await KinesisClient.PutRecordsAsync(request, cancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);

        if (results.FailedRecordCount == 0)
        {
            Logger.Info($"All data published to Bus {BusName}");
            return;
        }

        foreach (var data in dataStreams)
        {
            data.PublishedAt = null;
        }

        var errorRecords = results.Records.Where(r => r.ErrorCode != null);

        foreach (var error in errorRecords)
        {
            Logger.Error($"Error publishing message. Error: {error.ErrorCode}, ErrorMessage: {error.ErrorMessage}");
        }
    }

    private async Task InternalPublish(T data, CancellationToken cancellationToken = default)
    {
        if (data is null)
        {
            Logger.Info("The event list is empty or null.");
            return;
        }

        using var activity = Activity.Current;
        activity?.SetTag("BusName", BusName);

        var request = CreatePutRecordRequest(data, activity);
        request.StreamName = BusName;

        var policy = base.CreateDefaultRetryAsyncPolicy();

        var results = await policy.ExecuteAsync(async () =>
                await KinesisClient.PutRecordAsync(request, cancellationToken).ConfigureAwait(false))
            .ConfigureAwait(false);

        if (results == null || results.HttpStatusCode != HttpStatusCode.OK)
        {
            data.PublishedAt = null;
            Logger.Error($"Error publishing message.");
            return;
        }

        Logger.Info($"All data published to Bus {BusName}");
    }

    protected override void DisposeServices()
    {
        kinesisClient?.Dispose();
    }
}