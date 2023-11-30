// Innovt Company
// Author: Michel Borges
// Project: Innovt.Cloud.AWS.Lambda.Kinesis

using Amazon.Lambda.KinesisEvents;
using Innovt.Core.CrossCutting.Log;
using Innovt.Core.Exceptions;
using Innovt.Domain.Core.Streams;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace Innovt.Cloud.AWS.Lambda.Kinesis;

public abstract class KinesisProcessorBase<TBody> : EventProcessor<KinesisEvent, BatchFailureResponse>
    where TBody : IDataStream
{
    protected KinesisProcessorBase(ILogger logger, bool reportBatchFailures = false) : base(logger)
    {
        ReportBatchFailures = reportBatchFailures;
    }

    protected KinesisProcessorBase(bool reportBatchFailures = false)
    {
        ReportBatchFailures = reportBatchFailures;
    }

    protected bool ReportBatchFailures { get; set; }

    /// <summary>
    ///     When the developer want to discard the message from specific partition
    /// </summary>
    /// <param name="message"></param>
    /// <returns></returns>
    protected bool IsEmptyMessage(TBody message)
    {
        return message is IEmptyDataStream;
    }

    protected async Task<TBody> ParseRecord(KinesisEvent.KinesisEventRecord record)
    {
        if (record == null) throw new ArgumentNullException(nameof(record));
        if (record.Kinesis.Data is null)
            throw new CriticalException($"Kinesis Data for EventId {record.EventId} is null");

        Logger.Info($"Processing Kinesis Event message ID {record.EventId}.");

        using var reader = new StreamReader(record.Kinesis.Data, Encoding.UTF8);

        var content = await reader.ReadToEndAsync().ConfigureAwait(false);

        var body = DeserializeBody(content, record.Kinesis.PartitionKey);

        if (body != null)
        {
            body.EventId = record.EventId;
            body.ApproximateArrivalTimestamp = record.Kinesis.ApproximateArrivalTimestamp;
            body.Partition ??= record.Kinesis.PartitionKey;
        }

        return body;
    }

    protected abstract TBody DeserializeBody(string content, string partition);
}