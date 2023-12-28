﻿// Innovt Company
// Author: Michel Borges
// Project: Innovt.Cloud.AWS.Lambda.Sqs

using Amazon.Lambda.Core;
using Amazon.Lambda.SQSEvents;
using Innovt.Cloud.Queue;
using Innovt.Core.CrossCutting.Log;
using Innovt.Core.Serialization;
using Innovt.Core.Utilities;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using static Amazon.Lambda.SQSEvents.SQSEvent;

namespace Innovt.Cloud.AWS.Lambda.Sqs;

/// <summary>
///     If you're using this feature with a FIFO queue, your function should stop processing messages after the first
///     failure and return all failed and unprocessed messages in batchItemFailures. This helps preserve the ordering of
///     messages in your queue.
/// </summary>
/// <typeparam name="TBody"></typeparam>
public abstract class SqsEventProcessor<TBody> : EventProcessor<SQSEvent, BatchFailureResponse> where TBody : class
{
    private readonly bool isFifo;
    private ISerializer serializer;

    protected SqsEventProcessor(bool isFifo = false, bool reportBatchFailures = false)
    {
        this.isFifo = isFifo;
        ReportBatchFailures = reportBatchFailures;
    }

    protected SqsEventProcessor(ILogger logger, bool isFifo = false, bool reportBatchFailures = false) : base(logger)
    {
        this.isFifo = isFifo;
        ReportBatchFailures = reportBatchFailures;
    }

    protected SqsEventProcessor(ILogger logger, ISerializer serializer, bool isFifo = false,
        bool reportBatchFailures = false) : this(logger, isFifo, reportBatchFailures)
    {
        Serializer = serializer ?? throw new ArgumentNullException(nameof(serializer));
    }

    protected bool ReportBatchFailures { get; set; }

    private ISerializer Serializer
    {
        get { return serializer ??= new JsonSerializer(); }

        set => serializer = value;
    }

    protected override async Task<BatchFailureResponse> Handle(SQSEvent message, ILambdaContext context)
    {
        Logger.Info($"Processing Sqs event With {message?.Records?.Count} records.");

        using var watcher = new StopWatchHelper(Logger, nameof(Handle));

        var response = new BatchFailureResponse();

        if (message?.Records == null || message.Records.Count == 0) return response;

        var processedMessages = new List<string>();

        foreach (var record in message.Records)
        {
            try
            {
                var queueMessage = new QueueMessage<TBody>
                {
                    MessageId = record.MessageId,
                    ReceiptHandle = record.ReceiptHandle,
                    Attributes = record.Attributes,
                    Body = Serializer.DeserializeObject<TBody>(record.Body)
                };

                if (record.Attributes is not null)
                {
                    queueMessage.ParseQueueAttributes(record.Attributes);
                }

                if (record.MessageAttributes is not null)
                {
                    ParseQueueMessageAttributes(queueMessage, record.MessageAttributes);
                }

                using var activity = StartBaseActivity(nameof(Handle), queueMessage.ParentId);

                Logger.Info($"Processing SQS Event message ID {record.MessageId}.");

                activity?.SetTag("SqsMessageId", queueMessage.MessageId);
                activity?.SetTag("SqsMessageApproximateFirstReceiveTimestamp",
                    queueMessage.ApproximateFirstReceiveTimestamp);
                activity?.SetTag("SqsMessageApproximateReceiveCount", queueMessage.ApproximateReceiveCount);
                activity?.AddBaggage("Message.ElapsedTimeBeforeAttendedInMilliseconds",
                    $"{queueMessage.ApproximateFirstReceiveTimestamp.GetValueOrDefault()}");

                await ProcessMessage(queueMessage).ConfigureAwait(false);

                processedMessages.Add(record.MessageId);

                Logger.Info($"SQS Event message ID {record.MessageId} Processed.");
            }
            catch (Exception ex)
            {
                if (Activity.Current is not null)
                    Activity.Current.SetStatus(ActivityStatusCode.Error, ex.Message);

                if (!ReportBatchFailures)
                    throw;

                Logger.Warning($"SQS Event message ID {record.MessageId} will be returned as item failure.");
                Logger.Error(ex, $"Exception for message ID {record.MessageId}.");

                if (isFifo)
                {
                    response.AddItems(GetRemainingMessages(message, processedMessages));
                    break;
                }

                response.AddItem(record.MessageId);
            }
        }

        return response;
    }

    private static IEnumerable<string> GetRemainingMessages(SQSEvent message, IList<string> processedMessages)
    {
        return message.Records.Where(r => !processedMessages.Contains(r.MessageId)).Distinct().Select(r => r.MessageId);
    }

    private void ParseQueueMessageAttributes(IQueueMessage queueMessage,
     Dictionary<string, MessageAttribute> queueAttributes)
    {
        if (queueMessage is null || queueAttributes == null)
            return;

        if (queueAttributes.ContainsKey("TraceId"))
            queueMessage.TraceId = queueAttributes["TraceId"].StringValue;

        if (queueAttributes.ContainsKey("ParentId"))
            queueMessage.ParentId = queueAttributes["ParentId"].StringValue;
    }

    protected abstract Task ProcessMessage(QueueMessage<TBody> message);
}