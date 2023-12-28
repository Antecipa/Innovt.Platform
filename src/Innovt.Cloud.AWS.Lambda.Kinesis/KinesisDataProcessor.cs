﻿// Innovt Company
// Author: Michel Borges
// Project: Innovt.Cloud.AWS.Lambda.Kinesis

using Innovt.Core.CrossCutting.Log;
using Innovt.Core.Exceptions;
using Innovt.Domain.Core.Streams;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Innovt.Cloud.AWS.Lambda.Kinesis;

public abstract class KinesisDataProcessor<TBody> : KinesisDataProcessorBatch<TBody> where TBody : class, IDataStream
{
    protected KinesisDataProcessor(ILogger logger, bool reportBatchFailures = false) : base(logger, reportBatchFailures)
    {
    }

    protected KinesisDataProcessor(bool reportBatchFailures = false) : base(reportBatchFailures)
    {
    }

    protected override async Task<BatchFailureResponse> ProcessMessages(IList<TBody> messages)
    {
        if (messages == null) throw new ArgumentNullException(nameof(messages));

        var response = new BatchFailureResponse();

        foreach (var message in messages)
            try
            {
                if (message is null)
                    throw new CriticalException("Invalid message. The message from kinesis can't be null.");

                if (IsEmptyMessage(message))
                {
                    Logger.Warning($"Discarding message from partition {message.Partition}. EventId={message.EventId}");
                    continue;
                }

                using var activity = StartBaseActivity(nameof(ProcessMessages), message?.ParentId);
                activity?.SetTag("Kinesis.EventId", message.EventId);
                activity?.SetTag("Kinesis.EventName", message.Partition);

                Logger.Info($"Processing Kinesis EventId={message.EventId}.");

                message.PublishedAt = null;

                await ProcessMessage(message).ConfigureAwait(false);

                message.PublishedAt = DateTimeOffset.UtcNow;

                Logger.Info($"EventId={message.EventId} from Kinesis processed.");
            }
            catch (Exception ex)
            {
                if (!ReportBatchFailures)
                    throw;

                Logger.Error(ex, $"Exception for message ID {message?.EventId}.");

                response.AddItem(message?.EventId);
            }

        return response;
    }

    protected abstract Task ProcessMessage(TBody message);
}