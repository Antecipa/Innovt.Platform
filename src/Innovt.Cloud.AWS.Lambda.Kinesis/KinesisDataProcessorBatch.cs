﻿// INNOVT TECNOLOGIA 2014-2021
// Author: Michel Magalhães
// Project: Innovt.Cloud.AWS.Lambda.Kinesis
// Solution: Innovt.Platform
// Date: 2021-06-02
// Contact: michel@innovt.com.br or michelmob@gmail.com

using Amazon.Lambda.Core;
using Amazon.Lambda.KinesisEvents;
using Innovt.Core.CrossCutting.Log;
using Innovt.Domain.Core.Streams;
using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;

namespace Innovt.Cloud.AWS.Lambda.Kinesis
{
    public abstract class KinesisDataProcessorBatch<TBody> : KinesisProcessorBase<TBody> where TBody : class, IDataStream
    {
        protected KinesisDataProcessorBatch(ILogger logger,bool reportBacthFailures = false) : base(logger, reportBacthFailures)
        {
        }
        protected KinesisDataProcessorBatch(bool reportBacthFailures = false):base(reportBacthFailures)
        {
        }

        protected override TBody DeserializeBody(string content, string partition)
        {
            return JsonSerializer.Deserialize<TBody>(content);
        }

        private async Task<IList<TBody>> CreateBatchMessages(IEnumerable<KinesisEvent.KinesisEventRecord> messageRecords)
        {
            if (messageRecords == null) throw new ArgumentNullException(nameof(messageRecords));

            var dataStreams = new List<TBody>();

            foreach (var record in messageRecords)
            {
                dataStreams.Add(await ParseRecord(record).ConfigureAwait(false));
            }

            return dataStreams;
        }

        protected override async Task<BatchFailureResponse> Handle(KinesisEvent message, ILambdaContext context)
        {
            Logger.Info($"Processing Kinesis Event With {message?.Records?.Count} records.");

            using var activity = EventProcessorActivitySource.StartActivity(nameof(Handle));
            activity?.SetTag("Message.Records", message?.Records?.Count);

            if (message?.Records == null) return new BatchFailureResponse();
            if (message.Records.Count == 0) return new BatchFailureResponse();

            Logger.Info($"Processing Kinesis Event With {message?.Records?.Count} records.");
            var batchMessages = await CreateBatchMessages(message.Records).ConfigureAwait(false);
            Logger.Info($"Processing Kinesis Event With {message?.Records?.Count} records.");
            activity?.SetTag("BatchMessagesCount", batchMessages.Count);

            return await ProcessMessages(batchMessages).ConfigureAwait(false);
        }

        protected abstract Task<BatchFailureResponse> ProcessMessages(IList<TBody> messages);
    }
}