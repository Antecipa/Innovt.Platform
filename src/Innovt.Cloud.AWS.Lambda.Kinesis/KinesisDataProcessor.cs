﻿// INNOVT TECNOLOGIA 2014-2021
// Author: Michel Magalhães
// Project: Innovt.Cloud.AWS.Lambda.Kinesis
// Solution: Innovt.Platform
// Date: 2021-06-02
// Contact: michel@innovt.com.br or michelmob@gmail.com

using System;
using System.Collections.Generic;
using Innovt.Core.CrossCutting.Log;
using Innovt.Domain.Core.Streams;
using System.Threading.Tasks;

namespace Innovt.Cloud.AWS.Lambda.Kinesis
{
    public abstract class KinesisDataProcessor<TBody> : KinesisDataProcessorBatch<TBody> where TBody : class, IDataStream
    {
        protected KinesisDataProcessor(ILogger logger) : base(logger)
        {
        }

        protected KinesisDataProcessor()
        {
        }

        protected override async Task ProcessMessages(IList<TBody> messages)
        {
            if (messages == null) throw new ArgumentNullException(nameof(messages));

            foreach (var message in messages)
            {
                Logger.Info($"Processing Kinesis EventId={message.EventId}.");

                try
                {
                    await ProcessMessage(message).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    Logger.Error(ex, $"Error Processing Message from Kinesis Event. Developer, you should take care of it!. EventId={message.EventId}, PartitionKey={ message.Partition }");
                    throw;
                }

                Logger.Info($"EventId={message.EventId} from Kinesis processed.");
            }
        }

        protected abstract Task ProcessMessage(TBody message);
    }
}