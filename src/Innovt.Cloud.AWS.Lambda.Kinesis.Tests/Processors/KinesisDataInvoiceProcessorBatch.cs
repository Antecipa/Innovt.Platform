﻿// Company: Antecipa
// Project: Innovt.Cloud.AWS.Lambda.Kinesis.Tests
// Solution: Innovt.Platform
// Date: 2021-07-20

using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Innovt.Core.CrossCutting.Ioc;

namespace Innovt.Cloud.AWS.Lambda.Kinesis.Tests.Processors
{
    public class KinesisDataInvoiceProcessorBatch: KinesisDataProcessorBatch<Invoice>
    {
        private readonly IServiceMock serviceMock;

        public KinesisDataInvoiceProcessorBatch(IServiceMock serviceMock)
        {
            this.serviceMock = serviceMock ?? throw new System.ArgumentNullException(nameof(serviceMock));
        }

        protected override IContainer SetupIocContainer()
        {
            serviceMock.InicializeIoc();

            return null;
        }

        protected override Task ProcessMessages(IList<Invoice> messages)
        {
           serviceMock.ProcessMessage(messages.First().TraceId);

           return Task.CompletedTask;
        }
    }
}