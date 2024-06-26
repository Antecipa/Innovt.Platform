// Innovt Company
// Author: Michel Borges
// Project: Innovt.Cloud.AWS.Lambda.Kinesis.Tests

using Amazon.Lambda.KinesisEvents;
using Amazon.Lambda.TestUtilities;
using Innovt.Cloud.AWS.Lambda.Kinesis.Tests.Processors;
using Innovt.Core.Exceptions;
using Innovt.Domain.Core.Events;
using Innovt.Domain.Core.Streams;
using NSubstitute;
using NUnit.Framework;
using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace Innovt.Cloud.AWS.Lambda.Kinesis.Tests;

[TestFixture]
public class KinesisProcessorTests
{
    [SetUp]
    public void Setup()
    {
        serviceMock = Substitute.For<IServiceMock>();
    }

    private IServiceMock serviceMock = null!;

    private static readonly ActivitySource KinesisProcessorTestsActivitySource =
        new("Innovt.Cloud.AWS.Lambda.Kinesis.Tests");

    [Test]
    public async Task SimpleFunctionTest()
    {
        var domainServiceMock = Substitute.For<IDomainEventServiceMock<DomainEvent>>();

        var function = new KinesisDomainEventEmptyInvoiceProcessor(domainServiceMock);

        await function.Process(new KinesisEvent(), new TestLambdaContext());
        //should not receive the call because there is no records
        domainServiceMock.DidNotReceive().ProcessMessage(Arg.Any<DomainEvent>());
    }

    [Test]
    public void ProcessThrowExceptionIfMessageIsNull()
    {
        var function = new KinesisDataInvoiceProcessorBatch(serviceMock);

        Assert.ThrowsAsync<ArgumentNullException>(async () => await function.Process(null, null));
    }

    [Test]
    public void ProcessThrowExceptionIfContextIsNull()
    {
        var function = new KinesisDataInvoiceProcessorBatch(serviceMock);

        Assert.ThrowsAsync<ArgumentNullException>(async () => await function.Process(new KinesisEvent(), null));
    }

    [Test]
    public async Task ProcessShouldCallIoc()
    {
        var function = new KinesisDataInvoiceProcessorBatch(serviceMock);

        var lambdaContext = new TestLambdaContext();

        var message = new KinesisEvent();

        await function.Process(message, lambdaContext);

        serviceMock.Received().InitializeIoc();
        serviceMock.DidNotReceive().ProcessMessage();
    }

    [Test]
    public async Task ProcessWithoutMessageReturnWithoutCallHandle()
    {
        var function = new KinesisDataInvoiceProcessorBatch(serviceMock);

        var lambdaContext = new TestLambdaContext();

        var message = new KinesisEvent();

        await function.Process(message, lambdaContext);

        serviceMock.DidNotReceive().ProcessMessage();
    }

    [Test]
    public void ProcessWithoutKinesisDataThrowsException()
    {
        var function = new KinesisDataInvoiceProcessorBatch(serviceMock);

        var lambdaContext = new TestLambdaContext();

        var eventId = Guid.NewGuid().ToString();

        var message = new KinesisEvent
        {
            Records = new List<KinesisEvent.KinesisEventRecord>
            {
                new()
                {
                    AwsRegion = "us-east-1",
                    EventId = eventId,
                    EventName = "eventTest",
                    EventVersion = "1.0.0",
                    EventSource = "testing",
                    Kinesis = new KinesisEvent.Record { PartitionKey = "partition1", Data = null }
                }
            }
        };

        Assert.ThrowsAsync<CriticalException>(async () => await function.Process(message, lambdaContext),
            $"Kinesis Data for EventId {eventId} is null");

        serviceMock.Received().InitializeIoc();
        serviceMock.DidNotReceive().ProcessMessage();
    }

    [Test]
    public async Task Process()
    {
        var function = new KinesisDataInvoiceProcessorBatch(serviceMock);

        var lambdaContext = new TestLambdaContext();

        var eventId = Guid.NewGuid();

        var message = new KinesisEvent
        {
            Records = new List<KinesisEvent.KinesisEventRecord>
            {
                CreateValidKinesisRecord(eventId, new Invoice())
            }
        };

        var result = await function.Process(message, lambdaContext);

        Assert.That(result, Is.Null);
        serviceMock.Received().InitializeIoc();
        serviceMock.Received().ProcessMessage(Arg.Any<string>());
    }

    [Test]
    public async Task Process_WithCustomLogger()
    {
        var function = new KinesisDataInvoiceProcessorBatch(serviceMock);

        var lambdaContext = new TestLambdaContext();

        var eventId = Guid.NewGuid();

        var message = new KinesisEvent
        {
            Records = new List<KinesisEvent.KinesisEventRecord>
            {
                CreateValidKinesisRecord(eventId, new Invoice())
            }
        };

        await function.Process(message, lambdaContext);

        serviceMock.Received().InitializeIoc();
        serviceMock.Received().ProcessMessage(Arg.Any<string>());
    }

    [Test]
    public async Task DeserializeDomainEvent()
    {
        var domainMock = Substitute.For<IDomainEventServiceMock<InvoiceDomainEvent>>();

        var function = new KinesisDomainEventInvoiceProcessorBatch(domainMock);

        var lambdaContext = new TestLambdaContext();

        var eventId = Guid.NewGuid();

        var netValue = 10;

        var message = new KinesisEvent
        {
            Records = new List<KinesisEvent.KinesisEventRecord>
            {
                CreateValidKinesisRecord(eventId, new InvoiceDomainEvent { NetValue = netValue })
            }
        };

        await function.Process(message, lambdaContext);

        domainMock.Received().InicializeIoc();
        domainMock.Received()
            .ProcessMessage(Arg.Is<InvoiceDomainEvent>(p => p.NetValue == netValue && p.EventId == eventId.ToString()));
    }

    [Test]
    public async Task DeserializeDataStream()
    {
        var domainMock = Substitute.For<IDataServiceMock<BaseInvoice>>();

        var function = new KinesisDataInvoiceProcessor2(domainMock);

        var lambdaContext = new TestLambdaContext();

        var eventId = Guid.NewGuid();
        var netValue = 20;

        var message = new KinesisEvent
        {
            Records = new List<KinesisEvent.KinesisEventRecord>
            {
                CreateValidKinesisRecord(eventId,
                    new DataStream<BaseInvoice> { Body = new BaseInvoice { NetValue = netValue } })
            }
        };

        await function.Process(message, lambdaContext);

        domainMock.Received().InicializeIoc();
        domainMock.Received()
            .ProcessMessage(Arg.Is<DataStream<BaseInvoice>>(p =>
                p.Body.NetValue == netValue && p.EventId == eventId.ToString()));
    }

    [Test]
    public async Task ProcessShouldDiscardEmptyMessage()
    {
        var domainMock = Substitute.For<IDomainEventServiceMock<DomainEvent>>();
        var function = new KinesisDomainEventEmptyInvoiceProcessor(domainMock);
        var lambdaContext = new TestLambdaContext();
        var eventId = Guid.NewGuid();
        var netValue = 20;

        var message = new KinesisEvent
        {
            Records = new List<KinesisEvent.KinesisEventRecord>
            {
                CreateValidKinesisRecord(eventId,
                    new DataStream<BaseInvoice> { Body = new BaseInvoice { NetValue = netValue } })
            }
        };

        await function.Process(message, lambdaContext);

        domainMock.DidNotReceive().ProcessMessage(Arg.Any<DomainEvent>());
    }

    private static KinesisEvent.KinesisEventRecord CreateValidKinesisRecord(Guid eventId, object invoice)
    {
        var dataAsBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(invoice));
        var ms = new MemoryStream(dataAsBytes);
        return new KinesisEvent.KinesisEventRecord
        {
            AwsRegion = "us-east-1",
            EventId = eventId.ToString(),
            EventName = "eventTest",
            EventVersion = "1.0.0",
            EventSource = "testing",
            Kinesis = new KinesisEvent.Record { PartitionKey = "partition1", Data = ms }
        };
    }
}