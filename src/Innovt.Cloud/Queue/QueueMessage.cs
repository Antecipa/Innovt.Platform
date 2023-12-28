﻿// Innovt Company
// Author: Michel Borges
// Project: Innovt.Cloud

using System.Collections.Generic;

namespace Innovt.Cloud.Queue;

public class QueueMessage<T> : IQueueMessage
{
    public QueueMessage()
    {
    }

    public QueueMessage(T body)
    {
        Body = body;
    }

    public QueueMessage(Dictionary<string, string> attributes)
    {
        Attributes = attributes;
    }

    public T Body { get; set; }

    public string MessageId { get; set; }

    public string ReceiptHandle { get; set; }

    public string TraceId { get; set; }
    public string ParentId { get; set; }

    public double? ApproximateFirstReceiveTimestamp { get; set; }

    public int? ApproximateReceiveCount { get; set; }

#pragma warning disable CA2227 // Collection properties should be read only
    public Dictionary<string, string> Attributes { get; set; }
#pragma warning restore CA2227 // Collection properties should be read only
}