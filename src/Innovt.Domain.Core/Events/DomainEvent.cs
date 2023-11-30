// Innovt Company
// Author: Michel Borges
// Project: Innovt.Domain.Core

using Innovt.Domain.Core.Streams;
using System;

namespace Innovt.Domain.Core.Events;

public abstract class DomainEvent : IDataStream
{
    protected DomainEvent(string name, string version, string partition)
    {
        Name = name;
        Version = version;
        Partition = partition;
        CreatedAt = DateTime.UtcNow;
    }

    protected DomainEvent(string name, string partition)
    {
        Name = name;
        Partition = partition;
        CreatedAt = DateTime.UtcNow;
    }

    public string Name { get; set; }

    public DateTime CreatedAt { get; set; }

    public string EventId { get; set; }

    public string Version { get; set; }

    public string Partition { get; set; }
    public DateTimeOffset? PublishedAt { get; set; }
    public string TraceId { get; set; }
    public string ParentId { get; set; }
    public DateTime ApproximateArrivalTimestamp { get; set; }

    public static DomainEvent Empty(string partition)
    {
        return new EmptyDomainEvent(partition);
    }
}