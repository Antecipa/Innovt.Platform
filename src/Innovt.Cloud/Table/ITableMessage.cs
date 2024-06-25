// Innovt Company
// Author: Michel Borges
// Project: Innovt.Cloud

namespace Innovt.Cloud.Table;

/// <summary>
///     Represents a message associated with a table, defining a unique identifier.
/// </summary>
public interface ITableMessage<T>
{
    /// <summary>
    ///     Gets or sets the unique identifier for the table message.
    /// </summary>
    T Id { get; set; }
}

/// <summary>
///     Represents a message associated with a table, defining a unique identifier.
/// </summary>
public interface ITableMessage : ITableMessage<string>
{
}