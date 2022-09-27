// Innovt Company
// Author: Michel Borges
// Project: Innovt.Cloud

using System.Collections.Generic;

namespace Innovt.Cloud.Table;

public class TransactionWriteItem
{
    public TransactionWriteOperationType OperationType { get; set; }

    public string TableName { get; set; }
    public string ConditionExpression { get; set; }

    /// <summary>
    ///  Only for update operations
    /// </summary>
    public string UpdateExpression { get; set; }

#pragma warning disable CA2227 // Collection properties should be read only
    public Dictionary<string, object> Keys { get; set; }
#pragma warning restore CA2227 // Collection properties should be read only


#pragma warning disable CA2227 // Collection properties should be read only
    /// <summary>
    /// Only for Put operations
    /// </summary>
    public Dictionary<string, object> Items { get; set; }
#pragma warning restore CA2227 // Collection properties should be read only


#pragma warning disable CA2227 // Collection properties should be read only
    public Dictionary<string, object> ExpressionAttributeValues { get; set; }
#pragma warning restore CA2227 // Collection properties should be read only
}