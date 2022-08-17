﻿using System;
using System.Collections.Generic;


namespace Innovt.Cloud.Table
{
    public class BatchWriteItemRequest
    {
        public Dictionary<string, List<BatchWriteItem>> Items { get; private set; }
        public TimeSpan RetryDelay { get; set; }
        public int MaxRetry { get; set; }
        
        public BatchWriteItemRequest()
        {
            Items = new Dictionary<string, List<BatchWriteItem>>();
            MaxRetry = 3;
            RetryDelay = TimeSpan.FromSeconds(1);
        }

        public BatchWriteItemRequest(string tableName, BatchWriteItem batchWriteItem):this()
        {
            this.AddItem(tableName, batchWriteItem);
        }

        public void AddItem(string tableName, BatchWriteItem batchRequestItem)
        {
            if (batchRequestItem is null) throw new ArgumentNullException(nameof(batchRequestItem));

            if (!Items.ContainsKey(tableName))
            {
                Items.Add(tableName, new List<BatchWriteItem>()
                {
                    batchRequestItem
                });
            }
            else
            {
                Items[tableName].Add(batchRequestItem);
            }
        }

    }
}

