﻿// INNOVT TECNOLOGIA 2014-2021
// Author: Michel Magalhães
// Project: Innovt.Cloud.AWS.Dynamo
// Solution: Innovt.Platform
// Date: 2021-05-03
// Contact: michel@innovt.com.br or michelmob@gmail.com

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.DataModel;
using Amazon.DynamoDBv2.Model;
using Innovt.Cloud.AWS.Configuration;
using Innovt.Cloud.Table;
using Innovt.Core.Collections;
using Innovt.Core.CrossCutting.Log;
using Polly.Retry;
using QueryRequest = Innovt.Cloud.Table.QueryRequest;
using ScanRequest = Innovt.Cloud.Table.ScanRequest;

namespace Innovt.Cloud.AWS.Dynamo
{
    public abstract class Repository : AwsBaseService, ITableRepository
    {
        private static readonly ActivitySource Activity = new(nameof(Repository));

        private DynamoDBContext context;
        private AmazonDynamoDBClient dynamoClient;


        protected Repository(ILogger logger, IAWSConfiguration configuration) : base(logger, configuration)
        {
        }

        protected Repository(ILogger logger, IAWSConfiguration configuration, string region) : base(logger,
            configuration, region)
        {
        }

        private DynamoDBContext Context => context ??= new DynamoDBContext(DynamoClient);
        private AmazonDynamoDBClient DynamoClient => dynamoClient ??= CreateService<AmazonDynamoDBClient>();

        private static DynamoDBOperationConfig OperationConfig =>
            new()
            {
                ConsistentRead = true,
                Conversion = DynamoDBEntryConversion.V2
            };

        public async Task<T> GetByIdAsync<T>(object id, string rangeKey = null,
            CancellationToken cancellationToken = default) where T : ITableMessage
        {
            var policy = CreateDefaultRetryAsyncPolicy();

            if (string.IsNullOrEmpty(rangeKey))
                return await policy.ExecuteAsync(async () =>
                        await Context.LoadAsync<T>(id, OperationConfig, cancellationToken))
                    .ConfigureAwait(false);

            return await policy
                .ExecuteAsync(async () => await Context.LoadAsync<T>(id, rangeKey, OperationConfig, cancellationToken))
                .ConfigureAwait(false);
        }

        public async Task DeleteAsync<T>(T value, CancellationToken cancellationToken = default) where T : ITableMessage
        {
            await CreateDefaultRetryAsyncPolicy()
                .ExecuteAsync(async () => await Context.DeleteAsync(value, cancellationToken)).ConfigureAwait(false);
        }

        public async Task DeleteAsync<T>(object id, string rangeKey = null,
            CancellationToken cancellationToken = default) where T : ITableMessage
        {
            var policy = CreateDefaultRetryAsyncPolicy();

            if (string.IsNullOrEmpty(rangeKey))
                await policy.ExecuteAsync(async () => await Context.DeleteAsync<T>(id, cancellationToken))
                    .ConfigureAwait(false);
            else
                await policy.ExecuteAsync(async () => await Context.DeleteAsync<T>(id, rangeKey, cancellationToken))
                    .ConfigureAwait(false);
        }

        public async Task AddAsync<T>(T message, CancellationToken cancellationToken = default) where T : ITableMessage
        {
            await CreateDefaultRetryAsyncPolicy()
                .ExecuteAsync(async () => await Context.SaveAsync(message, OperationConfig, cancellationToken))
                .ConfigureAwait(false);
        }

        public async Task AddAsync<T>(IList<T> messages, CancellationToken cancellationToken = default)
            where T : ITableMessage
        {
            if (messages is null) throw new ArgumentNullException(nameof(messages));

            var batch = Context.CreateBatchWrite<T>(OperationConfig);

            batch.AddPutItems(messages);

            await CreateDefaultRetryAsyncPolicy()
                .ExecuteAsync(async () => await batch.ExecuteAsync(cancellationToken)).ConfigureAwait(false);
        }

        public async Task<T> QueryFirstAsync<T>(object id, CancellationToken cancellationToken = default)
        {
            var result = await CreateDefaultRetryAsyncPolicy().ExecuteAsync(async () =>
                    await Context.QueryAsync<T>(id, OperationConfig).GetNextSetAsync(cancellationToken))
                .ConfigureAwait(false);

            return result == null ? default : result.FirstOrDefault();
        }

        public async Task<IList<T>> QueryAsync<T>(object id, CancellationToken cancellationToken = default)
        {
            var result = await CreateDefaultRetryAsyncPolicy().ExecuteAsync(async () =>
                    await Context.QueryAsync<T>(id, OperationConfig).GetRemainingAsync(cancellationToken))
                .ConfigureAwait(false);

            return result;
        }

        public async Task<IList<T>> QueryAsync<T>(QueryRequest request, CancellationToken cancellationToken = default)
        {
            if (request is null) throw new ArgumentNullException(nameof(request));

            var (_, items) = await InternalQueryAsync<T>(request, cancellationToken).ConfigureAwait(false);

            return Helpers.ConvertAttributesToType<T>(items, Context);
        }

        public async Task<(List<TResult1> first, List<TResult2> second)> QueryMultipleAsync<T, TResult1, TResult2>(
            QueryRequest request, string splitBy, CancellationToken cancellationToken = default)
        {
            if (request is null) throw new ArgumentNullException(nameof(request));

            var (_, items) = await InternalQueryAsync<T>(request, cancellationToken).ConfigureAwait(false);

            return Helpers.ConvertAttributesToType<TResult1, TResult2>(items, splitBy, Context);
        }

        public async Task<(List<TResult1> first, List<TResult2> second, List<TResult3> third)>
            QueryMultipleAsync<T, TResult1, TResult2, TResult3>(QueryRequest request, string[] splitBy,
                CancellationToken cancellationToken = default)
        {
            if (request is null) throw new ArgumentNullException(nameof(request));

            var (_, items) = await InternalQueryAsync<T>(request, cancellationToken).ConfigureAwait(false);

            return Helpers.ConvertAttributesToType<TResult1, TResult2, TResult3>(items, splitBy, Context);
        }

        public async Task<T> QueryFirstOrDefaultAsync<T>(QueryRequest request,
            CancellationToken cancellationToken = default)
        {
            if (request is null) throw new ArgumentNullException(nameof(request));

            var (_, items) = await InternalQueryAsync<T>(request, cancellationToken).ConfigureAwait(false);

            var queryResponse = Helpers.ConvertAttributesToType<T>(items, Context);

            return queryResponse.FirstOrDefault();
        }

        public async Task<PagedCollection<T>> QueryPaginatedByAsync<T>(QueryRequest request,
            CancellationToken cancellationToken = default)
        {
            if (request is null) throw new ArgumentNullException(nameof(request));

            var (lastEvaluatedKey, items) =
                await InternalQueryAsync<T>(request, cancellationToken).ConfigureAwait(false);

            return new PagedCollection<T>
            {
                Items = Helpers.ConvertAttributesToType<T>(items, Context),
                Page = Helpers.CreatePaginationToken(lastEvaluatedKey),
                PageSize = request.PageSize.GetValueOrDefault()
            };
        }

        public async Task<IList<T>> ScanAsync<T>(ScanRequest request,
            CancellationToken cancellationToken = default)
        {
            return (await InternalScanAsync<T>(request, cancellationToken)).Items;
        }


        public async Task<PagedCollection<T>> ScanPaginatedByAsync<T>(ScanRequest request,
            CancellationToken cancellationToken = default)
        {
            if (request is null) throw new ArgumentNullException(nameof(request));

            var (exclusiveStartKey, items) = await InternalScanAsync<T>(request, cancellationToken);

            if (items?.Count() == 0)
                return new PagedCollection<T>();

            var response = new PagedCollection<T>
            {
                Items = items,
                Page = Helpers.CreatePaginationToken(exclusiveStartKey),
                PageSize = request.PageSize.GetValueOrDefault()
            };

            return response;
        }


        protected override AsyncRetryPolicy CreateDefaultRetryAsyncPolicy()
        {
            return base.CreateRetryAsyncPolicy<ProvisionedThroughputExceededException,
                InternalServerErrorException, LimitExceededException, ResourceInUseException>();
        }

        protected async Task UpdateAsync(string tableName, Dictionary<string, AttributeValue> key,
            Dictionary<string, AttributeValueUpdate> attributeUpdates, CancellationToken cancellationToken = default)
        {
            await CreateDefaultRetryAsyncPolicy().ExecuteAsync(async () =>
                    await DynamoClient.UpdateItemAsync(tableName, key, attributeUpdates, cancellationToken))
                .ConfigureAwait(false);
        }

        private async
            Task<(Dictionary<string, AttributeValue> LastEvaluatedKey, List<Dictionary<string, AttributeValue>> Items)>
            InternalQueryAsync<T>(QueryRequest request, CancellationToken cancellationToken = default)
        {
            if (request is null) throw new ArgumentNullException(nameof(request));

            var queryRequest = Helpers.CreateQueryRequest<T>(request);

            Dictionary<string, AttributeValue> lastEvaluatedKey = null;

            var items = new List<Dictionary<string, AttributeValue>>();
            var remaining = request.PageSize;

            var iterator = DynamoClient.Paginators.Query(queryRequest).Responses.GetAsyncEnumerator(cancellationToken);

            do
            {
                await iterator.MoveNextAsync();

                if (iterator.Current == null)
                    break;

                items.AddRange(iterator.Current.Items);
                queryRequest.ExclusiveStartKey = lastEvaluatedKey = iterator.Current.LastEvaluatedKey;

                remaining = remaining.HasValue ? request.PageSize - items.Count : 0;

                if (remaining > 0) queryRequest.Limit = remaining.Value;
            } while (lastEvaluatedKey.Count > 0 && remaining > 0);

            return (lastEvaluatedKey, items);
        }


        private async Task<(Dictionary<string, AttributeValue> ExclusiveStartKey, IList<T> Items)> InternalScanAsync<T>(
            ScanRequest request, CancellationToken cancellationToken = default)
        {
            if (request is null) throw new ArgumentNullException(nameof(request));

            var scanRequest = Helpers.CreateScanRequest<T>(request);

            Dictionary<string, AttributeValue> lastEvaluatedKey = null;

            var items = new List<T>();
            var remaining = request.PageSize;


            var iterator = DynamoClient.Paginators.Scan(scanRequest).Responses.GetAsyncEnumerator(cancellationToken);
            //TODO: Thi code is the same in InternalQuery - Refactory it
            do
            {
                await iterator.MoveNextAsync();

                if (iterator.Current == null)
                    break;

                items.AddRange(Helpers.ConvertAttributesToType<T>(iterator.Current.Items, Context));
                scanRequest.ExclusiveStartKey = lastEvaluatedKey = iterator.Current.LastEvaluatedKey;
                remaining = remaining.HasValue ? request.PageSize - items.Count : 0;

                if (remaining > 0) scanRequest.Limit = remaining.Value;
            } while (lastEvaluatedKey.Count > 0 && remaining > 0);

            return (lastEvaluatedKey, items);
        }

        protected async Task<TransactGetItemsResponse> TransactGetItemsAsync<T>(TransactGetItemsRequest request,
            CancellationToken cancellationToken = default)
        {
            if (request is null) throw new ArgumentNullException(nameof(request));

            return await CreateDefaultRetryAsyncPolicy()
                .ExecuteAsync(async () => await DynamoClient.TransactGetItemsAsync(request, cancellationToken))
                .ConfigureAwait(false);
        }

        protected override void DisposeServices()
        {
            context?.Dispose();
            dynamoClient?.Dispose();
        }
    }
}