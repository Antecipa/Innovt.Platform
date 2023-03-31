﻿using Amazon.Scheduler;
using Amazon.Scheduler.Model;
using Amazon.SecurityToken;
using Amazon.SecurityToken.Model;
using Innovt.Cloud.AWS.Configuration;
using Innovt.Cloud.Scheduler;
using Innovt.Core.CrossCutting.Log;
using Innovt.Core.Exceptions;
using Innovt.Core.Serialization;
using System;
using System.Diagnostics;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace Innovt.Cloud.AWS.Bridge
{
    public class SchedulerService : AwsBaseService, ISchedulerService
    {
        private static readonly ActivitySource QueueActivitySource = new("Innovt.Cloud.AWS.Bridge.SchedulerService");

        private ISerializer serializer;
        private ISerializer Serializer => serializer ??= new JsonSerializer();

        public string RoleArn { get; }

        private AmazonSchedulerClient schedulerClient;
        private AmazonSchedulerClient SchedulerClient => schedulerClient ??= CreateService<AmazonSchedulerClient>();

        public SchedulerService(ILogger logger, IAwsConfiguration configuration, string roleArn,
        ISerializer serializer = null) : base(logger, configuration)
        {
            RoleArn = roleArn ?? throw new System.ArgumentNullException(nameof(roleArn));
            this.serializer = serializer;
        }

        public SchedulerService(ILogger logger, IAwsConfiguration configuration, string region, string roleArn,
            ISerializer serializer = null) : base(logger, configuration, region)
        {
            RoleArn = roleArn ?? throw new System.ArgumentNullException(nameof(roleArn));
            this.serializer = serializer;
        }

        public async Task<string> ScheduleQueueMessageAsync<TK>(TK message, string queueName, DateTime dateTime, string scheduleName,
        CancellationToken cancellationToken = default)
        {
            if (message == null) throw new ArgumentNullException(nameof(message));
            if (queueName == null) throw new ArgumentNullException(nameof(queueName));
            if (scheduleName == null) throw new ArgumentNullException(nameof(scheduleName));

            using var activity = QueueActivitySource.StartActivity("QueueAsync");
            activity?.SetTag("schedulerService.queueName", queueName);

            var target = new Target()
            {
                Arn = await GetQueueArnAsync(queueName).ConfigureAwait(false),
                Input = Serializer.SerializeObject(message),
                RoleArn = RoleArn
            };
            var flexibleTimeWindow = new FlexibleTimeWindow()
            {
                Mode = FlexibleTimeWindowMode.OFF
            };

            var response = await base.CreateDefaultRetryAsyncPolicy()
                .ExecuteAsync(async () =>
                    await SchedulerClient.CreateScheduleAsync(new CreateScheduleRequest()
                    {
                        Name = scheduleName,
                        State = ScheduleState.ENABLED,
                        ScheduleExpression = $"at({dateTime:yyyy-MM-ddTHH:mm:ss})",
                        Target = target,
                        FlexibleTimeWindow = flexibleTimeWindow
                    }, cancellationToken)
                .ConfigureAwait(false)).ConfigureAwait(false);

            activity?.SetTag("schedulerService.status_code", response.HttpStatusCode);

            if (response.HttpStatusCode != HttpStatusCode.OK)
                throw new CriticalException("Error sending message to queue.");

            return response.ResponseMetadata.RequestId;
        }

        private async Task<string> GetQueueArnAsync(string queueName)
        {
            string queueArn = null;

            using var activity = QueueActivitySource.StartActivity();
            activity?.SetTag("schedulerService.queue_name", queueName);

            if (Configuration?.AccountNumber != null)
            {
                queueArn = $"arn:aws:sqs:{GetServiceRegionEndPoint().SystemName}:{Configuration?.AccountNumber}:{queueName}";
            }
            else
            {
                IAmazonSecurityTokenService stsClient = CreateService<AmazonSecurityTokenServiceClient>();
                var accountId = (await stsClient.GetCallerIdentityAsync(new GetCallerIdentityRequest()).ConfigureAwait(false)).Account;
                queueArn = $"arn:aws:sqs:{GetServiceRegionEndPoint().SystemName}:{accountId}:{queueName}";
            }
            activity?.SetTag("schedulerService.queue_arn", queueArn);

            return queueArn;
        }

        protected override void DisposeServices()
        {
            schedulerClient?.Dispose();
        }
    }
}