// Innovt Company
// Author: Michel Borges
// Project: Innovt.Cloud.AWS.Lambda

using Amazon.Lambda.Core;
using Innovt.Core.CrossCutting.Ioc;
using Innovt.Core.CrossCutting.Log;
using Innovt.Core.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using System;
using System.Diagnostics;
using System.Globalization;

namespace Innovt.Cloud.AWS.Lambda;

public abstract class BaseEventProcessor
{
    protected static readonly ActivitySource EventProcessorActivitySource =
        new("Innovt.Cloud.AWS.Lambda.EventProcessor");

    private bool isIocContainerInitialized;

    protected BaseEventProcessor(ILogger logger)
    {
        Logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    protected BaseEventProcessor()
    {
    }

    protected ILogger Logger { get; private set; }
    protected ILambdaContext Context { get; set; }
    protected IConfigurationRoot Configuration { get; set; }

    protected void InitializeLogger(ILogger logger = null)
    {
        if (Logger is { } && logger is null)
            return;

        Logger = logger ?? new LambdaLogger(Context.Logger);
    }

    protected void SetupIoc()
    {
        if (isIocContainerInitialized)
            return;

        var container = SetupIocContainer();

        if (container != null)
        {
            AddCoreService(container);
            container.CheckConfiguration();

            InitializeLogger(container.Resolve<ILogger>());

            Logger.Info("IOC Container Initialized.");
        }
        else
        {
            Logger.Warning("IOC Container not found.");
        }

        isIocContainerInitialized = true;
    }

    private void AddCoreService(IContainer container)
    {
        var services = new ServiceCollection();

        services.ConfigureAll<HttpClientFactoryOptions>(options =>
        {
            options.HttpMessageHandlerBuilderActions.Add(builder =>
            {
                builder.AdditionalHandlers.Add(builder.Services.GetRequiredService<HttpParentIdPropagationHandler>());
            });
        });

        container.AddModule(new IOCModule(services));
    }

    protected Activity StartBaseActivity(string activityName, string parentId = null)
    {
        if (activityName is null) throw new ArgumentNullException(nameof(activityName));

        var activity = new Activity(activityName);
        activity.SetIdFormat(ActivityIdFormat.W3C);

        if (!string.IsNullOrWhiteSpace(parentId))
            activity.SetParentId(parentId);
        else if (!string.IsNullOrWhiteSpace(Context.AwsRequestId))
            activity.SetParentId(Context.AwsRequestId);
        else
            activity.SetParentId(Guid.NewGuid().ToString());

        activity.SetTag("Lambda.FunctionName", Context.FunctionName);
        activity.SetTag("Lambda.FunctionVersion", Context.FunctionVersion);
        activity.SetTag("Lambda.LogStreamName", Context.LogStreamName);
        activity.AddBaggage("Lambda.RequestId", Context.AwsRequestId);

        activity.Start();

        return activity;
    }

    protected virtual void SetupConfiguration()
    {
        var configBuilder = new ConfigurationBuilder();
        configBuilder.AddEnvironmentVariables();
        configBuilder.AddJsonFile("appsettings.json", true);

        var environmentName = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");

        if (!string.IsNullOrWhiteSpace(environmentName))
            configBuilder.AddJsonFile(
                $"appsettings.{environmentName.ToLower(CultureInfo.CurrentCulture)}.json", true);

        EnrichConfiguration(configBuilder);

        Configuration = configBuilder.Build();
    }

    protected abstract IContainer SetupIocContainer();

    protected virtual void EnrichConfiguration(ConfigurationBuilder configurationBuilder)
    {
    }
}