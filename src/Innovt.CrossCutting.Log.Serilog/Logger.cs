﻿// INNOVT TECNOLOGIA 2014-2021
// Author: Michel Magalhães
// Project: Innovt.CrossCutting.Log.Serilog
// Solution: Innovt.Platform
// Date: 2021-06-02
// Contact: michel@innovt.com.br or michelmob@gmail.com

using System;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using Serilog.Formatting.Json;
using ILogger = Innovt.Core.CrossCutting.Log.ILogger;

namespace Innovt.CrossCutting.Log.Serilog;

public class Logger : ILogger, Microsoft.Extensions.Logging.ILogger
{
    private const string ConsoleTemplate = "[{Timestamp:HH:mm:ss} {Level:u3}] {TraceId} {SpanId} {Message:lj}{NewLine}{Exception}{ Properties: j}";
    private readonly global::Serilog.Core.Logger logger;

    /// <summary>
    ///     The default sink is Console
    /// </summary>
    public Logger() : this(new LoggerConfiguration())
    {
    }

    public Logger(ILogEventEnricher logEventEnricher) : this(new[]{ logEventEnricher} )
    {
        if (logEventEnricher is null) throw new ArgumentNullException(nameof(logEventEnricher));
    }

    public Logger(ILogEventEnricher[] logEventEnricher)
    {
        if (logEventEnricher is null) throw new ArgumentNullException(nameof(logEventEnricher));

        logger = new LoggerConfiguration()
            .WriteTo.Console(new JsonFormatter())
            .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
            .Enrich.With(logEventEnricher).Enrich.FromLogContext().CreateLogger();
    }

    public Logger(LoggerConfiguration configuration)
    {
        if (configuration == null) throw new ArgumentNullException(nameof(configuration));

        logger = configuration
            .WriteTo.Console(new JsonFormatter())
            .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
            .Enrich.FromLogContext().CreateLogger();
    }

    public void Debug(string message)
    {
        if (!IsEnabledInternal(LogLevel.Debug))
            return;

        logger.Debug(message);

    }

    public void Debug(string messageTemplate, params object[] propertyValues)
    {
        if (!IsEnabledInternal(LogLevel.Debug))
            return;


        logger.Debug(messageTemplate, propertyValues);
    }

    public void Debug(Exception exception, string messageTemplate)
    {
        if (!IsEnabledInternal(LogLevel.Debug))
            return;
        

        logger.Debug(exception, messageTemplate);
    }

    public void Debug(Exception exception, string messageTemplate, params object[] propertyValues)
    {
        if (!IsEnabledInternal(LogLevel.Debug))
            return;

        logger.Debug(exception, messageTemplate, propertyValues);
    }

    public void Error(string message)
    {
        if (!IsEnabledInternal(LogLevel.Error))
            return;

        logger.Error(message);
    }

    public void Error(string messageTemplate, params object[] propertyValues)
    {
        if (!IsEnabledInternal(LogLevel.Error))
            return;

        logger.Error(messageTemplate, propertyValues);
    }

    public void Error(Exception exception, string messageTemplate)
    {
        if (!IsEnabledInternal(LogLevel.Error))
            return;


        logger.Error(exception, messageTemplate);
    }

    public void Error(Exception exception, string messageTemplate, params object[] propertyValues)
    {
        if (!IsEnabledInternal(LogLevel.Error))
            return;
    
        logger.Error(exception, messageTemplate, propertyValues);
    }

    public void Fatal(string message)
    {
        if (!IsEnabledInternal(LogLevel.Critical))
            return;
        

        logger.Fatal(message);
    }

    public void Fatal(string messageTemplate, params object[] propertyValues)
    {
        if (!IsEnabledInternal(LogLevel.Critical))
            return;

        logger.Fatal(messageTemplate, propertyValues);
    }

    public void Fatal(Exception exception, string messageTemplate)
    {
        if (!IsEnabledInternal(LogLevel.Critical))
            return;

        logger.Fatal(exception, messageTemplate);
    }

    public void Fatal(Exception exception, string messageTemplate, params object[] propertyValues)
    {
        if (!IsEnabledInternal(LogLevel.Critical))
            return;

        logger.Fatal(exception, messageTemplate, propertyValues);
    }

    public void Info(string message)
    {
        if (!IsEnabledInternal(LogLevel.Information))
            return;

        logger.Information(message);
    }

    public void Info(string messageTemplate, params object[] propertyValues)
    {
        if (!IsEnabledInternal(LogLevel.Information))
            return;

        logger.Information(messageTemplate, propertyValues);
    }

    public void Info(Exception exception, string messageTemplate)
    {
        if (!IsEnabledInternal(LogLevel.Information))
            return;

        logger.Information(exception, messageTemplate);
    }

    public void Info(Exception exception, string messageTemplate, params object[] propertyValues)
    {
        if (!IsEnabledInternal(LogLevel.Information))
            return;

        logger.Information(exception, messageTemplate, propertyValues);
    }

    public void Verbose(string message)
    {
        if (!IsEnabledInternal(LogLevel.Trace))
            return;

        logger.Verbose(message);
    }

    public void Verbose(string messageTemplate, params object[] propertyValues)
    {
        if (!IsEnabledInternal(LogLevel.Trace))
            return;

        logger.Verbose(messageTemplate, propertyValues);
    }

    public void Verbose(Exception exception, string messageTemplate)
    {
        if (!IsEnabledInternal(LogLevel.Trace))
            return;

        logger.Verbose(exception, messageTemplate);
    }

    public void Verbose(Exception exception, string messageTemplate, params object[] propertyValues)
    {
        if (!IsEnabledInternal(LogLevel.Trace))
            return;

        logger.Verbose(exception, messageTemplate, propertyValues);
    }

    public void Warning(string message)
    {
        if (!IsEnabledInternal(LogLevel.Warning))
            return;

        logger.Warning(message);
    }

    public void Warning(string messageTemplate, params object[] propertyValues)
    {
        if (!IsEnabledInternal(LogLevel.Warning))
            return;

        logger.Warning(messageTemplate, propertyValues);
    }

    public void Warning(Exception exception, string messageTemplate)
    {
        if (!IsEnabledInternal(LogLevel.Warning))
            return;

        logger.Warning(exception, messageTemplate);
    }

    public void Warning(Exception exception, string messageTemplate, params object[] propertyValues)
    {
        if (!IsEnabledInternal(LogLevel.Warning))
            return;

        logger.Warning(exception, messageTemplate, propertyValues);
    }


    private bool IsEnabledInternal(LogLevel logLevel)
    {
        switch (logLevel)
        {
            case LogLevel.Trace:
            case LogLevel.Debug:
            {
                return logger.IsEnabled(LogEventLevel.Debug) || logger.IsEnabled(LogEventLevel.Verbose);
            }
            case LogLevel.Information:
            {
                return logger.IsEnabled(LogEventLevel.Information);
            }
            case LogLevel.Warning:
            {
                return logger.IsEnabled(LogEventLevel.Warning);
            }
            case LogLevel.Error:
            {
                return logger.IsEnabled(LogEventLevel.Error);
            }

            case LogLevel.Critical:
            {
                return logger.IsEnabled(LogEventLevel.Fatal);
            }
            case LogLevel.None:
            default:
            {
                return false;
            }
        }
    }

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
    {
        if (formatter == null)
        {
            throw new ArgumentNullException(nameof(formatter));
        }
        
        var message = formatter(state, exception);

        switch (logLevel)
        {
            case LogLevel.Trace:
            case LogLevel.Debug:
                this.Debug(exception, message);
                break;
            case LogLevel.Information:
                this.Info(exception, message);
                break;
            case LogLevel.Warning:
                this.Warning(exception, message);
                break;
            case LogLevel.Error:
                this.Error(exception, message);
                break;
            case LogLevel.Critical:
                this.Fatal(exception, message);
                break;
            case LogLevel.None:
            default:
                break;
        }
    }

    public bool IsEnabled(LogLevel logLevel)
    {
        return IsEnabledInternal(logLevel);
    }

    public IDisposable BeginScope<TState>(TState state)
    {
        return NullScope.Instance;
    }
}