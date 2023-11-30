﻿// Innovt Company
// Author: Michel Borges
// Project: Innovt.CrossCutting.Log.Serilog

using Serilog.Core;
using Serilog.Events;
using System;
using System.Diagnostics;

namespace Innovt.CrossCutting.Log.Serilog;

public class DataDogEnrich : ILogEventEnricher
{
    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        if (logEvent is null) throw new ArgumentNullException(nameof(logEvent));

        var activity = GetActivity();

        if (activity is null)
            return;

        var ddTraceId = Convert.ToUInt64(activity.TraceId.ToString().Substring(16), 16).ToString();
        var ddSpanId = Convert.ToUInt64(activity.SpanId.ToString(), 16).ToString();
        logEvent.AddOrUpdateProperty(new LogEventProperty("dd.trace_id", new ScalarValue(ddTraceId)));
        logEvent.AddOrUpdateProperty(new LogEventProperty("dd.span_id", new ScalarValue(ddSpanId)));

        try
        {
            var ddParentId = Convert.ToUInt64(activity.ParentId.ToString().Substring(16), 16).ToString();
            logEvent.AddOrUpdateProperty(new LogEventProperty("dd.parent_id", new ScalarValue(ddParentId)));
        }
        catch (Exception) { }
    }

#pragma warning disable CA1822 // Mark members as static

    private static Activity GetActivity()
#pragma warning restore CA1822 // Mark members as static
    {
        return Activity.Current ?? null;
    }
}