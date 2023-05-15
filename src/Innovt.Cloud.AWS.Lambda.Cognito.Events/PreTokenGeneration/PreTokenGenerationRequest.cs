﻿// Innovt Company
// Author: Michel Borges
// Project: Innovt.Cloud.AWS.Lambda.Cognito.Events

using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Text.Json.Serialization;
using System.Xml.Linq;
using Amazon.Lambda.CognitoEvents;

namespace Innovt.Cloud.AWS.Lambda.Cognito.Events.PreTokenGeneration;

public class PreTokenGenerationRequest : TriggerRequest
{
    [DataMember(Name = "groupConfiguration")]
    [JsonPropertyName("groupConfiguration")]
    public GroupConfiguration GroupConfiguration { get; set; } = new GroupConfiguration();


    [DataMember(Name = "clientMetadata")]
    [JsonPropertyName("clientMetadata")]
    public Dictionary<string, string> ClientMetadata { get; set; } = new Dictionary<string, string>();
}