﻿// INNOVT TECNOLOGIA 2014-2021
// Author: Michel Magalhães
// Project: Innovt.Cloud
// Solution: Innovt.Platform
// Date: 2021-06-02
// Contact: michel@innovt.com.br or michelmob@gmail.com

namespace Innovt.Cloud.Queue
{
    public class MessageBatchRequest
    {
        public string Id { get; set; }

        public object Message { get; set; }
    }
}