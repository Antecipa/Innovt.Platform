﻿// INNOVT TECNOLOGIA 2014-2021
// Author: Michel Magalhães
// Project: Innovt.Domain.Core
// Solution: Innovt.Platform
// Date: 2021-05-03
// Contact: michel@innovt.com.br or michelmob@gmail.com

namespace Innovt.Domain.Core.Model
{
    public class SimpleVo<T> : ValueObject<T> where T : struct
    {
        public SimpleVo()
        {
        }

        public SimpleVo(T id, string description)
        {
            Id = id;
            Description = description;
        }

        public string Description { get; set; }
    }
}