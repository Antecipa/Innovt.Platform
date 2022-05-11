﻿// INNOVT TECNOLOGIA 2014-2021
// Author: Michel Magalhães
// Project: Innovt.Domain.Core
// Solution: Innovt.Platform
// Date: 2021-06-02
// Contact: michel@innovt.com.br or michelmob@gmail.com

using System;
using System.Linq.Expressions;

namespace Innovt.Domain.Core.Specification;

/// <summary>
///     True specification
/// </summary>
/// <typeparam name="TValueObject">Type of entity in this specification</typeparam>
public sealed class TrueSpecification<TEntity>
    : Specification<TEntity>
    where TEntity : class
{
    #region Specification overrides

    /// <summary>
    ///     <see cref=" Specification{TEntity}" />
    /// </summary>
    /// <returns>
    ///     <see cref=" Specification{TEntity}" />
    /// </returns>
    public override Expression<Func<TEntity, bool>> SatisfiedBy()
    {
        //Create "result variable" transform adhoc execution plan in prepared plan
        //for more info: http://geeks.ms/blogs/unai/2010/07/91/ef-4-0-performance-tips-1.aspx
        var result = true;

        Expression<Func<TEntity, bool>> trueExpression = t => result;
        return trueExpression;
    }

    #endregion
}