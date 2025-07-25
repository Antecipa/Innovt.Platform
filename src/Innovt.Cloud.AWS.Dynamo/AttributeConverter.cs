﻿// Innovt Company
// Author: Michel Borges
// Project: Innovt.Cloud.AWS.Dynamo

using Amazon.DynamoDBv2.DataModel;
using Amazon.DynamoDBv2.DocumentModel;
using Amazon.DynamoDBv2.Model;
using Innovt.Core.Collections;
using Innovt.Core.Utilities;
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;

namespace Innovt.Cloud.AWS.Dynamo;

/// <summary>
///     A utility class for converting between different attribute types.
/// </summary>
internal static class AttributeConverter
{
    /// <summary>
    ///     An array containing primitive types that can be represented as attributes.
    /// </summary>
    private static readonly Type[] PrimitiveTypesArray = new Type[19]
    {
        typeof(bool),
        typeof(byte),
        typeof(char),
        typeof(DateTime),
        typeof(decimal),
        typeof(double),
        typeof(int),
        typeof(long),
        typeof(sbyte),
        typeof(short),
        typeof(float),
        typeof(string),
        typeof(uint),
        typeof(ulong),
        typeof(ushort),
        typeof(Guid),
        typeof(byte[]),
        typeof(MemoryStream),
        typeof(Primitive)
    };

    private static readonly HashSet<TypeInfo> PrimitiveTypeInfos =
    [
        ..PrimitiveTypesArray.Select(t => t.GetTypeInfo())
    ];

    /// <summary>
    ///     Checks if a given type is a primitive DynamoDB type.
    /// </summary>
    /// <param name="type">The type to check.</param>
    /// <returns>True if the type is primitive; otherwise, false.</returns>
    public static bool IsPrimitive(Type type)
    {
        var typeWrapper = type.GetTypeInfo();
        return PrimitiveTypeInfos.Any(ti => typeWrapper.IsAssignableFrom(ti));
    }

    /// <summary>
    ///     Checks if a given type is a collection (array or IEnumerable).
    /// </summary>
    /// <param name="type">The type to check.</param>
    /// <returns>True if the type is a collection; otherwise, false.</returns>
    public static bool IsCollection(Type type)
    {
        return type.IsArray || (type.IsGenericType && typeof(IEnumerable).IsAssignableFrom(type));
    }

    /// <summary>
    ///     Checks if a given type is a dictionary.
    /// </summary>
    /// <param name="type">The type to check.</param>
    /// <returns>True if the type is a dictionary; otherwise, false.</returns>
    public static bool IsDictionary(Type type)
    {
        return type.IsArray || (type.IsGenericType && typeof(IDictionary<,>).IsAssignableFrom(type)) ||
               typeof(IDictionary).IsAssignableFrom(type);
    }

    /// <summary>
    ///     Converts a dictionary of string and object pairs to DynamoDB AttributeValues.
    /// </summary>
    /// <param name="items">The dictionary to convert.</param>
    /// <returns>A dictionary of string and AttributeValue pairs.</returns>
    internal static Dictionary<string, AttributeValue> ConvertToAttributeValues(Dictionary<string, object> items)
    {
        return items?.Select(i =>
            new
            {
                i.Key,
                Value = CreateAttributeValue(i.Value)
            }).ToDictionary(x => x.Key, x => x.Value);
    }

    /// <summary>
    ///     Conversion from object to attribute Value
    /// </summary>
    /// <param name="value">Any object</param>
    /// <returns></returns>
    internal static AttributeValue CreateAttributeValue(object value)
    {
        switch (value)
        {
            case null:
                return new AttributeValue { NULL = true };

            case MemoryStream stream:
                return new AttributeValue { B = stream };

            case bool:
                return new AttributeValue { BOOL = bool.Parse(value.ToString()) };

            case List<MemoryStream> streams:
                return new AttributeValue { BS = streams };

            case List<string> list:
                return new AttributeValue { SS = list };

            case int or double or float or decimal or long:
                return new AttributeValue { N = value.ToString() };

            case DateTime time:
                return new AttributeValue { S = time.ToString("s") };

            case IList<int> or IList<double> or IList<float> or IList<decimal> or IList<long>:
                {
                    var array = (value as IList).Cast<object>().Select(o => o.ToString()).ToList();

                    return new AttributeValue { NS = array };
                }
            case IDictionary<string, object> objects:
                {
                    var array = objects.ToDictionary(item => item.Key, item => CreateAttributeValue(item.Value));

                    return new AttributeValue { M = array };
                }
            case IList<object> objects:
                {
                    return new AttributeValue { L = objects.Select(CreateAttributeValue).ToList() };
                }
            default:
                return new AttributeValue(value.ToString());
        }
    }

    /// <summary>
    ///     Converts a DynamoDB AttributeValue to an object of the specified desiredType.
    /// </summary>
    /// <param name="value">The DynamoDB AttributeValue to convert.</param>
    /// <param name="desiredType">The desired Type to convert to.</param>
    /// <returns>
    ///     An object of the specified desiredType containing the converted value from the AttributeValue.
    /// </returns>
    internal static object CreateAttributeValueToObject(AttributeValue value, Type desiredType)
    {
        if (value is null)
            return default;

        if (value.IsBOOLSet) return value.BOOL;

        if (value.IsLSet)
            return value.L.Select(l => CreateAttributeValueToObject(l, desiredType.GetGenericArguments()[0])).ToList();

        //Nested Type
        if (value.IsMSet)
        {
            if (IsDictionary(desiredType)) return ItemsToDictionary(desiredType, value.M);

            var method = typeof(AttributeConverter).GetMethod(nameof(ConvertAttributesToType),
                BindingFlags.Static | BindingFlags.NonPublic, null,
                new[] { typeof(Dictionary<string, AttributeValue>) }, null);
            return method?.MakeGenericMethod(desiredType).Invoke(null, new object[] { value.M });
        }

        if (value.BS.IsNotNullOrEmpty()) return value.BS;

        if (value.N is not null) return value.N;

        if (value.NS.IsNotNullOrEmpty()) return value.NS;

        if (value.SS.IsNotNullOrEmpty()) return value.SS;

        return value.S.IsNotNullOrEmpty() ? value.S : default(object);
    }

    /// <summary>
    ///     Converts a collection of items to the specified target type.
    /// </summary>
    /// <param name="targetType">The desired Type to convert the items to.</param>
    /// <param name="items">The collection of items to convert.</param>
    /// <returns>
    ///     An object of the specified target type containing the converted items.
    /// </returns>
    public static object ItemsToCollection(Type targetType, IEnumerable<object> items)
    {
        return !targetType.IsArray ? ItemsToIList(targetType, items) : ItemsToArray(targetType, items);
    }

    /// <summary>
    ///     Converts a dictionary of items to the specified target dictionary type.
    /// </summary>
    /// <param name="targetType">The desired dictionary Type to convert the items to.</param>
    /// <param name="items">The dictionary of items to convert.</param>
    /// <returns>
    ///     An object of the specified target dictionary type containing the converted items, or null if the conversion is not
    ///     supported.
    /// </returns>
    public static object ItemsToDictionary(Type targetType, Dictionary<string, AttributeValue> items)
    {
        if (items is null || targetType is null)
            return null;

        var genericArguments = targetType.GetGenericArguments();

        //not supported
        if (genericArguments.Length != 2)
            return null;

        var dictionary = Activator.CreateInstance(targetType) as IDictionary;

        if (dictionary is null)
            return null;

        var valueType = genericArguments[1];

        foreach (var item in items) dictionary.Add(item.Key, CreateAttributeValueToObject(item.Value, valueType));

        return dictionary;
    }

    /// <summary>
    ///     Retrieves the element type of a collection or array type.
    /// </summary>
    /// <param name="collectionType">The Type representing a collection or array.</param>
    /// <returns>
    ///     The Type of the elements contained within the collection or array, or null if the element type could not be
    ///     determined.
    /// </returns>
    private static Type GetElementType(Type collectionType)
    {
        var elementType = collectionType.GetElementType();

        if (elementType == null)
        {
            var genericArguments = collectionType.GetTypeInfo().GetGenericArguments();
            if (genericArguments is { Length: 1 })
                elementType = genericArguments[0];
        }

        return elementType;
    }

    /// <summary>
    ///     Converts a collection of objects to an array of the specified target type.
    /// </summary>
    /// <param name="targetType">The Type representing the target array type.</param>
    /// <param name="items">The collection of objects to convert to an array.</param>
    /// <returns>
    ///     An array of the specified target type containing the converted objects, or null if the input collection is
    ///     null.
    /// </returns>
    private static object ItemsToArray(Type targetType, IEnumerable<object> items)
    {
        if (items is null)
            return null;

        var list = items.ToList();
        var array = (Array)Activator.CreateInstance(targetType, list.Count);

        var elementType = GetElementType(targetType);

        for (var index = 0; index < list.Count; ++index)
            array.SetValue(IsPrimitive(elementType) ? ConvertType(elementType, list[index]) : list[index], index);

        return array;
    }

    /// <summary>
    ///     Converts a collection of objects to an instance of the specified target type that implements IList.
    /// </summary>
    /// <param name="targetType">The Type representing the target list type.</param>
    /// <param name="items">The collection of objects to convert to a list.</param>
    /// <returns>
    ///     An instance of the specified target type containing the converted objects,
    ///     or null if the input collection is null or the target type cannot be instantiated.
    /// </returns>
    private static object ItemsToIList(Type targetType, IEnumerable<object> items)
    {
        var result = Activator.CreateInstance(targetType);
        var elementType = GetElementType(targetType);

        if (result is IList list)
        {
            foreach (var obj in items) list.Add(IsPrimitive(elementType) ? ConvertType(elementType, obj) : obj);

            return result;
        }

        var method = targetType.GetTypeInfo().GetMethod("Add");

        if (method == null) return null;

        foreach (var obj in items)
            method.Invoke(result, new object[1]
            {
                IsPrimitive(elementType) ? ConvertType(elementType, obj) : obj
            });

        return result;
    }

    /// <summary>
    ///     Gets the PropertyInfo for a property with the specified name in the given set of properties, considering
    ///     case-insensitive matches and custom attributes.
    /// </summary>
    /// <param name="properties">The array of PropertyInfo objects to search for the property.</param>
    /// <param name="propertyName">The name of the property to find.</param>
    /// <param name="declaringType">The Type that declares the property, used to disambiguate properties with the same name.</param>
    /// <returns>
    ///     The PropertyInfo for the property with the specified name, considering case-insensitive matches and custom
    ///     attributes,
    ///     or null if the property is not found or cannot be written to.
    /// </returns>
    private static PropertyInfo GetProperty(PropertyInfo[] properties, string propertyName, Type declaringType)
    {
        var instanceProps = properties.Where(p => p.Name.Equals(propertyName, StringComparison.OrdinalIgnoreCase))
            .ToList();

        //Custom attributes
        if (!instanceProps.Any())
            instanceProps = properties.Where(p => p.GetCustomAttribute<DynamoDBPropertyAttribute>() != null &&
                                                  propertyName.Equals(
                                                      p.GetCustomAttribute<DynamoDBPropertyAttribute>().AttributeName,
                                                      StringComparison.OrdinalIgnoreCase)).ToList();

        if (!instanceProps.Any())
            return null;

        var prop = instanceProps.FirstOrDefault(p => p.DeclaringType == declaringType) ?? instanceProps.First();

        if (prop is null || !prop.CanWrite) return null;

        return prop;
    }

    /// <summary>
    ///     Converts a value to the specified property type, considering type conversion and compatibility workarounds.
    /// </summary>
    /// <param name="propertyType">The target property type to convert the value to.</param>
    /// <param name="value">The value to be converted.</param>
    /// <returns>
    ///     The converted value of the specified property type, or the default value of the property type if the input value is
    ///     null.
    /// </returns>
    private static object ConvertType(Type propertyType, object value)
    {
        if (value is null)
            return default;

        var typeConverter = TypeDescriptor.GetConverter(propertyType);

        if (typeConverter.CanConvertFrom(value.GetType()))
        {
            //workaround compatibility v1 and v2
            if (typeConverter is BooleanConverter && (value.ToString() == "1" || value.ToString() == "0"))
                return typeConverter.ConvertFrom(null!, CultureInfo.InvariantCulture,
                    value.ToString() == "1" ? "true" : "false");

            return typeConverter.ConvertFrom(null!, CultureInfo.InvariantCulture, value);
        }

        var destinationType = Nullable.GetUnderlyingType(propertyType) ?? propertyType;

        return Convert.ChangeType(value, destinationType, CultureInfo.InvariantCulture);
    }

    /// <summary>
    ///     Converts an AttributeValue to a DynamoDBEntry, handling different data types.
    /// </summary>
    /// <param name="attributeValue">The AttributeValue to be converted.</param>
    /// <returns>
    ///     A DynamoDBEntry representing the converted AttributeValue, or a DynamoDBNull if the input is null.
    /// </returns>
    internal static DynamoDBEntry ConvertAttributeValue(AttributeValue attributeValue)
    {
        if (attributeValue is null)
            return new DynamoDBNull();

        if (attributeValue.IsBOOLSet)
            return new DynamoDBBool(attributeValue.BOOL.GetValueOrDefault());

        if (attributeValue.B is not null)
            return new Primitive(attributeValue.B);

        if (attributeValue.N is not null)
            return new Primitive(attributeValue.N, true);

        return new Primitive(attributeValue.S);
    }

    /// <summary>
    ///     Converts a non-primitive property value to the desired type, considering custom converters.
    /// </summary>
    /// <param name="property">The PropertyInfo object representing the property.</param>
    /// <param name="attributeValue">The AttributeValue to be converted.</param>
    /// <param name="value">The current value of the property.</param>
    /// <returns>
    ///     The converted value of the property, considering custom converters if available, or the original value if no custom
    ///     converter is found.
    /// </returns>
    internal static object ConvertNonPrimitiveType(PropertyInfo property, AttributeValue attributeValue, object value)
    {
        if (property.PropertyType.IsEnum)
            return Enum.Parse(property.PropertyType, value.ToString(), true);

        //has converter?
        var customConverter = property.GetCustomAttributes<DynamoDBPropertyAttribute>()
            .SingleOrDefault(a => a.Converter != null);

        if (customConverter is null) return value;

        var convertedEntry = ConvertAttributeValue(attributeValue);

        if (convertedEntry is null)
            return null;

        if (Activator.CreateInstance(customConverter.Converter) is not IPropertyConverter converterInstance)
            return null;

        return converterInstance.FromEntry(convertedEntry);
    }

    /// <summary>
    ///     Convert an attribute array to specific type
    /// </summary>
    /// <typeparam name="T">The desired Type </typeparam>
    /// <param name="items"></param>
    /// <returns></returns>
    internal static T ConvertAttributesToType<T>(Dictionary<string, AttributeValue> items)
    {
        if (items is null) return default;

        var instance = Activator.CreateInstance<T>();
        var properties = instance.GetType()
            .GetProperties(BindingFlags.Instance | BindingFlags.Public | BindingFlags.SetProperty);

        if (!properties.Any())
            return instance;

        foreach (var attributeValue in items)
        {
            var prop = GetProperty(properties, attributeValue.Key, instance.GetType());

            if (prop is null)
                continue;

            object convertedValue = null;
            var value = CreateAttributeValueToObject(attributeValue.Value, prop.PropertyType);

            if (IsPrimitive(prop.PropertyType))
            {
                convertedValue = ConvertType(prop.PropertyType, value);
            }
            else
            {
                if (IsCollection(prop.PropertyType))
                    convertedValue = IsDictionary(prop.PropertyType)
                        ? value
                        : ItemsToCollection(prop.PropertyType, (IEnumerable<object>)value);
                else
                    convertedValue = ConvertNonPrimitiveType(prop, attributeValue.Value, value);
            }

            //setting the converted value
            prop.SetValue(instance, convertedValue, null);
        }

        return instance;
    }
}