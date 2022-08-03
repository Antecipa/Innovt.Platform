﻿using ConsoleAppTest.DataModels;
using ConsoleAppTest.Domain;
using Innovt.Cloud.AWS.Configuration;
using Innovt.Cloud.AWS.Dynamo;
using Innovt.Cloud.Table;
using Innovt.Core.CrossCutting.Log;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace ConsoleAppTest;

public class InvoiceRepository : Repository
{
    public InvoiceRepository(ILogger logger, IAwsConfiguration configuration) : base(logger, configuration)
    {
    }


    public async Task SaveAll(IList<InvoicesAggregationCompanyDataModel> dataModels)
    {
        try
        {
            //Cria as entradas antes,
            //atualiza as entradas
            var transactionRequest = new TransactionWriteRequest();

            foreach (var dataModel in dataModels)
            {
                //transactionRequest.TransactItems.Add(new TransactionWriteItem()
                //{
                //    TableName = "InvoicesAggregation",
                //    Items = new Dictionary<string, object>
                //    {
                //        { "PK", dataModel.PK },
                //        { "SK1", dataModel.SK1 },
                //        {
                //            "TotalValue",dataModel.TotalValue
                //        },
                //        {
                //            "Quantity",dataModel.Quantity
                //        }
                //    },
                //    OperationType = TransactionWriteOperationType.Put,
                //    ConditionExpression = "attribute_not_exists(PK)",
                //});

                transactionRequest.TransactItems.Add(new TransactionWriteItem()
                {
                    TableName = "InvoicesAggregation",
                    Keys = new Dictionary<string, object>
                {
                    { "PK", dataModel.PK },
                    { "SK1", dataModel.SK1 }
                },
                    OperationType = TransactionWriteOperationType.Update,
                    UpdateExpression = "SET TotalValue = TotalValue + :tot, Quantity = Quantity + :qty ",
                    ExpressionAttributeValues = new Dictionary<string, object>
                    {
                        {
                            ":tot",dataModel.TotalValue
                        },
                        {
                            ":qty",dataModel.Quantity
                        }
                    }
                });
                //transactionRequest.TransactItems.Add(new TransactionWriteItem()
                //{
                //    TableName = "InvoicesAggregation",
                //    Keys = new Dictionary<string, object>
                //    {
                //        { "PK", dataModel.PK },
                //        { "SK1", dataModel.SK1 }
                //    },
                //    OperationType = TransactionWriteOperationType.Check,
                //    UpdateExpression = "SET TotalValue = TotalValue + :tot, Quantity = Quantity + :qty ",
                //    ExpressionAttributeValues = new Dictionary<string, object>
                //    {
                //        {
                //            ":tot",dataModel.TotalValue
                //        },
                //        {
                //            ":qty",dataModel.TotalValue
                //        }
                //    }
                //});
            }
            await TransactWriteItemsAsync(transactionRequest, CancellationToken.None);


        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
        //await UpdateAsync(databaseObject.TableName, databaseObject.Keys, databaseObject.AttributeValueUpdate, cancellationToken);


    }

    public async Task<List<UserDataModel>> GetBatchUsers()
    {
        try
        {
            //Cria as entradas antes,
            //atualiza as entradas
            var getRequest = new BatchGetItemRequest();

            getRequest.AddItem("Users", new BatchGetItemRequestItem()
            {
                ConsistentRead = true,
                Keys = new List<Dictionary<string, object>>
                {
                    new Dictionary<string, object>(){
                        {"PK", "U#b9909dfa-bd94-4370-80be-43d183545185" },
                        {"SK", "PROFILE" }
                    },
                     new Dictionary<string, object>(){
                        {"PK", "U#9828d40c-9122-4cbf-89e7-f53ca0de9b18" },
                        {"SK", "PROFILE" }
                    },
                     new Dictionary<string, object>(){
                        {"PK", "U#9c3db849-a690-4c60-afd2-0af09fc755f2" },
                        {"SK", "PROFILE" }
                    }

                }
            }); 

            return await BatchGetItem<UserDataModel>(getRequest, CancellationToken.None);
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            throw;
        }
        //await UpdateAsync(databaseObject.TableName, databaseObject.Keys, databaseObject.AttributeValueUpdate, cancellationToken);


    }

}