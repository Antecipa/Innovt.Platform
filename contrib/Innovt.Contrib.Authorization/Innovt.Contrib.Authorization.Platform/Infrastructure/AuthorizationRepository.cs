﻿// INNOVT TECNOLOGIA 2014-2021
// Author: Michel Magalhães
// Project: Innovt.Authorization.Platform
// Solution: Innovt.Platform
// Date: 2021-05-12
// Contact: michel@innovt.com.br or michelmob@gmail.com

using System;
using System.Collections.Generic;
using System.Data;
using System.Threading;
using System.Threading.Tasks;
using Innovt.Cloud.AWS.Configuration;
using Innovt.Cloud.AWS.Dynamo;
using Innovt.Contrib.Authorization.Platform.Domain;
using Innovt.Contrib.Authorization.Platform.Domain.Filters;
using Innovt.Contrib.Authorization.Platform.Infrastructure.DataModel;
using Innovt.Core.CrossCutting.Log;
using Innovt.Domain.Security;
using IAuthorizationRepository = Innovt.Contrib.Authorization.Platform.Domain.IAuthorizationRepository;

namespace Innovt.Contrib.Authorization.Platform.Infrastructure
{


    internal class AuthorizationRepository : Repository, IAuthorizationRepository
    {
        public AuthorizationRepository(ILogger logger, IAwsConfiguration awsConfiguration) : base(logger, awsConfiguration)
        {
        }

        //public async Task AddPermission(Permission permission,CancellationToken cancellationToken = default)
        //{
        //    Check.NotNull(permission, nameof(permission));
            
        //    await AddAsync(PermissionDataModel.FromPermission(permission), cancellationToken).ConfigureAwait(false);
        //}

       
        //public Task<IList<Permission>> GetUserPermissions(string userId, string domain = null, string resource = null)
        //{
        //    if (categoryFilter == null) throw new ArgumentNullException(nameof(categoryFilter));

        //    var request = new Innovt.Cloud.Table.QueryRequest()
        //    {
        //        KeyConditionExpression = $"PK = :pk AND begins_with(SK,:sk)",
        //        Filter = new { pk = $"C#{categoryFilter.UserIdentity.CompanyId}", sk = $"S#True#CAT#" },
        //        AttributesToGet = "CategoryName,CategoryIconUrl,CategoryId"
        //    };

        //    var category = await base.QueryAsync<DashboardDataModel>(request, cancellationToken).ConfigureAwait(false);

        //    return CategoryDataModel.ToCategory(category);
        //}
        public async Task AddPermission(Permission permission, CancellationToken cancellationToken = default)
        {
            if (permission is null)
            {
                throw new ArgumentNullException(nameof(permission));
            }

            var permissionDataModel = PermissionDataModel.FromPermission(permission);

            await base.AddAsync(permissionDataModel, cancellationToken).ConfigureAwait(false);
        }

        public async Task RemovePermission(Permission permission, CancellationToken cancellationToken = default)
        {
            if (permission is null)
            {
                throw new ArgumentNullException(nameof(permission));
            }

            var permissionDataModel = PermissionDataModel.FromPermission(permission);

            await base.DeleteAsync(permissionDataModel, cancellationToken).ConfigureAwait(false);
        }

        public Task<Permission> GetPermissionsById(Guid permissionId, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public async  Task AddRole(Role role, CancellationToken cancellationToken = default)
        {
            if (role is null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            var roleDataModel = RoleDataModel.FromRole(role);

            await base.AddAsync(roleDataModel, cancellationToken).ConfigureAwait(false);
        }

        public async Task RemoveRole(Role role, CancellationToken cancellationToken = default)
        {
            if (role is null)throw new ArgumentNullException(nameof(role));            

            var roleDataModel = RoleDataModel.FromRole(role);

            await base.DeleteAsync(roleDataModel, cancellationToken).ConfigureAwait(false);
        }

        public Task<Role> GetRoleById(Guid roleId, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<Role> GetRoleByName(string name, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task UpdateRole(Role role, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public async Task AddGroup(Group @group, CancellationToken cancellationToken = default)
        {
            if (@group is null)
            {
                throw new ArgumentNullException(nameof(@group));
            }

            var groupDataModel = GroupDataModel.FromGroup(@group);

            await base.AddAsync(groupDataModel, cancellationToken).ConfigureAwait(false);
        }

        public Task UpdateGroup(Group @group, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<Group> GetGroupById(Guid groupId, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<Group> GetGroupBy(string name, string domain, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }


        public Task RemoveGroup(Group @group, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<IList<Group>> GetGroupsBy(string name, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<IList<Group>> GetUserGroups(string userId, CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<IList<Permission>> GetPermissionsBy(string domain = null, string resource = null, string name = null,
            CancellationToken cancellationToken = default)
        {
            throw new NotImplementedException();
        }

        public Task<IList<Permission>> GetUserPermissions(string userId, string domain = null, string resource = null,
            CancellationToken cancellationToken = default)
        {
            //if (categoryFilter == null) throw new ArgumentNullException(nameof(categoryFilter));

            //var request = new Innovt.Cloud.Table.QueryRequest()
            //{
            //    KeyConditionExpression = $"PK = :pk AND begins_with(SK,:sk)",
            //    Filter = new { pk = $"C#", sk = $"S#True#CAT#" },
            //    AttributesToGet = "CategoryName,CategoryIconUrl,CategoryId"
            //};
            //

            //var category = await base.QueryAsync<DashboardDataModel>(request, cancellationToken).ConfigureAwait(false);
            return null;
        }
     
        public async Task<Domain.AdminUser> GetAdminUser(UserFilter userFilter, CancellationToken cancellationToken)
        {
            var request = new Innovt.Cloud.Table.QueryRequest()
            {
                KeyConditionExpression = $"PK=:pk AND SK=:sk",
                Filter = new { pk = $"MU#{userFilter.Email}", sk= "ADMINUSER" }
            };

            var user = await base.QueryFirstOrDefaultAsync<UserDataModel>(request, cancellationToken).ConfigureAwait(false);

            return UserDataModel.ToUser(user);
        }
        public async Task Save(Domain.AdminUser adminUser, CancellationToken cancellationToken)
        {
            if (adminUser is null)
            {
                throw new ArgumentNullException(nameof(adminUser));
            }

            var user = UserDataModel.FromUser(adminUser);

            await base.AddAsync(user, cancellationToken).ConfigureAwait(false);
        }
    }
}