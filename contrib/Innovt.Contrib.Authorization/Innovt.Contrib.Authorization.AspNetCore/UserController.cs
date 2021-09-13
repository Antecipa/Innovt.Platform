﻿using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Innovt.Contrib.Authorization.Platform.Application;
using Innovt.Contrib.Authorization.Platform.Application.Commands;
using Microsoft.AspNetCore.Mvc;

namespace Innovt.Contrib.Authorization.AspNetCore
{
    [ApiController]
    [Route("Authorization/[controller]")]
    public class UserController : ControllerBase
    {
        private readonly IAuthorizationAppService authorizationAppService;

        public UserController(IAuthorizationAppService authorizationAppService)
        {   
            this.authorizationAppService = authorizationAppService ?? throw new ArgumentNullException(nameof(authorizationAppService));
        }

        [HttpPost("AddUser")]
        [ProducesResponseType((int)HttpStatusCode.OK)]
        [ProducesResponseType((int)HttpStatusCode.Unauthorized)]
        [ProducesResponseType((int)HttpStatusCode.InternalServerError)]
        public async Task<IActionResult> AddUser(AddUserCommand command, CancellationToken cancellationToken =default)
        {
            await authorizationAppService.AddUser(command, cancellationToken);
            
            return Ok();
        }
        
        [HttpDelete("RemoveUser")]
        [ProducesResponseType((int)HttpStatusCode.OK)]
        [ProducesResponseType((int)HttpStatusCode.Unauthorized)]
        [ProducesResponseType((int)HttpStatusCode.InternalServerError)]
        public async Task<IActionResult> RemoveUser(RemoveUserCommand command, CancellationToken cancellationToken = default)
        {
            await authorizationAppService.RemoveUser(command, cancellationToken);

            return Ok();
        }
    }
}
