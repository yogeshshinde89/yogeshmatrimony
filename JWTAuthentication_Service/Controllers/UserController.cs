using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using JWTAuthentication_Service.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using NLog;

namespace JWTAuthentication_Service.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private static Logger logger = LogManager.GetCurrentClassLogger();
        private readonly UserManager<ApplicationUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly IConfiguration _configuration;
        private readonly int _Newpasswordlength;

        public UserController(IConfiguration config, UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            _configuration = configuration;
            _Newpasswordlength = config.GetValue<int>("Passwordlength");
        }

        [HttpDelete]
        [Route("Deleteuser")]
        [Authorize(Roles = UserRoles.Admin)]
        public async Task<ActionResult> DeleteUser([Required] string username)
        {
            try
            {


                var user = await userManager.FindByNameAsync(username);
                if (username == null || user == null)
                {
                    return NotFound();
                }


                //List Logins associated with user
                //var logins = user.;
                //Gets list of Roles associated with current user

                var rolesForUser = await userManager.GetRolesAsync(user);
                var status = await userManager.DeleteAsync(user);
                if (status.Succeeded == true)
                {
                    return Ok(new Response { Status = "Success", Message = "User Deleted successfully!" });
                }
                else
                {
                    return Ok(new Response { Status = "Failure", Message = "Something went wrong while deleting the record!" });
                }
            }
            catch (Exception ex)
            {
                logger.Error(ex);
                throw;
            }
        }

        [HttpPut]
        [Route("/api/Updatepassword")]
        public async Task<ActionResult> UpdatePassword([Required] string username, [Required] string currentpassword, [Required] string newpassword)
        {
            var user = await userManager.FindByNameAsync(username);

            if (user != null && await userManager.CheckPasswordAsync(user, currentpassword))
            {
                var status = await userManager.ChangePasswordAsync(user, currentpassword, newpassword);
                if (status.Succeeded)
                {
                    return Ok(new Response { Status = "Success", Message = "Password Changed successfully!" });
                }
                else
                {
                    return Ok(new Response { Status = "Error", Message = "Something went wrong while updating password!" });
                }
            }
            else
            {
                return BadRequest(new Response { Status = "Unauthorised", Message = "Password is incorrect!" });
            }
        }

        [HttpGet]
        [Route("/api/GetUserRole")]
        public async Task<IActionResult> Getuserrole(string Username)
        {
            logger.Info(_Newpasswordlength);
            var data = CreateRandomPassword(_Newpasswordlength);
            logger.Info(data);
            try
            {
                var user = await userManager.FindByNameAsync(Username);
                if (user == null)
                {
                    return BadRequest(new Response { Status = "Unauthorised", Message = "Username not found" });
                }
                var userrole = await userManager.GetRolesAsync(user);
                return Ok(userrole);
            }
            catch (Exception ex)
            {
                logger.Error(ex);
                throw;
            }
        }

        private static string CreateRandomPassword(int length)
        {
            //logger.Info(_Newpasswordlength)
            // Create a string of characters, numbers, special characters that allowed in the password  
            string validChars = "ABCDEFGHJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*?_-";
            Random random = new Random();

            // Select one random character at a time from the string  
            // and create an array of chars  
            char[] chars = new char[length];
            for (int i = 0; i < length; i++)
            {
                chars[i] = validChars[random.Next(0, validChars.Length)];
            }
            return new string(chars);
        }

        [HttpPost]
        [Route("/api/ForgotPassword")]
        public async Task<IActionResult> ForgotPassword(string username)
        {
            var newpassword = CreateRandomPassword(_Newpasswordlength);
            var userexists = await userManager.FindByNameAsync(username);
            //var userbyEmail = await userManager.FindByEmailAsync(Email);
            //var us = await userManager.ChangePasswordAsync(userbyname, "", ne);

            if (userexists != null)
            {
                //var re = await userManager.GeneratePasswordResetTokenAsync(userbyname);
                var user = await userManager.FindByIdAsync(userexists.Id);
                var token = await userManager.GeneratePasswordResetTokenAsync(user);
                var result = await userManager.ResetPasswordAsync(user, token, "MyN3wP@ssw0rd");
                if (result.Succeeded == true)
                {
                    return Ok("Success");
                }
                else
                {
                    return Ok("Something went wrong.");
                }
                // var userId = await userManager.GetUserId(
                //var token = await userManager.GeneratePasswordResetTokenAsync(userbyEmail);

                // var result = await userManager.ResetPasswordAsync(userId, token, newPassword);
                // var r = await userManager.generat
            }
            return BadRequest(new Response { Status = "Unauthorised", Message = "Username not found" });
        }

    }
}
