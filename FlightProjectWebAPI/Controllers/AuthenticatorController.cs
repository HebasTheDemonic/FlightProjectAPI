using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using FlightProject;
using FlightProject.Exceptions;
using FlightProject.Facades;
using FlightProject.POCOs;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace FlightProject_WebAPI.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthenticatorController : ControllerBase
    {
        private const string securitykey = "7133743677397A244326462948404D635166546A576E5A7234753778214125442A472D4B614E645267556B58703273357638792F423F4528482B4D6251655368";
        private SymmetricSecurityKey symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(securitykey));

        public IActionResult Authenticator([FromQuery]string username, [FromQuery]string password)
        {
            User user = new User(username, password);
            IActionResult result = SafeExecute(() =>
            {
                FlyingCenterSystem flyingCenterSystem = FlyingCenterSystem.GetInstance();
                int facadeIndex = flyingCenterSystem.UserLogin(user.Username, user.Password);
                if (FlyingCenterSystem.FacadeList[facadeIndex].GetType() != typeof(AnonymousUserFacade))
                {
                    string token = CreateToken(facadeIndex);
                    return Created("", token);
                }
                return Unauthorized();

            });
            return result;
        }


        private string CreateToken(int facadeIndex)
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            ClaimsIdentity claims = new ClaimsIdentity();

            if(FlyingCenterSystem.FacadeList[facadeIndex] is LoggedInAdministratorFacade)
            {
                LoginToken<Administrator> token = GetToken(FlyingCenterSystem.FacadeList[facadeIndex] as LoggedInAdministratorFacade);
                claims = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, token.User.Username),
                    new Claim(ClaimTypes.Role, token.User.GetType().ToString()),
                    new Claim("FacadeListLocation", facadeIndex.ToString())
                });
            }

            if (FlyingCenterSystem.FacadeList[facadeIndex] is LoggedInAirlineFacade)
            {
                LoginToken<AirlineCompany> token = GetToken(FlyingCenterSystem.FacadeList[facadeIndex] as LoggedInAirlineFacade);
                claims = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, token.User.Username),
                    new Claim(ClaimTypes.Role, token.User.GetType().ToString()),
                    new Claim("FacadeListLocation", facadeIndex.ToString())
                });
            }

            if (FlyingCenterSystem.FacadeList[facadeIndex] is LoggedInCustomerFacade)
            {
                LoginToken<Customer> token = GetToken(FlyingCenterSystem.FacadeList[facadeIndex] as LoggedInCustomerFacade);
                claims = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, token.User.Username),
                    new Claim(ClaimTypes.Role, token.User.GetType().ToString()),
                    new Claim("FacadeListLocation", facadeIndex.ToString())
                });
            }

            DateTime issuedAt = DateTime.UtcNow;
            DateTime expiresAt = DateTime.UtcNow.AddDays(1);

            SigningCredentials signingCredentials = new SigningCredentials(symmetricSecurityKey, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256Signature);

            JwtSecurityToken jwtSecurityToken = (JwtSecurityToken)tokenHandler.CreateJwtSecurityToken
                (
                    issuer: "FlightSystem",
                    subject: claims,
                    signingCredentials: signingCredentials,
                    issuedAt: issuedAt,
                    expires: expiresAt
                );
            string tokenString = tokenHandler.WriteToken(jwtSecurityToken);
            return tokenString;
        }

        private LoginToken<Administrator> GetToken(LoggedInAdministratorFacade administratorFacade)
        {
            LoginToken<Administrator> loginToken = administratorFacade.LoginToken;
            return loginToken;
        }

        private LoginToken<Customer> GetToken(LoggedInCustomerFacade customerFacade)
        {
            LoginToken<Customer> loginToken = customerFacade.LoginToken;
            return loginToken;
        }

        private LoginToken<AirlineCompany> GetToken(LoggedInAirlineFacade airlineFacade)
        {
            LoginToken<AirlineCompany> loginToken = airlineFacade.LoginToken;
            return loginToken;
        }

        #region SafeExecute Method
        /// <summary>
        /// A method for all general try-catch instances
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        /// <param name="func"/>
        private IActionResult SafeExecute(Func<IActionResult> func)
        {
            try
            {
                return func.Invoke();
            }
            catch (UserNotFoundException ex)
            {
                return NotFound(ex.Message);
            }
            catch (UserAlreadyExistsException ex)
            {
                return Conflict(ex.Message);
            }
            catch (WrongPasswordException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (SqlException)
            {
                return new StatusCodeResult(StatusCodes.Status503ServiceUnavailable);
            }
          //  catch (Exception)
          //  {
          //      return new StatusCodeResult(StatusCodes.Status500InternalServerError);
          //  }
        }
        #endregion
    }
}