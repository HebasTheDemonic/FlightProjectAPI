using System;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Linq;
using System.Threading.Tasks;
using FlightProject;
using FlightProject.Exceptions;
using FlightProject.Facades;
using FlightProject.POCOs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace FlightProject_WebAPI.Controllers
{
    [Route("api/")]
    [ApiController]
    [Authorize(Roles = "Administrator")]
    public class AdministratorFacadeController : ControllerBase
    {
        #region POST Methods

        #region Create airline
        /// <summary>
        /// Create a new airline company
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        /// <param name="airline"/>
        [Produces(typeof(string))]
        [Route("airline/post", Name = "CreateNewAirline")]
        [HttpPost]
        public IActionResult CreateNewAirline([FromBody]AirlineCompany airline)
        {
            IActionResult result = SafeExecute(() =>
            {
                int facadeIndex = RetriveFacadeIndex();
                LoggedInAdministratorFacade administratorFacade = (LoggedInAdministratorFacade)FlyingCenterSystem.FacadeList[facadeIndex];
                administratorFacade.CreateNewAirline(administratorFacade.LoginToken, airline);
                return Ok();
            });
            return result;
        }
        #endregion

        #region Create customer
        /// <summary>
        /// Create a new customer
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        /// <param name="customer"/>
        [Produces(typeof(string))]
        [Route("customer/post/byadmin", Name = "CreateNewCustomer")]
        [HttpPost]
        public IActionResult CreateNewCustomer([FromBody]Customer customer)
        {
            IActionResult result = SafeExecute(() =>
            {
                int facadeIndex = RetriveFacadeIndex();
                LoggedInAdministratorFacade administratorFacade = (LoggedInAdministratorFacade)FlyingCenterSystem.FacadeList[facadeIndex];
                administratorFacade.CreateNewCustomer(administratorFacade.LoginToken, customer);
                return Ok();
            });
            return result;
        }
        #endregion

        #region Create Administrator
        /// <summary>
        /// Create a new administrator
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        /// <param name="administrator"/>
        [Produces(typeof(string))]
        [Route("admin/post", Name = "CreateNewAdministator")]
        [HttpPost]
        public IActionResult CreateNewAdministrator([FromBody]Administrator administrator)
        {
            IActionResult result = SafeExecute(() =>
            {
                int facadeIndex = RetriveFacadeIndex();
                LoggedInAdministratorFacade administratorFacade = (LoggedInAdministratorFacade)FlyingCenterSystem.FacadeList[facadeIndex];
                administratorFacade.CreateNewAdministrator(administratorFacade.LoginToken, administrator);
                return Ok();
            });
            return result;
        }
        #endregion

        #region Create country
        /// <summary>
        /// Create a new country
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        /// <param name="country"/>
        [Produces(typeof(string))]
        [Route("customer/post", Name = "CreateCountry")]
        [HttpPost]
        public IActionResult CreateCountry([FromBody]Country country)
        {
            IActionResult result = SafeExecute(() =>
            {
                int facadeIndex = RetriveFacadeIndex();
                LoggedInAdministratorFacade administratorFacade = (LoggedInAdministratorFacade)FlyingCenterSystem.FacadeList[facadeIndex];
                administratorFacade.CreateCountry(administratorFacade.LoginToken, country);
                return Ok();
            });
            return result;
        }
        #endregion

        #endregion

        #region PUT Methods

        #region Update airline Company
        /// <summary>
        /// Update the data of an existing airline company
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        /// <param name="airline"/>
        [Produces(typeof(string))]
        [Route("airline/put", Name = "UpdateAirline")]
        [HttpPut]
        public IActionResult UpdateAirline([FromBody]AirlineCompany airline)
        {
            IActionResult result = SafeExecute(() =>
            {
                int facadeIndex = RetriveFacadeIndex();
                LoggedInAdministratorFacade administratorFacade = (LoggedInAdministratorFacade)FlyingCenterSystem.FacadeList[facadeIndex];
                administratorFacade.UpdateAirlineDetails(administratorFacade.LoginToken, airline);
                return Ok();
            });
            return result;
        }
        #endregion

        #region Update customer
        /// <summary>
        /// Update the data of an existing customer
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        /// <param name="customer"/>
        [Produces(typeof(string))]
        [Route("customer/put", Name = "UpdateCustomer")]
        [HttpPut]
        public IActionResult UpdateCustomer([FromBody]Customer customer)
        {
            IActionResult result = SafeExecute(() =>
            {
                int facadeIndex = RetriveFacadeIndex();
                LoggedInAdministratorFacade administratorFacade = (LoggedInAdministratorFacade)FlyingCenterSystem.FacadeList[facadeIndex];
                administratorFacade.UpdateCustomerDetails(administratorFacade.LoginToken, customer);
                return Ok();
            });
            return result;
        }
        #endregion

        #region Update Administrator
        /// <summary>
        /// Update the data of an existing Administator
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        /// <param name="administrator"/>
        [Produces(typeof(string))]
        [Route("admin/put", Name = "UpdateAdministrator")]
        [HttpPut]
        public IActionResult UpdateAdministrator([FromBody]Administrator administrator)
        {
            IActionResult result = SafeExecute(() =>
            {
                int facadeIndex = RetriveFacadeIndex();
                LoggedInAdministratorFacade administratorFacade = (LoggedInAdministratorFacade)FlyingCenterSystem.FacadeList[facadeIndex];
                administratorFacade.UpdateAdministrator(administratorFacade.LoginToken, administrator);
                return Ok();
            });
            return result;
        }
        #endregion

        #region Update country
        /// <summary>
        /// Update the data of an existing country
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        /// <param name="country"/>
        [Produces(typeof(string))]
        [Route("country/put", Name = "UpdateCountry")]
        [HttpPut]
        public IActionResult UpdateCountry([FromBody]Country country)
        {
            IActionResult result = SafeExecute(() =>
            {
                int facadeIndex = RetriveFacadeIndex();
                LoggedInAdministratorFacade administratorFacade = (LoggedInAdministratorFacade)FlyingCenterSystem.FacadeList[facadeIndex];
                administratorFacade.UpdateCountry(administratorFacade.LoginToken, country);
                return Ok();
            });
            return result;
        }
        #endregion

        #endregion

        #region DELETE Methods

        #region Delete airline
        /// <summary>
        /// Delete a registered airline company
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        /// <param name="airline"/>
        [Produces(typeof(string))]
        [Route("airline/delete", Name = "DeleteAirline")]
        [HttpDelete]
        public IActionResult DeleteAirline([FromBody]AirlineCompany airline)
        {
            IActionResult result = SafeExecute(() =>
            {
                int facadeIndex = RetriveFacadeIndex();
                LoggedInAdministratorFacade administratorFacade = (LoggedInAdministratorFacade)FlyingCenterSystem.FacadeList[facadeIndex];
                administratorFacade.RemoveAirline(administratorFacade.LoginToken, airline);
                return Ok();
            });
            return result;
        }
        #endregion

        #region Delete customer
        /// <summary>
        /// Delete a registered customer
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        /// <param name="customer"/>
        [Produces(typeof(string))]
        [Route("customer/delete", Name = "DeleteCustomer")]
        [HttpDelete]
        public IActionResult DeleteCustomer([FromBody]Customer customer)
        {
            IActionResult result = SafeExecute(() =>
            {
                int facadeIndex = RetriveFacadeIndex();
                LoggedInAdministratorFacade administratorFacade = (LoggedInAdministratorFacade)FlyingCenterSystem.FacadeList[facadeIndex];
                administratorFacade.RemoveCustomer(administratorFacade.LoginToken, customer);
                return Ok();
            });
            return result;
        }
        #endregion

        #region Delete administrator
        /// <summary>
        /// Delete a registered administrator
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        /// <param name="administrator"/>
        [Produces(typeof(string))]
        [Route("admin/delete", Name = "DeleteAdministrator")]
        [HttpDelete]
        public IActionResult DeleteAdministrator([FromBody]Administrator administrator)
        {
            IActionResult result = SafeExecute(() =>
            {
                int facadeIndex = RetriveFacadeIndex();
                LoggedInAdministratorFacade administratorFacade = (LoggedInAdministratorFacade)FlyingCenterSystem.FacadeList[facadeIndex];
                administratorFacade.RemoveAdministrator(administratorFacade.LoginToken, administrator);
                return Ok();
            });
            return result;
        }
        #endregion

        #region Delete country
        /// <summary>
        /// Delete a registered administrator
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        /// <param name="country"/>
        [Produces(typeof(string))]
        [Route("country/delete", Name = "DeleteCountry")]
        [HttpDelete]
        public IActionResult DeleteCountry([FromBody]Country country)
        {
            IActionResult result = SafeExecute(() =>
            {
                int facadeIndex = RetriveFacadeIndex();
                LoggedInAdministratorFacade administratorFacade = (LoggedInAdministratorFacade)FlyingCenterSystem.FacadeList[facadeIndex];
                administratorFacade.RemoveCountry(administratorFacade.LoginToken, country);
                return Ok();
            });
            return result;
        }
        #endregion

        #endregion

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
            catch (NullReferenceException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (UnauthorizedActionException ex)
            {
                return Conflict(ex.Message);
            }
            catch (WrongPasswordException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (DataAlreadyExistsException ex)
            {
                return Conflict(ex.Message);
            }
            catch (UserAlreadyExistsException ex)
            {
                return Conflict(ex.Message);
            }
            catch (UserNotFoundException ex)
            {
                return BadRequest(ex.Message);
            }
            catch (UnregisteredDataException ex)
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
            catch (Exception)
            {
                return new StatusCodeResult(StatusCodes.Status500InternalServerError);
            }
        }
        #endregion

        #region RetreiveFacadeIndex Method
        /// <summary>
        /// A method for extracting the correct facade index for the current user
        /// </summary>
        /// <returns>
        /// int
        /// </returns>
        private int RetriveFacadeIndex()
        {
            string indexString = HttpContext.User.Claims.Where(c => c.Type.ToString().Equals("FacadeListLocation")).ToString();
            int facadeIndex = Int32.Parse(indexString);
            return facadeIndex;
        }
        #endregion

        #region SingleResultChecker Method
        /// <summary>
        /// A method meant to verify a non-null response to non list result queries
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        /// <param name="poco"/>
        /// <param name="nullResponce"/>
        private IActionResult SingleResultChecker(IPoco poco, string nullResponce)
        {
            IActionResult result;
            if (poco.GetHashCode() == 0)
            {
                result = BadRequest(nullResponce);
            }
            else
            {
                result = Ok(poco);
            }
            return result;
        }
        #endregion
    }
}
