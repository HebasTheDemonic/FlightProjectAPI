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
    /// <summary>
    /// Controller for all Logged In Customer Facade methods
    /// </summary>
    [Route("api/")]
    [ApiController]
    [Authorize(Roles = "Customer")]
    public class CustomerFacadeController : ControllerBase
    {
        #region Get all flights for current customer
        /// <summary>
        /// Get a list of current customer's flights
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        [Produces(typeof(IList<Flight>))]
        [Route("ticket/getbycustomer", Name = "GetAllMyFlights")]
        [HttpGet]
        public IActionResult GetAllMyFlights()
        {
            IActionResult result = SafeExecute(() =>
            {
                int facadeIndex = RetriveFacadeIndex();
                LoggedInCustomerFacade customerFacade = (LoggedInCustomerFacade)FlyingCenterSystem.FacadeList[facadeIndex];
                List<Flight> flights = (List<Flight>)customerFacade.GetAllMyFlights(customerFacade.LoginToken);
                if (flights.Count < 1)
                {
                    return NoContent();
                }
                return Ok(flights);
            });
            return result;
        }
        #endregion

        #region Create a new ticket for current customer
        /// <summary>
        /// Create a new ticket assosiated with current customer
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        /// <param name="flightId"/>
        [Produces(typeof(Ticket))]
        [Route("ticket/post", Name = "CreateTicket")]
        [HttpPost]
        public IActionResult CreateTicket([FromQuery]int flightId)
        {
            IActionResult result = SafeExecute(() =>
            {
                int facadeIndex = RetriveFacadeIndex();
                LoggedInCustomerFacade customerFacade = (LoggedInCustomerFacade)FlyingCenterSystem.FacadeList[facadeIndex];
                Ticket ticket = customerFacade.PurchaseTicket(customerFacade.LoginToken, flightId);
                return Ok();
            });
            return result;
        }
        #endregion

        #region Delete a ticket belonging to current customer
        /// <summary>
        /// Delete an existing ticket
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        /// <param name="ticket"/>
        [Produces(typeof(string))]
        [Route("ticket/delete", Name = "DeleteTicket")]
        [HttpDelete]
        public IActionResult DeleteTicket([FromBody]Ticket ticket)
        {
            IActionResult result = SafeExecute(() =>
            {
                int facadeIndex = RetriveFacadeIndex();
                LoggedInCustomerFacade customerFacade = (LoggedInCustomerFacade)FlyingCenterSystem.FacadeList[facadeIndex];
                customerFacade.CancelTicket(customerFacade.LoginToken, ticket);
                return Ok();
            });
            return result;
        }
        #endregion

        #region Update customer details
        /// <summary>
        /// Update details for the current customer
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        /// <param name="customer"/>
        [Produces(typeof(string))]
        [Route("customer/put/bycustomer/details", Name = "UpdateCustomerDetails")]
        [HttpPut]
        public IActionResult UpdateCustomerDetails([FromBody]Customer customer)
        {
            IActionResult result = SafeExecute(() =>
            {
                int facadeIndex = RetriveFacadeIndex();
                LoggedInCustomerFacade customerFacade = (LoggedInCustomerFacade)FlyingCenterSystem.FacadeList[facadeIndex];
                customerFacade.ModifyCustomerDetails(customerFacade.LoginToken, customer);
                if (customerFacade.LoginToken.User != customer)
                {
                    return new StatusCodeResult(StatusCodes.Status304NotModified);
                }
                return Ok();
            });
            return result;
        }
        #endregion

        #region Change customer password
        /// <summary>
        /// Change current customers password
        /// </summary>
        /// <returns>
        /// IActionResult
        /// </returns>
        /// <param name="newPassword"/>
        /// <param name="oldPassword"/>
        [Produces(typeof(string))]
        [Route("customer/put/bycustomer/password", Name = "ChangeCustomerPassword")]
        [HttpPut]
        public IActionResult ChangePassword([FromQuery]string oldPassword, [FromQuery]string newPassword)
        {
            IActionResult result = SafeExecute(() =>
            {
                int facadeIndex = RetriveFacadeIndex();
                LoggedInCustomerFacade customerFacade = (LoggedInCustomerFacade)FlyingCenterSystem.FacadeList[facadeIndex];
                customerFacade.ChangeMyPassword(customerFacade.LoginToken, oldPassword, newPassword);
                if (customerFacade.LoginToken.User.Password != newPassword)
                {
                    return new StatusCodeResult(StatusCodes.Status304NotModified);
                }
                return Ok();
            });
            return result;
        }
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